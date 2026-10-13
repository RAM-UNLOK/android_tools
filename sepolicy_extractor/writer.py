"""
writer.py — Part 5 of the pipeline.

Builds one merged policy index per tier-family
    platform = system + system_ext + product   -> private/ + public/
    vendor   = vendor + odm                    -> vendor/
condenses it (lossless perm macros + verified domain macros) and writes ONE .te
per group.

FIXED vs. the previous writer
  * Different partitions used to write to the SAME path (e.g. system and
    system_ext both -> private/property.te, vendor and odm -> vendor/file.te)
    with mode "w": the last partition silently overwrote the others.
  * rx_file_perms & friends were chosen by "trigger perms" and widened rules.
  * `typealias` was emitted without the `alias` keyword (does not compile).
  * type_transition with a file name had name/new_type swapped.
  * allowx ranges were mangled; auditallow/permissive/typebounds were dropped.
  * attribute removal in property macros dropped attributes the macro does not imply.
"""

import os
import re
from collections import defaultdict

from taxonomy import classify, get_vendor
from perm_macros import PermMacros, parse_global_macros
import macro_condenser as mc
from cil_parser import read_sexps

FAMILIES = {
    "platform": ["system", "system_ext", "product"],
    "vendor":   ["vendor", "odm"],
}

DEFAULT_PROP_MACROS = {
    "system_internal_prop", "system_restricted_prop", "system_public_prop",
    "vendor_internal_prop", "vendor_restricted_prop", "vendor_public_prop",
    "product_internal_prop", "product_restricted_prop", "product_public_prop",
}
PROP_OWNERS = ("system", "vendor", "product", "system_ext")
PROP_SCOPES = ("public", "internal", "restricted")
ACTION_ORDER = {"allow": 0, "auditallow": 1, "dontaudit": 2, "neverallow": 3}


def get_taxonomy(name: str) -> tuple:
    lower = name.lower()
    vendor = get_vendor(name)

    if "hal_" in lower or lower.endswith("_hal"): role = "HAL"
    elif "app" in lower:
        if any(x in lower for x in["untrusted", "isolated", "ephemeral"]): role = "APP_UNTRUSTED"
        elif any(x in lower for x in["priv", "platform", "system"]): role = "APP_PRIV"
        else: role = "APP_SYSTEM"
    elif "service" in lower or "manager" in lower: role = "SERVICE"
    elif lower.endswith("d") and len(lower) > 2: role = "DAEMON"
    elif any(x in lower for x in ["sysfs", "proc", "dev"]): role = "DRIVER / KERNEL"
    elif "prop" in lower: role = "PROPERTY"
    else: role = "NATIVE / MISC"

    hit = classify(name)
    if hit:
        return (hit[0], hit[1], role, vendor)
    return ("Uncategorized", "Misc", role, vendor)


def get_group_name(name: str) -> str:
    if name.endswith("_prop") or "property" in name: return "property"
    if name.startswith("base_typeattr_"):            return "base_typeattr"
    
    if name.startswith("pdx_"):           return "pdx"
    if name.startswith("fs_bpf"):         return "fs_bpf"
    if name.startswith("binderfs"):       return "binderfs"
    if name.startswith("debugfs"):        return "debugfs"
    if name.startswith("sysfs") or name.startswith("vendor_sysfs"): return "sysfs"
    if name.startswith("procfs_") or name.startswith("proc_") or name == "proc": return "proc"
    if name.startswith("cgroup"):         return "cgroup"
        
    if name.startswith("untrusted_app"):  return "untrusted_app"
    if name.startswith("isolated_app"):   return "isolated_app"
    if name.startswith("sdk_sandbox"):    return "sdk_sandbox"
        
    if name.startswith("apex_"):          return "apex"
    if name.startswith("traced"):         return "traced"
    if name.startswith("tombstoned"):     return "tombstoned"
    if name.startswith("compos"):         return "compos"

    base = name
    suffixes =["_exec", "_socket", "_tmpfs", "_userfaultfd", "_devpts", 
                "_key", "_marker", "_server", "_client", "_type", "_iouring"]
    for _ in range(2):
        for s in suffixes:
            if base.endswith(s):
                base = base[:-len(s)]
                break

    if base.startswith("rild"): return "rild"
    if base.endswith("_hwservice") or base == "hwservicemanager": return "hwservice"
    if base.endswith("_service") or base == "servicemanager":     return "service"
    if base.endswith("_device"): return "device"

    if "hal_" in base:
        for s in ["_default", "_impl"]:
            if base.endswith(s): base = base[:-len(s)]
        return base

    if base.endswith("_file") or base.endswith("_dir") or base.endswith("_fs"):
        return "file"

    return base


# ---------------------------------------------------------------------------
# Merged policy index (one per family)
# ---------------------------------------------------------------------------

class Index:
    def __init__(self):
        self.types, self.attributes = set(), set()
        self.type_attrs = defaultdict(set)
        self.aliases = defaultdict(set)
        self.av = defaultdict(set)
        self.avx = defaultdict(set)
        self.tt = {}
        self.other_tt = []
        self.raw_rules = defaultdict(list)
        self.permissive, self.expand, self.typebounds = set(), {}, set()
        self.partitions = []
        self.prop_types = set()

    def merge(self, pname, r):
        self.partitions.append(pname)
        self.types |= r["types"]
        self.attributes |= r["attributes"]
        for k, v in r["type_attrs"].items():
            self.type_attrs[k] |= v
        for k, v in r["aliases"].items():
            self.aliases[k] |= v
        for k, v in r["av"].items():
            self.av[k] |= v
        for k, v in r["avx"].items():
            self.avx[k] |= v
        self.tt.update(r["tt"])
        self.other_tt += r["other_tt"]
        for k, v in r["raw_rules"].items():
            self.raw_rules[k] += v
        self.permissive |= r["permissive"]
        self.expand.update(r["expand"])
        self.typebounds |= r["typebounds"]

    def finish(self):
        self.prop_types = {t for t, a in self.type_attrs.items() if "property_type" in a} | \
                          {t for t in self.types if t.endswith("_prop")}

    def atoms(self):
        """Atomic view of the ORIGINAL policy (for verification)."""
        out = set()
        for (act, s, t, c), perms in self.av.items():
            for p in perms:
                out.add((act, s, t, c, p))
        for (s, t, c, n), new in self.tt.items():
            out.add(("type_transition", s, t, c, f"{new}|{n or ''}"))
        return out


def _prop_macro(attrs: set, avail: set):
    hits = []
    for o in PROP_OWNERS:
        for sc in PROP_SCOPES:
            m = f"{o}_{sc}_prop"
            need = {"property_type", f"{o}_property_type", f"{o}_{sc}_property_type"}
            if m in avail and need <= attrs:
                hits.append((m, need))
    return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _cls_str(classes):
    c = sorted(classes)
    return c[0] if len(c) == 1 else "{ " + " ".join(c) + " }"


def render_name(name, idx, by_src, pm, macros_for, prop_avail, use_perm_macros):
    decl, rules = [], []

    # ---- declaration ----------------------------------------------------
    at = set(idx.type_attrs.get(name, ()))
    extra_attr_lines = []
    if name in idx.types:
        pm_hit = _prop_macro(at, prop_avail)
        if pm_hit:
            decl.append(f"{pm_hit[0]}({name})")
            at -= pm_hit[1]
            extra_attr_lines = [f"typeattribute {name} {a};" for a in sorted(at)]
        else:
            decl.append(f"type {name}" + ("".join(f", {a}" for a in sorted(at))) + ";")
    else:
        extra_attr_lines = [f"typeattribute {name} {a};" for a in sorted(at)]
    for al in sorted(idx.aliases.get(name, ())):
        decl.append(f"typealias {name} alias {al};")
    if name in idx.permissive:
        decl.append(f"permissive {name};")
    for p, c in sorted(idx.typebounds):
        if c == name:
            decl.append(f"typebounds {p} {c};")
    decl += extra_attr_lines

    # ---- rules ----------------------------------------------------------
    rules += sorted(macros_for.get(name, []))

    grp = defaultdict(set)
    for (act, s, t, c), perms in by_src.get(name, []):
        ps = pm.compress(perms, c) if use_perm_macros else \
            (next(iter(perms)) if len(perms) == 1 else "{ " + " ".join(sorted(perms)) + " }")
        grp[(act, t, ps)].add(c)
    avl = []
    for (act, t, ps), classes in grp.items():
        avl.append(((ACTION_ORDER.get(act, 9), t, _cls_str(classes), ps),
                    f"{act} {name} {t}:{_cls_str(classes)} {ps};"))
    rules += [l for _, l in sorted(avl)]

    xg = defaultdict(set)
    for (act, s, t, c, xt), xp in idx.avx.items():
        if s == name:
            xg[(act, t, c, xt)] |= xp
    for (act, t, c, xt), xp in sorted(xg.items()):
        body = next(iter(xp)) if len(xp) == 1 else "{ " + " ".join(sorted(xp)) + " }"
        rules.append(f"{act} {name} {t}:{c} {xt} {body};")

    for (s, t, c, fname), new in sorted(idx.tt.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][3] or "")):
        if s == name:
            rules.append(f"type_transition {s} {t}:{c} {new}" + (f" {fname}" if fname else "") + ";")
    for kind, s, t, c, new in idx.other_tt:
        if s == name:
            rules.append(f"{'type_change' if kind == 'typechange' else 'type_member'} {s} {t}:{c} {new};")
    if name in idx.expand:
        rules.append(f"expandtypeattribute {name} {idx.expand[name]};")
    rules += sorted(idx.raw_rules.get(name, []))
    return {"type_decl": decl, "attributes": [], "rules": rules}


def _public_types(data):
    pub = set()
    for pdata in data["partitions"].values():
        for lines in pdata.get("mappings", {}).values():
            nodes, _ = read_sexps(lines)
            for st in nodes:
                if isinstance(st, list) and len(st) == 3 and st[0] == "typeattributeset" \
                        and isinstance(st[2], list):
                    for m in st[2]:
                        if isinstance(m, str):
                            pub.add(m)
    return pub


def _te_macro_names(path):
    names = set()
    paths = [path] if os.path.isfile(path) else \
        [os.path.join(path, f) for f in ("te_macros", "global_macros") if os.path.isfile(os.path.join(path, f))]
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            names |= set(re.findall(r"define\(\s*`(\w+)'", f.read()))
    return names


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _write_lines(filepath: str, lines: list):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    clean, prev_empty = [], False
    for line in lines:
        e = line.strip() == ""
        if e and prev_empty:
            continue
        clean.append(line)
        prev_empty = e
    with open(filepath, "w", encoding="utf-8") as f:
        for line in clean:
            f.write(line + "\n")


def _write_te_file(filepath, group_name, tier, content_by_domain, partitions):
    cat, subcat, role, vendor = get_taxonomy(group_name)
    lines = [f"# {'=' * 60}", f"# File: {group_name}.te", f"# Tier: {tier}",
             f"# Partitions: {', '.join(partitions)}", f"# Vendor: {vendor}",
             f"# Category: {cat}", f"# Subcategory: {subcat}", f"# Role: {role}",
             "# Generated by sepolicy_extract", f"# {'=' * 60}", ""]
    multiple = len(content_by_domain) > 1
    for dn in sorted(content_by_domain):
        dom = content_by_domain[dn]
        if multiple:
            lines.append(f"# --- {dn} ---")
        if dom["type_decl"]:
            lines += dom["type_decl"] + [""]
        if dom["rules"]:
            lines += dom["rules"] + [""]
        lines.append("")
    _write_lines(filepath, lines)


def _write_attributes_file(filepath, partition, attr_names):
    base, hal, core = [], defaultdict(list), []
    for n in sorted(attr_names):
        line = f"attribute {n};"
        if n.startswith("base_typeattr_"):
            base.append(line)
        elif "hal_" in n or "_client" in n or "_server" in n:
            hal[get_taxonomy(n)[0]].append(line)
        else:
            core.append(line)
    lines = [f"# Global attributes for {partition}", "# Generated by sepolicy_extract", ""]
    if core:
        lines += ["# [ Core Attributes ]"] + core + [""]
    for cat, a in sorted(hal.items()):
        lines += [f"# [ HAL Attributes - {'Misc HALs' if cat == 'Uncategorized' else cat} ]"] + a + [""]
    if base:
        lines += ["# [ Base Type Attributes ]"] + base + [""]
    _write_lines(filepath, lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def write_output(parsed: dict, data: dict, out_dir: str, options: dict = None) -> dict:
    options = options or {}
    use_perm = not options.get("no_perm_macros")
    use_dom = not options.get("no_domain_macros")

    # ---- macro definitions ---------------------------------------------
    defs = None
    if options.get("global_macros"):
        gm = options["global_macros"]
        gm = os.path.join(gm, "global_macros") if os.path.isdir(gm) else gm
        with open(gm, encoding="utf-8", errors="replace") as f:
            defs = parse_global_macros(f.read())
        print(f"[TE] Loaded {len(defs)} perm macros from {gm}")
    pm = PermMacros(defs)

    prop_avail, enabled = set(DEFAULT_PROP_MACROS), None
    if options.get("te_macros"):
        known = _te_macro_names(options["te_macros"])
        prop_avail = {m for m in DEFAULT_PROP_MACROS if m in known}
        enabled = {c.name for c in mc.ALL_SPECS if c.name in known}
        print(f"[TE] te_macros: domain macros enabled = {sorted(enabled)}")

    public_types = _public_types(data)
    print(f"[TE] Found {len(public_types)} public types (from mapping/*.cil).")

    report = {"families": {}, "variant_macros": bool(options.get("variant_macros"))}
    plan = defaultdict(lambda: defaultdict(dict))   # tier -> group -> {name: content}
    plan_parts = defaultdict(lambda: defaultdict(set))
    stats_all = {}

    for fam, members in FAMILIES.items():
        present = [p for p in members if p in parsed]
        if not present:
            continue
        idx = Index()
        for p in present:
            idx.merge(p, parsed[p])
        idx.finish()
        atoms_before = idx.atoms()

        macros_for, stats, specs = {}, {}, {}
        if use_dom:
            macros_for, stats, specs = mc.condense(idx, pm, enabled, bool(options.get('variant_macros')))
        stats_all[fam] = stats
        print(f"[TE] {fam}: domain macros used: {stats or 'none'}")
        report["families"][fam] = {"atoms": atoms_before, "specs": specs, "pm": pm,
                                   "partitions": present}

        by_src = defaultdict(list)
        for k, perms in idx.av.items():
            by_src[k[1]].append((k, perms))

        names = set(idx.types) | set(by_src) | set(idx.type_attrs) | set(macros_for) | \
            {s for (s, *_r) in idx.tt} | {k[1] for k in idx.avx} | set(idx.aliases) | \
            set(idx.raw_rules) | idx.permissive | set(idx.expand) | {c for _, c in idx.typebounds} | \
            {o[1] for o in idx.other_tt}

        groups = defaultdict(dict)
        for n in sorted(names):
            c = render_name(n, idx, by_src, pm, macros_for, prop_avail, use_perm)
            if c["type_decl"] or c["rules"]:
                groups[get_group_name(n)][n] = c

        for g, doms in groups.items():
            if fam == "vendor":
                tier = "vendor"
            else:
                tier = "public" if any(d in public_types for d in doms) else "private"
            plan[tier][g].update(doms)
            plan_parts[tier][g] |= set(present)

        for p in present:
            attrs = parsed[p]["attributes"]
            if attrs:
                tier = "vendor" if fam == "vendor" else "private"
                _write_attributes_file(os.path.join(out_dir, tier, f"_attributes_{p}.te"), p, attrs)

    written = 0
    for tier, gs in plan.items():
        for g, doms in gs.items():
            _write_te_file(os.path.join(out_dir, tier, f"{g}.te"), g, tier, doms,
                           sorted(plan_parts[tier][g]))
            written += 1
    print(f"\n[DONE] Wrote {written} .te files (each path written exactly once).")
    report["stats"] = stats_all
    return report
