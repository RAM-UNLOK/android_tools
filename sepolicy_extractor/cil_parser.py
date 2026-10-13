"""
cil_parser.py — Part 3 of the pipeline.

Parses CIL into a STRUCTURED policy model (no string munging, no regex on
rules). The writer renders it to .te.

Parser: a real S-expression reader (handles ';' comments, quoted strings and
statements that span several lines). The old one required each statement on
one line and silently dropped anything with a trailing comment.

Per-partition result
--------------------
{
  "types":        set(name)                       # (type X)
  "attributes":   set(name)                       # (typeattribute X)
  "attrsets":     [(attr, expr)]                  # raw typeattributeset, resolved later
  "type_attrs":   {type: set(attr)}               # filled by parse_all_cil()
  "aliases":      {real: set(alias)}
  "av":           {(action,src,tgt,cls): set(perms)}
  "avx":          {(action,src,tgt,cls,xtype): set(xperms)}
  "tt":           {(src,tgt,cls,name|None): new_type}   # type_transition
  "other_tt":     [(kind,src,tgt,cls,new)]        # type_change / type_member
  "raw_rules":    {subject: [te_line]}            # ~perm / * forms we can't merge
  "permissive":   set(type)
  "expand":       {name: "true"/"false"}
  "typebounds":   set((parent, child))
  "genfs_contexts": [line]
  "parse_errors": [str]
  "unhandled":    Counter(keyword)
}
"""

import re
from collections import Counter, defaultdict
from config import DEFAULT_PLAT_VERSION

_TOK = re.compile(r'"(?:[^"\\]|\\.)*"|;[^\n]*|\(|\)|[^\s()";]+')

SKIP_ATTR = {"cil_gen_require"}          # checkpolicy -C bookkeeping, not real policy
SET_OPS = {"and", "or", "not", "xor", "all"}
AV_ACTIONS = ("allow", "dontaudit", "auditallow", "neverallow")
AVX_ACTIONS = {"allowx": "allowxperm", "dontauditx": "dontauditxperm",
               "auditallowx": "auditallowxperm", "neverallowx": "neverallowxperm"}
GENFS_FTYPE = {"file": "--", "dir": "-d", "char": "-c", "block": "-b",
               "socket": "-s", "pipe": "-p", "symlink": "-l"}

# keywords that carry no .te meaning for this tool (don't nag about them)
HARMLESS = {"roletype", "role", "roleattribute", "roleattributeset", "user", "userrole",
            "userlevel", "userrange", "sensitivity", "sensitivityorder", "sensitivitycategory",
            "category", "categoryorder", "categoryalias", "categoryaliasactual", "level",
            "levelrange", "sid", "sidorder", "sidcontext", "class", "classorder",
            "classcommon", "common", "classpermission", "classpermissionset", "classmap",
            "classmapping", "mls", "handleunknown", "policycap", "defaultuser", "defaultrole",
            "defaulttype", "defaultrange", "block", "blockinherit", "blockabstract", "in",
            "optional", "filecon", "fsuse", "netifcon", "nodecon", "portcon", "pirqcon",
            "iomemcon", "ioportcon", "pcidevicecon", "devicetreecon", "ibpkeycon",
            "ibendportcon", "selinuxuser", "selinuxuserdefault", "typeattribute_dummy",
            "mlsconstrain", "mlsvalidatetrans", "constrain", "validatetrans", "permissionx",
            "rangetransition", "roletransition", "roleallow", "roletype", "typepermissive_dummy"}


# --------------------------------------------------------------------------
# name / version helpers
# --------------------------------------------------------------------------

def normalize_version(v: str) -> list:
    """plat_sepolicy_vers.txt holds '202404' (A15) or '34.0' (A14); the type
    suffix in the CIL is '_202404' / '_34_0'. Return candidate suffixes."""
    v = (v or "").strip()
    cands = []
    if v:
        cands.append(v)
        cands.append(v.replace(".", "_"))
    return list(dict.fromkeys(cands))


def detect_suffix(cil_lines: list, hints: list) -> str:
    """Pick the suffix actually used in the CIL (hint first, else guess)."""
    text_sample = "\n".join(cil_lines[:200000])
    for h in hints:
        if re.search(rf"\b\w+_{re.escape(h)}\b", text_sample):
            return h
    m = Counter(re.findall(r"\(type \w+?_(\d{6}|\d+_\d+)\)", text_sample))
    if m:
        return m.most_common(1)[0][0]
    return hints[0] if hints else DEFAULT_PLAT_VERSION


def _strip(name: str, suffix: str) -> str:
    s = f"_{suffix}"
    return name[:-len(s)] if suffix and name.endswith(s) else name


# --------------------------------------------------------------------------
# S-expression reader
# --------------------------------------------------------------------------

def read_sexps(lines: list):
    """-> (list_of_top_level_nodes, error_count). Nodes are str | list."""
    stack = [[]]
    errors = 0
    for m in _TOK.finditer("\n".join(lines)):
        t = m.group(0)
        c = t[0]
        if c == ";":
            continue
        if c == "(":
            new = []
            stack[-1].append(new)
            stack.append(new)
        elif c == ")":
            if len(stack) > 1:
                stack.pop()
            else:
                errors += 1
        else:
            stack[-1].append(t)
    if len(stack) > 1:
        errors += len(stack) - 1
    return stack[0], errors


def _is_names(node) -> bool:
    return isinstance(node, list) and all(isinstance(x, str) for x in node)


# --------------------------------------------------------------------------
# permission / xperm expressions
# --------------------------------------------------------------------------

def _perm_expr(node):
    """-> ('set', set) | ('raw', str) | None"""
    if isinstance(node, str):
        return ("set", {node})
    if not isinstance(node, list):
        return None
    if node == ["all"]:
        return ("raw", "*")
    if node and node[0] == "not" and len(node) == 2:
        inner = _perm_expr(node[1])
        if inner and inner[0] == "set":
            return ("raw", "~{ " + " ".join(sorted(inner[1])) + " }")
        return None
    if _is_names(node) and not (node and node[0] in SET_OPS):
        return ("set", set(node))
    return None


def _xperm_items(node):
    """xperm list -> ('set', set(str)) | ('raw', str) | None.  (range a b) -> 'a-b'"""
    if isinstance(node, str):
        return ("set", {node})
    if not isinstance(node, list):
        return None
    if node and node[0] == "not" and len(node) == 2:
        inner = _xperm_items(node[1])
        if inner and inner[0] == "set":
            return ("raw", "~{ " + " ".join(sorted(inner[1])) + " }")
        return None
    out = set()
    for it in node:
        if isinstance(it, str):
            out.add(it)
        elif isinstance(it, list) and len(it) == 3 and it[0] == "range":
            out.add(f"{it[1]}-{it[2]}")
        elif isinstance(it, list) and len(it) == 1 and isinstance(it[0], str):
            out.add(it[0])
        else:
            return None
    return ("set", out)


# --------------------------------------------------------------------------
# Partition parser
# --------------------------------------------------------------------------

def parse_partition_cil(cil_lines: list, suffix: str, partition_name: str) -> dict:
    nodes, unbalanced = read_sexps(cil_lines)
    sv = lambda n: _strip(n, suffix)

    R = {
        "types": set(), "attributes": set(), "attrsets": [], "type_attrs": defaultdict(set),
        "aliases": defaultdict(set), "av": defaultdict(set), "avx": defaultdict(set),
        "tt": {}, "other_tt": [], "raw_rules": defaultdict(list), "permissive": set(),
        "expand": {}, "typebounds": set(), "genfs_contexts": [], "parse_errors": [],
        "unhandled": Counter(), "orig_names": defaultdict(set),
    }
    err = R["parse_errors"].append
    if unbalanced:
        err(f"[reader] {unbalanced} unbalanced parenthesis")

    permx = {}          # named permissionx definitions
    pending_alias = set()

    def name(tok):
        if not isinstance(tok, str):
            return None
        s = sv(tok)
        if s != tok:
            R["orig_names"][s].add(tok)
        return s

    def subjects(tok):
        """source/target token -> list of names (single or expanded set)."""
        if isinstance(tok, str):
            return [name(tok)]
        if _is_names(tok) and tok and tok[0] not in SET_OPS:
            return [name(t) for t in tok]
        return None

    # first pass: named permissionx
    for st in nodes:
        if isinstance(st, list) and len(st) == 3 and st[0] == "permissionx" and isinstance(st[1], str):
            permx[st[1]] = st[2]

    for st in nodes:
        if not isinstance(st, list) or not st or not isinstance(st[0], str):
            continue
        kw, a = st[0], st[1:]

        if kw == "type" and len(a) == 1:
            R["types"].add(name(a[0]))

        elif kw == "typeattribute" and len(a) == 1:
            n = name(a[0])
            if n not in SKIP_ATTR:
                R["attributes"].add(n)

        elif kw == "typeattributeset" and len(a) == 2:
            n = name(a[0])
            if n not in SKIP_ATTR:
                R["attrsets"].append((n, _mapnames(a[1], name)))

        elif kw == "typealias" and len(a) == 1:
            pending_alias.add(name(a[0]))

        elif kw == "typealiasactual" and len(a) == 2:
            R["aliases"][name(a[1])].add(name(a[0]))

        elif kw == "typepermissive" and len(a) == 1:
            R["permissive"].add(name(a[0]))

        elif kw == "typebounds" and len(a) == 2:
            R["typebounds"].add((name(a[0]), name(a[1])))

        elif kw == "expandtypeattribute" and len(a) == 2:
            names = a[0] if isinstance(a[0], list) else [a[0]]
            for t in names:
                R["expand"][name(t)] = a[1]

        elif kw in AV_ACTIONS:
            _av(kw, a, R, subjects, permx, err, st)

        elif kw in AVX_ACTIONS:
            _avx(kw, a, R, subjects, permx, err, st)

        elif kw == "typetransition" and len(a) in (4, 5):
            s, t, c = name(a[0]), name(a[1]), a[2]
            rest = a[3:]
            # CIL order is: [object_name] default_type  (name comes FIRST).
            fname = next((x for x in rest if isinstance(x, str) and x.startswith('"')), None)
            new = next((x for x in rest if isinstance(x, str) and not x.startswith('"')), None)
            if None in (s, t) or not isinstance(c, str) or new is None:
                err(f"[typetransition] {st}")
            else:
                R["tt"][(s, t, c, fname)] = name(new)

        elif kw in ("typechange", "typemember") and len(a) == 4:
            R["other_tt"].append((kw, name(a[0]), name(a[1]), a[2], name(a[3])))

        elif kw == "genfscon" and len(a) in (3, 4):
            line = _genfs(a, sv)
            if line:
                R["genfs_contexts"].append(line)
            else:
                err(f"[genfscon] {st}")

        elif kw not in HARMLESS:
            R["unhandled"][kw] += 1

    # name collisions caused by suffix stripping
    for s, origs in R["orig_names"].items():
        if (s in R["types"] or s in R["attributes"]) and any(o != s for o in origs):
            pass  # informational only
    return R


def _mapnames(node, name):
    if isinstance(node, str):
        return name(node)
    return [_mapnames(x, name) for x in node]


def _av(kw, a, R, subjects, permx, err, st):
    if len(a) != 3 or not isinstance(a[2], list) or len(a[2]) < 2:
        err(f"[{kw}] {st}")
        return
    srcs, tgts = subjects(a[0]), subjects(a[1])
    cls = a[2][0]
    perms = _perm_expr(a[2][1])
    if not srcs or not tgts or not isinstance(cls, str) or perms is None:
        err(f"[{kw}] unsupported form: {st}")
        return
    tgt = tgts[0] if len(tgts) == 1 else "{ " + " ".join(sorted(tgts)) + " }"
    for s in srcs:
        if perms[0] == "set":
            R["av"][(kw, s, tgt, cls)] |= perms[1]
        else:
            R["raw_rules"][s].append(f"{kw} {s} {tgt}:{cls} {perms[1]};")


def _avx(kw, a, R, subjects, permx, err, st):
    if len(a) != 3:
        err(f"[{kw}] {st}")
        return
    srcs, tgts = subjects(a[0]), subjects(a[1])
    px = permx.get(a[2]) if isinstance(a[2], str) else a[2]
    if not srcs or not tgts or not isinstance(px, list) or len(px) < 3:
        err(f"[{kw}] unsupported form: {st}")
        return
    xtype, cls = px[0], px[1]
    items = _xperm_items(px[2])
    if items is None or not isinstance(cls, str):
        err(f"[{kw}] unsupported xperm expr: {st}")
        return
    tgt = tgts[0] if len(tgts) == 1 else "{ " + " ".join(sorted(tgts)) + " }"
    for s in srcs:
        if items[0] == "set":
            R["avx"][(AVX_ACTIONS[kw], s, tgt, cls, xtype)] |= items[1]
        else:
            R["raw_rules"][s].append(f"{AVX_ACTIONS[kw]} {s} {tgt}:{cls} {xtype} {items[1]};")


def _genfs(a, sv):
    fs, path = a[0], a[1].strip('"') if isinstance(a[1], str) else None
    ftype = ""
    ctx = a[-1]
    if len(a) == 4 and isinstance(a[2], str):
        ftype = GENFS_FTYPE.get(a[2], "")
    if not path or not isinstance(ctx, list) or len(ctx) < 3:
        return None
    level = "s0"
    try:
        lv = ctx[3][0]
        level = lv[0] if isinstance(lv, list) and lv and isinstance(lv[0], str) else "s0"
    except Exception:
        pass
    parts = ["genfscon", fs, path] + ([ftype] if ftype else [])
    return " ".join(parts) + f" {ctx[0]}:{ctx[1]}:{sv(ctx[2])}:{level}"


# --------------------------------------------------------------------------
# typeattributeset resolution (supports and/or/not/xor/all, nested attrs)
# --------------------------------------------------------------------------

class _Resolver:
    def __init__(self, results: dict):
        self.all_types, self.all_attrs = set(), set()
        self.sets = defaultdict(list)           # attr -> [expr, ...]
        for r in results.values():
            self.all_types |= r["types"]
            self.all_attrs |= r["attributes"]
            for attr, expr in r["attrsets"]:
                self.sets[attr].append(expr)
                self.all_attrs.add(attr)
        self.memo, self.busy, self.unresolved = {}, set(), []

    def members(self, name):
        if name not in self.all_attrs:
            return {name}
        if name in self.memo:
            return self.memo[name]
        if name in self.busy:
            return set()
        self.busy.add(name)
        out = set()
        for e in self.sets.get(name, []):
            out |= self.ev(e)
        self.busy.discard(name)
        self.memo[name] = out
        return out

    def ev(self, e):
        if isinstance(e, str):
            return set(self.all_types) if e == "all" else self.members(e)
        if not e:
            return set()
        h = e[0]
        if h == "all":
            return set(self.all_types)
        if h == "not":
            return set(self.all_types) - self.ev(e[1]) if len(e) > 1 else set()
        if h in ("and", "or", "xor") and len(e) >= 2:
            parts = [self.ev(x) for x in e[1:]]
            acc = parts[0]
            for p in parts[1:]:
                acc = acc & p if h == "and" else acc | p if h == "or" else acc ^ p
            return acc
        out = set()
        for x in e:
            out |= self.ev(x)
        return out


def _resolve(results: dict):
    rs = _Resolver(results)
    for pname, r in results.items():
        for attr, expr in r["attrsets"]:
            for m in rs.ev(expr):
                if m in rs.all_attrs:
                    continue
                r["type_attrs"][m].add(attr)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def parse_all_cil(data: dict) -> dict:
    hints = normalize_version(data.get("plat_version") or DEFAULT_PLAT_VERSION)
    results = {}
    for pname, pdata in data["partitions"].items():
        lines = pdata.get("cil_lines", [])
        if not lines:
            print(f"\n[CIL] Skipping {pname} — no CIL lines")
            continue
        suffix = detect_suffix(lines, hints)
        print(f"\n[CIL] Parsing {pname}: {len(lines)} lines, version suffix _{suffix}")
        r = parse_partition_cil(lines, suffix, pname)
        r["suffix"] = suffix
        results[pname] = r

    _resolve(results)

    for pname, r in results.items():
        n_rules = sum(len(v) for v in r["av"].values())
        print(f"  [{pname}] types={len(r['types'])} attrs={len(r['attributes'])} "
              f"av-keys={len(r['av'])} perms={n_rules} xperm-keys={len(r['avx'])} "
              f"type_transition={len(r['tt'])} genfscon={len(r['genfs_contexts'])} "
              f"errors={len(r['parse_errors'])}")
        for e in r["parse_errors"][:5]:
            print(f"      ! {e}")
        notable = {k: v for k, v in r["unhandled"].items()}
        if notable:
            print(f"      ignored statements: {dict(notable)}")
        # drop the raw (unresolved) expressions to keep memory small
        r["attrsets"] = []
    return results
