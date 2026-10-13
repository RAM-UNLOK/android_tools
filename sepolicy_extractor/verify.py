"""
verify.py — proves the written .te files grant exactly what the stock CIL grants.

Reads every .te we wrote, expands perm macros (rx_file_perms ...) and domain
macros (get_prop, binder_use ...), and diffs the result against the atomic
rules parsed from the CIL.

   MISSING  = in stock policy, not in output   (policy would break)
   EXTRA    = in output, not in stock policy   (over-grant -> neverallow errors)
"""

import os
import re

_BR = r"\{[^}]*\}"
_AV = re.compile(rf"^(allow|dontaudit|auditallow|neverallow)\s+({_BR}|\S+)\s+({_BR}|[^\s:]+):({_BR}|\S+)\s+({_BR}|\S+)$")
_TT = re.compile(rf"^type_transition\s+(\S+)\s+(\S+):(\S+)\s+(\S+?)(?:\s+(\"[^\"]*\"))?$")
_MAC = re.compile(r"^(\w+)\(([^)]*)\)$")


def _set(tok):
    tok = tok.strip()
    if tok.startswith("{"):
        return tok[1:-1].split()
    return [tok]


def _read_te(path, pm, specs):
    buf = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                buf.append(line)
    text = " ".join(buf)

    atoms = set()
    # 1) macro calls (they carry no ';'): expand, then cut them out of the text
    for mm in re.finditer(r"\b(\w+)\(([^)]*)\)", text):
        sp = specs.get(mm.group(1))
        if sp is None:
            continue
        args = tuple(a.strip() for a in mm.group(2).split(","))
        for r in sp.reqs(args):
            if r.kind == "av":
                act, s, t, c = r.key
                for p in r.val:
                    atoms.add((act, s, t, c, p))
            elif r.kind == "tt":
                s, t, c, n = r.key
                atoms.add(("type_transition", s, t, c, f"{r.val}|"))
    text = re.sub(r"\b\w+\([^)]*\)", " ", text)

    # 2) plain statements
    for st in text.split(";"):
        st = " ".join(st.split())
        if not st:
            continue
        m = _AV.match(st)
        if m:
            act, src, tgt, cls, perms = m.groups()
            ps = pm.expand(perms)
            if ps is None:
                continue
            for s in _set(src):
                for t in _set(tgt):
                    for c in _set(cls):
                        for p in ps:
                            atoms.add((act, s, t, c, p))
            continue
        m = _TT.match(st)
        if m:
            s, t, c, new, name = m.groups()
            atoms.add(("type_transition", s, t, c, f"{new}|{name or ''}"))
    return atoms


def verify_semantics(out_dir: str, report: dict, show: int = 12) -> int:
    """Return number of problems (missing + over-grants)."""
    problems = 0
    for fam, info in report["families"].items():
        pm, specs = info["pm"], info["specs"]
        tiers = ("vendor",) if fam == "vendor" else ("private", "public")
        produced = set()
        for tier in tiers:
            d = os.path.join(out_dir, tier)
            if not os.path.isdir(d):
                continue
            for fn in os.listdir(d):
                if fn.endswith(".te"):
                    produced |= _read_te(os.path.join(d, fn), pm, specs)
        want = info["atoms"]
        missing = want - produced
        # dontaudit side-effects of macros (e.g. noatsecure) are harmless
        extra = {a for a in produced - want if a[0] != "dontaudit"}
        if report.get("variant_macros"):      # add_service()'s userdebug-only su rule
            extra = {a for a in extra if not (a[2] == "su" and a[3] == "tcp_socket")}
        print(f"  [VERIFY/{fam}] CIL atoms={len(want)}  output atoms={len(produced)}  "
              f"missing={len(missing)}  over-granted={len(extra)}")
        for label, bad in (("MISSING", missing), ("OVER-GRANT", extra)):
            for a in sorted(bad)[:show]:
                print(f"       {label}: {a[0]} {a[1]} {a[2]}:{a[3]} {a[4]}")
            if len(bad) > show:
                print(f"       ... and {len(bad) - show} more {label}")
        problems += len(missing) + len(extra)
    return problems
