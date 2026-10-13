"""
perm_macros.py — exact permission-macro compression.

WHY THIS EXISTS
---------------
The old compressor used "trigger" perms: if a rule contained {read execute} it
was replaced by rx_file_perms, which expands to
    getattr open read ioctl lock map watch watch_reads execute execute_no_trans
so the rebuilt policy granted ~8 permissions the stock policy never granted.
That is what trips neverallow.

RULE NOW: a macro is used only if EVERY permission it expands to is present in
the original rule. Nothing is ever added, and nothing is ever dropped. Every
compression result is re-expanded and compared to the input (assert).

Definitions below are AOSP Android 14/15 public/global_macros. If your tree
differs, pass --global-macros /path/to/public/global_macros and the real file
is parsed instead.
"""

import re

BUILTIN_DEFS = {
    "x_file_perms":      "getattr execute execute_no_trans map",
    "r_file_perms":      "getattr open read ioctl lock map watch watch_reads",
    "w_file_perms":      "open append write lock map",
    "rx_file_perms":     "r_file_perms x_file_perms",
    "ra_file_perms":     "r_file_perms append",
    "rw_file_perms":     "r_file_perms w_file_perms",
    "rwx_file_perms":    "rw_file_perms x_file_perms",
    "create_file_perms": "create rename setattr unlink rw_file_perms",

    "r_dir_perms":       "open getattr read search ioctl lock watch watch_reads",
    "w_dir_perms":       "open search write add_name remove_name lock",
    "ra_dir_perms":      "r_dir_perms add_name write",
    "rw_dir_perms":      "r_dir_perms w_dir_perms",
    "create_dir_perms":  "create reparent rename rmdir setattr rw_dir_perms",

    "rw_socket_perms":
        "ioctl read getattr write setattr lock append bind connect getopt setopt shutdown map",
    "rw_socket_perms_no_ioctl":
        "read getattr write setattr lock append bind connect getopt setopt shutdown map",
    "create_socket_perms":           "create rw_socket_perms",
    "create_socket_perms_no_ioctl":  "create rw_socket_perms_no_ioctl",
    "rw_stream_socket_perms":        "rw_socket_perms listen accept",
    "create_stream_socket_perms":    "create rw_stream_socket_perms",
}

FILE_CLASSES = {"file", "chr_file", "blk_file", "lnk_file", "fifo_file", "sock_file"}
DIR_CLASSES = {"dir"}

# a macro is only offered for classes it is meant for
def _kind(name: str) -> str:
    if "_dir_perms" in name:
        return "dir"
    if "_file_perms" in name:
        return "file"
    if "socket_perms" in name:
        return "socket"
    return "other"


def _class_ok(kind: str, cls: str) -> bool:
    if kind == "file":
        return cls in FILE_CLASSES
    if kind == "dir":
        return cls in DIR_CLASSES
    if kind == "socket":
        return cls.endswith("_socket") or cls == "socket"
    return False


_DEF_RE = re.compile(r"define\(\s*`(\w+)'\s*,\s*`\s*\{([^}]*)\}\s*'\s*\)")


def parse_global_macros(text: str) -> dict:
    """Parse `define(`name', `{ a b c_macro }')` lines of AOSP global_macros."""
    return {m.group(1): m.group(2).strip() for m in _DEF_RE.finditer(text)}


class PermMacros:
    # accept a macro on top of an already-chosen one only if it brings this
    # many NEW perms (or is entirely new) - keeps output readable
    MIN_NEW = 3

    def __init__(self, defs: dict = None):
        self.defs = dict(defs or BUILTIN_DEFS)
        self.flat = {}
        for n in self.defs:
            self.flat[n] = frozenset(self._flatten(n, set()))
        # only macros we know how to class-gate
        self.usable = {n: s for n, s in self.flat.items() if _kind(n) != "other"}

    # -- helpers -----------------------------------------------------------
    def _flatten(self, name, seen):
        if name in seen:
            raise ValueError(f"cyclic perm macro {name}")
        seen = seen | {name}
        out = set()
        for tok in self.defs[name].split():
            if tok in self.defs:
                out |= self._flatten(tok, seen)
            else:
                out.add(tok)
        return out

    def expand(self, perm_str: str):
        """Perm string ('read', '{ rx_file_perms foo }') -> set of atomic perms.
        Returns None for complemented/wildcard forms."""
        s = perm_str.strip()
        if "~" in s or "*" in s:
            return None
        out = set()
        for tok in re.findall(r"[^\s{}]+", s):
            out |= self.flat[tok] if tok in self.flat else {tok}
        return out

    # -- compression -------------------------------------------------------
    def compress(self, perms, cls: str) -> str:
        perms = set(perms)
        cands = [(n, s) for n, s in self.usable.items()
                 if _class_ok(_kind(n), cls) and s <= perms]
        covered, chosen = set(), []
        while True:
            best = None
            for n, s in cands:
                if n in chosen:
                    continue
                new = len(s - covered)
                if new == 0:
                    continue
                if new < self.MIN_NEW and new != len(s):
                    continue
                key = (new, -len(s), )
                if best is None or key > best[0] or (key == best[0] and n < best[1]):
                    best = (key, n, s)
            if best is None:
                break
            chosen.append(best[1])
            covered |= best[2]

        items = sorted(chosen) + sorted(perms - covered)
        result = items[0] if len(items) == 1 else "{ " + " ".join(items) + " }"

        # hard safety net: expansion must be EXACTLY the input
        back = self.expand(result)
        if back != perms:
            raise AssertionError(
                f"perm compression not lossless for {cls}: "
                f"in={sorted(perms)} out={result} extra={sorted(back - perms)} "
                f"missing={sorted(perms - back)}")
        return result
