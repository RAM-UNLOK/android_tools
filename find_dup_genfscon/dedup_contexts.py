#!/usr/bin/env python3
"""
dedup_contexts.py

Remove entries from the PRIMARY context file if the same key also appears in
any of the OTHER files. Supports BOTH genfs_contexts and file_contexts.

Type detection (unless --type is given):
  * filename contains 'genfs'              -> genfs_contexts
  * filename contains 'file_contexts'      -> file_contexts
  * otherwise peek first data line:
        starts with 'genfscon'             -> genfs_contexts
        starts with '/' or '('             -> file_contexts

Comparison keys:
  genfs_contexts : (fs_type, path)              --by-context: (fs_type, path, ctx)
  file_contexts  : (path_pattern, file_type)    --by-context: (path_pattern, file_type, ctx)

  (file_contexts file_type is the optional -d/-f/-l/-c/-b/-p/-s/-- flag.
   Two entries with the same path but different -type are legitimately different
   and are NOT considered duplicates.)

Usage:
  ./dedup_contexts.py <primary> <other> [<other> ...] \
        [-o OUT] [--diff] [--by-context] [--type auto|genfs|file_contexts]

Examples:
  # genfs
  ./dedup_contexts.py genfs_contexts plat/genfs_contexts vendor/genfs_contexts

  # file_contexts (separate invocation, because types can't be mixed)
  ./dedup_contexts.py file_contexts plat_file_contexts vendor_file_contexts \
        -o file_contexts.dedup --diff
"""

import argparse
import os
import sys
from collections import defaultdict

# --------------------------------------------------------------------------- #
# type detection
# --------------------------------------------------------------------------- #

def detect_type(path):
    base = os.path.basename(path).lower()
    if 'genfs' in base:
        return 'genfs'
    if 'file_contexts' in base:
        return 'file_contexts'
    try:
        with open(path, 'r', errors='replace') as f:
            for raw in f:
                s = raw.strip()
                if not s or s.startswith('#'):
                    continue
                if s.startswith('genfscon'):
                    return 'genfs'
                if s.startswith('/') or s.startswith('('):
                    return 'file_contexts'
    except OSError:
        return None
    return None

# --------------------------------------------------------------------------- #
# line parsing
# --------------------------------------------------------------------------- #

def _strip_comment(raw):
    s = raw.strip()
    if not s or s.startswith('#'):
        return None
    if '#' in s:
        s = s.split('#', 1)[0].strip()
    return s or None


def parse_genfs(raw):
    """Return (fs_type, path, ctx) or None."""
    s = _strip_comment(raw)
    if s is None:
        return None
    parts = s.split()
    if parts[0] != 'genfscon' or len(parts) < 4:
        return None
    return parts[1], parts[2], parts[3]


def parse_fc(raw):
    """Return (path_pattern, file_type_or_None, ctx) or None.
    Accepts both 'path [ -type ] ctx' and 'path ctx [ -type ]' orderings."""
    s = _strip_comment(raw)
    if s is None:
        return None
    parts = s.split()
    if len(parts) < 2:
        return None
    path = parts[0]
    ftype = None
    ctx = None
    for tok in parts[1:]:
        if tok == '--' or (tok.startswith('-') and len(tok) == 2):
            ftype = tok
        elif ctx is None and ':' in tok:
            ctx = tok
    if ctx is None:
        return None
    return path, ftype, ctx


def get_parser(kind):
    return parse_genfs if kind == 'genfs' else parse_fc


def key_for(kind, parsed, by_context):
    if kind == 'genfs':
        fs, path, ctx = parsed
        return (fs, path, ctx) if by_context else (fs, path)
    path, ftype, ctx = parsed
    return (path, ftype, ctx) if by_context else (path, ftype)

# --------------------------------------------------------------------------- #
# key collection
# --------------------------------------------------------------------------- #

def collect_from_file(path, kind, by_context):
    """Return {key: {source_file, ...}} for one file."""
    parser = get_parser(kind)
    out = defaultdict(set)
    with open(path, 'r', errors='replace') as f:
        for raw in f:
            p = parser(raw)
            if p is not None:
                out[key_for(kind, p, by_context)].add(path)
    return out


def collect_from_others(others, kind, by_context):
    combined = defaultdict(set)
    for other in others:
        for k, srcs in collect_from_file(other, kind, by_context).items():
            combined[k] |= srcs
    return combined

# --------------------------------------------------------------------------- #
# dedup
# --------------------------------------------------------------------------- #

def dedup_primary(primary, kind, by_context, external_keys):
    parser = get_parser(kind)
    kept = []
    removed = []
    with open(primary, 'r', errors='replace') as f:
        for lineno, raw in enumerate(f, 1):
            p = parser(raw)
            if p is None:
                kept.append(raw)
                continue
            k = key_for(kind, p, by_context)
            if k in external_keys:
                removed.append((lineno, raw.rstrip('\n'), k, external_keys[k]))
            else:
                kept.append(raw)
    return kept, removed

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Remove entries from the primary context file that also "
                    "exist in any of the other files. Handles genfs_contexts "
                    "and file_contexts.")
    ap.add_argument('primary', help="Primary context file (kept file)")
    ap.add_argument('others', nargs='+', help="One or more other context files")
    ap.add_argument('-o', '--output', default=None,
                    help="Output file (default: <primary>.dedup)")
    ap.add_argument('--diff', action='store_true',
                    help="Print removed entries with source file references")
    ap.add_argument('--by-context', action='store_true',
                    help="Match on the security context too (stricter)")
    ap.add_argument('--type', choices=['auto', 'genfs', 'file_contexts'],
                    default='auto', help="Force file type (default: auto)")
    args = ap.parse_args(argv)

    # -- resolve type ------------------------------------------------------- #
    if args.type == 'auto':
        ptype = detect_type(args.primary)
        if ptype is None:
            print(f"ERROR: cannot auto-detect type of {args.primary!r}. "
                  f"Use --type.", file=sys.stderr)
            return 1
        otypes = {detect_type(o) for o in args.others}
        if None in otypes:
            print("ERROR: cannot auto-detect type of some 'other' files. "
                  "Use --type.", file=sys.stderr)
            return 1
        if otypes != {ptype}:
            print(f"ERROR: type mismatch — primary is {ptype!r}, "
                  f"others are {sorted(otypes)!r}.", file=sys.stderr)
            print("       genfs_contexts and file_contexts cannot be compared "
                  "directly; run the script once per type.", file=sys.stderr)
            return 1
        kind = ptype
    else:
        kind = args.type

    # -- work --------------------------------------------------------------- #
    external = collect_from_others(args.others, kind, args.by_context)
    kept, removed = dedup_primary(args.primary, kind, args.by_context, external)

    out_path = args.output or (args.primary + '.dedup')
    with open(out_path, 'w') as f:
        f.writelines(kept)

    print(f"Type         : {kind}", file=sys.stderr)
    print(f"Match mode   : "
          f"{'path+type+ctx' if args.by_context else 'path+type'}"
          f"{' (genfs: fs+path+ctx)' if args.by_context and kind=='genfs' else ''}"
          f"{' (genfs: fs+path)' if not args.by_context and kind=='genfs' else ''}",
          file=sys.stderr)
    print(f"Primary      : {args.primary}", file=sys.stderr)
    print(f"Compared with: {', '.join(args.others)}", file=sys.stderr)
    print(f"Removed      : {len(removed)} line(s)", file=sys.stderr)
    print(f"Output       : {out_path}", file=sys.stderr)

    if args.diff and removed:
        print("\n--- removed entries ---", file=sys.stderr)
        for lineno, line, key, srcs in removed:
            print(f"  line {lineno:>5}: {line}", file=sys.stderr)
            print(f"           key {key} found in: {', '.join(sorted(srcs))}",
                  file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())