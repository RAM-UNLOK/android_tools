#!/usr/bin/env python3
"""
dedup_genfs.py

Remove `genfscon` entries from the FIRST genfs_contexts file if the same
(fs_type, path) pair also appears in any of the OTHER files.

Comments, blank lines, and non-genfscon lines in the first file are preserved
verbatim (including inline comments on kept genfscon lines).

Usage:
    ./dedup_genfs.py <primary_file> <other_file> [<other_file> ...] \
        [-o OUTPUT] [--diff] [--by-context]

Options:
    -o OUTPUT      Write cleaned primary file here (default: <primary>.dedup)
    --diff         Also print a summary of which lines were removed.
    --by-context   Match on (fs_type, path, context) instead of (fs_type, path).
                   Use this if you only want EXACT duplicates removed and you
                   intend to keep same-path/different-context conflicts.
"""

import argparse
import sys
from collections import defaultdict


def parse_line(raw):
    """
    Return (kind, key, payload) for a raw line.
      kind == 'genfs'  -> key = (fs, path) or (fs, path, ctx); payload = (fs, path, ctx)
      kind == 'other'  -> key = None
    Strips inline '#' comments, but ONLY for parsing purposes.
    """
    s = raw.strip()
    if not s or s.startswith("#"):
        return ("other", None, None)
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    if not s:
        return ("other", None, None)
    parts = s.split()
    if parts[0] != "genfscon" or len(parts) < 4:
        return ("other", None, None)
    fs, path, ctx = parts[1], parts[2], parts[3]
    return ("genfs", (fs, path, ctx), (fs, path, ctx))


def collect_keys(path, by_context):
    keys = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            kind, full_key, _ = parse_line(raw)
            if kind != "genfs":
                continue
            fs, p, ctx = full_key
            keys.add((fs, p, ctx) if by_context else (fs, p))
    return keys


def dedup(primary, others, by_context):
    external = set()
    per_file_hits = defaultdict(list)  # key -> list of files that contained it
    for other in others:
        ks = collect_keys(other, by_context)
        external |= ks
        # remember which file contributed each key (for --diff)
        with open(other, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                kind, full_key, _ = parse_line(raw)
                if kind != "genfs":
                    continue
                fs, p, ctx = full_key
                k = (fs, p, ctx) if by_context else (fs, p)
                if k in ks and other not in per_file_hits[k]:
                    per_file_hits[k].append(other)

    kept_lines = []
    removed = []  # (lineno, raw_line, key, source_files)

    with open(primary, "r", encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            kind, full_key, _ = parse_line(raw)
            if kind != "genfs":
                kept_lines.append(raw)
                continue

            fs, p, ctx = full_key
            k = (fs, p, ctx) if by_context else (fs, p)
            if k in external:
                removed.append((lineno, raw.rstrip("\n"), k, per_file_hits[k]))
            else:
                kept_lines.append(raw)

    return kept_lines, removed


def main():
    ap = argparse.ArgumentParser(
        description="Remove genfscon entries from the primary file that "
                    "already exist in the other files.")
    ap.add_argument("primary", help="First genfs_contexts file (will be cleaned)")
    ap.add_argument("others", nargs="+", help="One or more other genfs_contexts files")
    ap.add_argument("-o", "--output", default=None,
                    help="Output file (default: <primary>.dedup)")
    ap.add_argument("--diff", action="store_true",
                    help="Print the removed entries with source file references")
    ap.add_argument("--by-context", action="store_true",
                    help="Match on (fs, path, context) rather than just (fs, path)")
    args = ap.parse_args()

    out_path = args.output or (args.primary + ".dedup")

    kept, removed = dedup(args.primary, args.others, args.by_context)

    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(kept)

    print(f"Primary file : {args.primary}", file=sys.stderr)
    print(f"Compared with: {', '.join(args.others)}", file=sys.stderr)
    print(f"Match mode   : {'fs+path+context' if args.by_context else 'fs+path'}",
          file=sys.stderr)
    print(f"Removed      : {len(removed)} line(s)", file=sys.stderr)
    print(f"Output       : {out_path}", file=sys.stderr)

    if args.diff and removed:
        print("\n--- removed entries ---", file=sys.stderr)
        for lineno, line, key, srcs in removed:
            print(f"  line {lineno:>5}: {line}", file=sys.stderr)
            print(f"           found in: {', '.join(srcs)}", file=sys.stderr)


if __name__ == "__main__":
    main()