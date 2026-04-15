#!/usr/bin/env python3
import sys
from pathlib import Path

input_file = Path(sys.argv[1] if len(sys.argv) > 1 else "proprietary-files.txt")
raw_lines = input_file.read_text(encoding="utf-8").splitlines()

original_order = []
plain_entries = []
plain_set = set()

for line in raw_lines:
    s = line.strip()
    original_order.append(line)
    if not s or s.startswith("#") or ";SYMLINK=" in s:
        continue
    plain_entries.append(s)
    plain_set.add(s)

preferred_map = {}
remove_set = set()

for path in plain_entries:
    parts = path.split("/")

    if "mt6899" not in parts:
        continue

    for i in range(1, len(parts) - 1):
        if parts[i] != "mt6899":
            continue

        candidate = "/".join(parts[:i] + parts[i+1:])
        if candidate in plain_set:
            preferred_map[path] = candidate
            remove_set.add(candidate)
            break

output = []
already_added = set()

for line in original_order:
    s = line.strip()

    if not s or s.startswith("#"):
        output.append(line)
        continue

    if ";SYMLINK=" in s:
        continue

    if s in remove_set:
        continue

    if s in preferred_map:
        new_line = f"{s};SYMLINK={preferred_map[s]}"
        if new_line not in already_added:
            output.append(new_line)
            already_added.add(new_line)
        continue

    if s not in already_added:
        output.append(s)
        already_added.add(s)

input_file.write_text("\n".join(output) + "\n", encoding="utf-8")