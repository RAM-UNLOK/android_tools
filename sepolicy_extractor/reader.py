"""
reader.py — Part 2 of the pipeline.

Reads all staged files from tmp/ into clean in-memory data structures.
Nothing is written here. No dump paths are touched.

Output data structure returned by read_staged():
{
    "plat_version": "202404",

    "partitions": {
        "vendor": {
            "cil_lines":   [...],   # raw lines from vendor_sepolicy.cil
            "contexts": {
                "vendor_file_contexts":     [...],  # raw lines
                "vendor_property_contexts": [...],  # raw lines (with #line headers)
                "vendor_service_contexts":  [...],
                "vendor_hwservice_contexts":[...],
                "vndservice_contexts":      [...],
                ...
            },
            "mappings": {
                "34.0.cil": [...],  # raw lines per mapping file
                ...
            },
            "plat_vers": "202404"
        },
        "odm": {
            "cil_lines": [...],
            "contexts":  { ... },
            "mappings":  {}
        },
        ...
    }
}
"""

import os
from config import NEEDS_LINE_STRIP


# ---------------------------------------------------------------------------
# Low-level file readers
# ---------------------------------------------------------------------------

def _read_lines(filepath: str) -> list:
    """
    Read a file into a list of raw lines (with newlines stripped).
    Opens in read-only mode. Returns empty list if file doesn't exist.
    """
    if not filepath or not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f.readlines()]


def _strip_line_directives(lines: list) -> list:
    """
    Strip build-system #line directives from context files.

    These are injected by the Android build system when stitching
    multiple source files together into one output file. They look like:

        #line 1 "system/sepolicy/flagging/te_macros"
        #line 1 "out/out_vext/soong/.intermediates/..."
        #line 1 "device/mediatek/sepolicy/base/vendor/property_contexts"

    We remove:
      - Any line starting with #line
      - Surrounding blank lines left by removal (normalised to single blanks)
      - Pure comment blocks that are part of the te_macros header boilerplate

    Regular inline comments (e.g. "# MTK Policy Rule") are kept.
    """
    cleaned = []
    in_macro_header = False

    for line in lines:
        stripped = line.strip()

        # Detect start of the te_macros boilerplate comment block
        if stripped == '#line 1 "system/sepolicy/flagging/te_macros"':
            in_macro_header = True
            continue

        # The macro header ends when we hit the first real #line for actual content
        # i.e. a #line pointing to something other than te_macros or newline intermediates
        if in_macro_header:
            if stripped.startswith("#line") and (
                "te_macros" not in stripped and
                "newline" not in stripped
            ):
                in_macro_header = False
                # Don't add this #line either, just stop suppressing
                continue
            else:
                # Still in the header block — skip
                continue

        # Skip all remaining #line directives
        if stripped.startswith("#line"):
            continue

        cleaned.append(line)

    # Normalise: collapse runs of 3+ blank lines down to 2
    result = []
    blank_count = 0
    for line in cleaned:
        if line.strip() == "":
            blank_count += 1
            if blank_count <= 2:
                result.append(line)
        else:
            blank_count = 0
            result.append(line)

    return result


# ---------------------------------------------------------------------------
# Main reader
# ---------------------------------------------------------------------------

def read_staged(staged: dict) -> dict:
    """
    Read all files from the staged tmp structure into memory.

    Parameters
    ----------
    staged : dict
        The dict returned by stage.stage_files() — describes what
        was copied to tmp and where.

    Returns
    -------
    dict
        Full in-memory representation of all policy files,
        ready for the CIL parser and context writers.
    """

    data = {
        "plat_version": None,
        "partitions": {}
    }

    for partition_name, info in staged.items():
        print(f"\n[READ] Partition: {partition_name}")

        partition_data = {
            "cil_lines": [],
            "contexts":  {},
            "mappings":  {},
            "plat_vers": info.get("plat_vers"),
        }

        # --- Capture plat_version from vendor partition ---
        if partition_name == "vendor" and info.get("plat_vers"):
            data["plat_version"] = info["plat_vers"]
            print(f"  [info] Platform policy version: {info['plat_vers']}")

        # --- Read main CIL file ---
        cil_path = info.get("cil")
        if cil_path:
            cil_lines = _read_lines(cil_path)
            partition_data["cil_lines"] = cil_lines
            print(f"  [read] CIL: {os.path.basename(cil_path)} — {len(cil_lines)} lines")
        else:
            print(f"  [skip] No CIL file for {partition_name}")

        # --- Read context files ---
        contexts = info.get("contexts", {})
        for fname, fpath in contexts.items():
            raw_lines = _read_lines(fpath)

            # Strip #line directives for files that need it
            if fname in NEEDS_LINE_STRIP:
                clean_lines = _strip_line_directives(raw_lines)
                print(f"  [read] {fname} — {len(raw_lines)} lines → {len(clean_lines)} after strip")
                partition_data["contexts"][fname] = clean_lines
            else:
                print(f"  [read] {fname} — {len(raw_lines)} lines")
                partition_data["contexts"][fname] = raw_lines

        # --- Read mapping .cil files ---
        tmp_partition_dir = info.get("tmp_dir", "")
        mapping_dir = os.path.join(tmp_partition_dir, "mapping")
        if os.path.isdir(mapping_dir):
            for fname in sorted(os.listdir(mapping_dir)):
                if fname.endswith(".cil"):
                    fpath = os.path.join(mapping_dir, fname)
                    lines = _read_lines(fpath)
                    partition_data["mappings"][fname] = lines
                    print(f"  [read] mapping/{fname} — {len(lines)} lines")

        data["partitions"][partition_name] = partition_data

    # Fallback plat_version if vendor wasn't present
    if not data["plat_version"]:
        from config import DEFAULT_PLAT_VERSION
        data["plat_version"] = DEFAULT_PLAT_VERSION
        print(f"\n[warn] plat_version not found in vendor, using default: {DEFAULT_PLAT_VERSION}")

    return data


# ---------------------------------------------------------------------------
# Utility: quick summary of what was read
# ---------------------------------------------------------------------------

def print_read_summary(data: dict):
    """Print a summary table of everything loaded into memory."""
    print("\n" + "=" * 55)
    print("  READ SUMMARY")
    print("=" * 55)
    print(f"  Platform version : {data['plat_version']}")
    print()

    for pname, pdata in data["partitions"].items():
        cil_count = len(pdata["cil_lines"])
        ctx_files = list(pdata["contexts"].keys())
        map_files = list(pdata["mappings"].keys())

        print(f"  Partition : {pname}")
        print(f"    CIL lines    : {cil_count}")
        print(f"    Context files: {len(ctx_files)}")
        for f in ctx_files:
            print(f"      - {f} ({len(pdata['contexts'][f])} lines)")
        if map_files:
            print(f"    Mapping files: {len(map_files)}")
            for f in map_files:
                print(f"      - {f} ({len(pdata['mappings'][f])} lines)")
        print()

    print("=" * 55)
