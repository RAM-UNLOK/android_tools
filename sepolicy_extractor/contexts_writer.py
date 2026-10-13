"""
contexts_writer.py — Part 4 of the pipeline.

Writes all context files into the AOSP 3-tier folder structure.
Features perfect column alignment, alphabetical sorting, and an advanced 
multi-dimensional Taxonomy engine.
"""

import os
from collections import defaultdict

PARTITION_PREFIX = {
    "system":     "plat",
    "system_ext": "system_ext",
    "product":    "product",
    "vendor":     "vendor",
    "odm":        "odm",
}

CONTEXT_OUTPUT_NAMES =[
    "file_contexts",
    "property_contexts",
    "service_contexts",
    "hwservice_contexts",
    "seapp_contexts",
    "mac_permissions.xml",
    "keystore2_key_contexts",
    "tee_service_contexts",
]

VENDOR_EXTRA =[
    "vndservice_contexts",
    "plat_pub_versioned.cil",
    "plat_sepolicy_vers.txt",
    "selinux_denial_metadata",
]

from taxonomy import TAXONOMY, VENDORS, get_vendor as _get_vendor, kw_match, _tokens


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def _write_lines(filepath: str, lines: list):
    _ensure_dir(os.path.dirname(filepath))
    
    # Prune consecutive blank lines for perfect spacing
    clean_lines =[]
    prev_empty = False
    for line in lines:
        is_empty = (line.strip() == "")
        if is_empty and prev_empty:
            continue
        clean_lines.append(line)
        prev_empty = is_empty
        
    with open(filepath, "w", encoding="utf-8") as f:
        for line in clean_lines:
            f.write(line + "\n")

def _format_and_align_contexts(lines: list, categorize: bool = False, owner_first: bool = False) -> list:
    """Sorts, aligns, and applies a rich 2-dimensional taxonomy hierarchy with perfect spacing."""
    data = list(set([l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]))
    
    max_len = 0
    parsed =[]
    for l in data:
        idx = l.find(" u:object_r:")
        if idx == -1: idx = l.find(" u:r:")
        if idx != -1:
            left, right = l[:idx].strip(), l[idx:].strip()
            max_len = max(max_len, len(left))
            parsed.append((left, right))
        else:
            parts = l.split()
            if len(parts) >= 2:
                left, right = " ".join(parts[:-1]), parts[-1]
                max_len = max(max_len, len(left))
                parsed.append((left, right))
            else:
                parsed.append((l, ""))
                
    formatted =[]

    if categorize:
        if owner_first:
            grouped = defaultdict(lambda: defaultdict(list))
        else:
            grouped = {cat: defaultdict(list) for cat in TAXONOMY}
            grouped["Uncategorized / Misc"] = defaultdict(list)

        for left, right in parsed:
            search_str = left.lower().replace("mediatek", "mtk")
            _tk = _tokens(search_str)
            assigned = False
            vendor = _get_vendor(left)
            
            for cat, subcats in TAXONOMY.items():
                if assigned: break
                for subcat, keywords in subcats.items():
                    if any(kw_match(kw, search_str, _tk) for kw in keywords):
                        if owner_first:
                            grouped[vendor][cat].append((left, right))
                        else:
                            subcat_name = f"{vendor} {subcat}" if vendor != "AOSP / Generic" else subcat
                            grouped[cat][subcat_name].append((left, right))
                        assigned = True
                        break
            if not assigned:
                if owner_first:
                    grouped[vendor]["Misc"].append((left, right))
                else:
                    subcat_name = f"{vendor} Misc" if vendor != "AOSP / Generic" else "Misc"
                    grouped["Uncategorized / Misc"][subcat_name].append((left, right))

        if owner_first:
            for vendor, cats in sorted(grouped.items()):
                formatted.append(f"# [ Vendor: {vendor} ]")
                for cat, items in sorted(cats.items()):
                    if not items: continue
                    formatted.append(f"# --- {cat} ---")
                    for left, right in sorted(items):
                        if right: formatted.append(f"{left.ljust(max_len + 4)}{right}")
                        else: formatted.append(left)
                    formatted.append("") # 1 line spacing between categories
                formatted.append("")     # 1 line spacing between vendors
        else:
            for cat, subcats in grouped.items():
                if not subcats: continue
                formatted.append(f"# [ {cat} ]")
                for subcat, items in sorted(subcats.items()):
                    if not items: continue
                    formatted.append(f"# --- {subcat} ---")
                    for left, right in sorted(items):
                        if right: formatted.append(f"{left.ljust(max_len + 4)}{right}")
                        else: formatted.append(left)
                    formatted.append("") # 1 line spacing between subcategories
                formatted.append("")     # 1 line spacing between categories
    else:
        for left, right in sorted(parsed):
            if right: formatted.append(f"{left.ljust(max_len + 4)}{right}")
            else: formatted.append(left)
            
    return formatted

# Files that must be copied byte-for-byte (they are XML / CIL / free text, NOT
# "<key> <context>" lines; sorting/deduping/stripping comments destroys them).
VERBATIM = {"mac_permissions.xml", "plat_pub_versioned.cil",
            "plat_sepolicy_vers.txt", "selinux_denial_metadata"}
# Files whose line ORDER is meaningful - never sorted, comments kept.
ORDER_SENSITIVE = {"seapp_contexts"}


def write_contexts(data: dict, parsed: dict, out_dir: str):
    print(f"\n[CTX] Writing context files to: {out_dir}")
    aggregated = {"private": {}, "vendor": {}, "public": {}}
    verbatim = []   # (path, lines)

    for partition_name, partition_data in data["partitions"].items():
        tier = "vendor" if partition_name in ["vendor", "odm"] else "private"
        prefix = PARTITION_PREFIX.get(partition_name, partition_name)
        contexts = partition_data.get("contexts", {})

        for output_name in CONTEXT_OUTPUT_NAMES:
            lines = contexts.get(f"{prefix}_{output_name}")
            if not lines:
                continue
            if output_name in VERBATIM:
                verbatim.append((os.path.join(out_dir, tier, f"{prefix}_{output_name}"), lines))
            else:
                aggregated[tier].setdefault(output_name, {})[partition_name] = lines

        if partition_name == "vendor":
            for fname in VENDOR_EXTRA:
                lines = contexts.get(fname)
                if not lines:
                    continue
                if fname in VERBATIM:
                    verbatim.append((os.path.join(out_dir, tier, fname), lines))
                else:
                    aggregated[tier].setdefault(fname, {})[partition_name] = lines

        if partition_name in parsed:
            genfs = parsed[partition_name].get("genfs_contexts", [])
            if genfs:
                aggregated[tier].setdefault("genfs_contexts", {})[partition_name] = genfs

    # --- verbatim copies -------------------------------------------------
    for path, lines in verbatim:
        _write_raw(path, lines)
        print(f"  [copy ] {os.path.relpath(path, out_dir)}  (verbatim)")

    # --- aligned / sorted / categorised -----------------------------------
    for tier, files in aggregated.items():
        for fname, partition_dict in files.items():
            final_lines = [f"# {fname} - Generated by sepolicy_extract", ""]
            ordered = fname in ORDER_SENSITIVE
            owner_first = any(x in fname for x in ["file_contexts", "genfs_contexts"])

            for part_name in sorted(partition_dict):
                raw_lines = partition_dict[part_name]
                if ordered:
                    block = [l for l in raw_lines]          # untouched, incl. comments
                else:
                    block = _format_and_align_contexts(raw_lines, categorize=True,
                                                       owner_first=owner_first)
                if block:
                    final_lines += [f"# {'=' * 40}", f"# Partition: {part_name}",
                                    f"# {'=' * 40}", ""] + block + [""]

            out_path = os.path.join(out_dir, tier, fname)
            if ordered:
                _write_raw(out_path, final_lines)
            else:
                _write_lines(out_path, final_lines)
            print(f"  [write] {tier}/{fname}" + ("  (order preserved)" if ordered else ""))

    print("\n[CTX] Context writing complete.")


def _write_raw(filepath: str, lines: list):
    _ensure_dir(os.path.dirname(filepath))
    with open(filepath, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
