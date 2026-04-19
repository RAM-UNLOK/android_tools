"""
stage.py — Part 1 of the pipeline.

Discovers all SELinux policy files in the dump (read-only),
copies them into a structured tmp/ working directory.

The dump is NEVER written to. All copies go to tmp_dir only.

Output structure in tmp/:
    tmp/
    ├── system/
    │   ├── plat_sepolicy.cil
    │   ├── plat_file_contexts
    │   ├── mapping/
    │   │   ├── 34.0.cil
    │   │   └── ...
    │   └── ...
    ├── vendor/
    │   ├── vendor_sepolicy.cil
    │   ├── vendor_file_contexts
    │   └── ...
    ├── odm/
    │   └── ...
    └── plat_sepolicy_vers.txt   ← top-level, read from vendor/etc/selinux/
"""

import os
import shutil
from config import PARTITIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _copy_file(src: str, dst: str) -> bool:
    """
    Safely copy a file from dump (read-only source) to tmp dst.
    Creates parent directories as needed.
    Returns True if copied, False if src doesn't exist.
    """
    if not os.path.isfile(src):
        return False
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    return True


def _copy_mapping_dir(dump_path: str, mapping_rel: str, tmp_partition_dir: str) -> list:
    """
    Copy all .cil files from a partition's mapping/ subdirectory.
    Returns list of copied filenames.
    """
    copied = []
    src_dir = os.path.join(dump_path, mapping_rel)
    if not os.path.isdir(src_dir):
        return copied

    dst_dir = os.path.join(tmp_partition_dir, "mapping")
    os.makedirs(dst_dir, exist_ok=True)

    for fname in os.listdir(src_dir):
        if fname.endswith(".cil"):
            src = os.path.join(src_dir, fname)
            dst = os.path.join(dst_dir, fname)
            shutil.copy2(src, dst)
            copied.append(fname)
            print(f"  [staged] mapping/{fname}")

    return copied


# ---------------------------------------------------------------------------
# Main stage function
# ---------------------------------------------------------------------------

def stage_files(dump_path: str, tmp_dir: str) -> dict:
    """
    Walk through all known partition definitions, locate sepolicy files
    in the dump, and copy them to tmp_dir.

    Returns a dict describing what was staged:
    {
        "vendor": {
            "cil": "/tmp/sepolicy_tmp/vendor/vendor_sepolicy.cil",
            "contexts": {
                "vendor_file_contexts": "/tmp/sepolicy_tmp/vendor/vendor_file_contexts",
                ...
            },
            "mappings": ["34.0.cil", ...],
            "plat_vers": "202404"   # only on vendor partition
        },
        "odm": { ... },
        ...
    }
    """

    # Safety: ensure tmp_dir is clean before staging
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir, exist_ok=True)

    staged = {}

    for partition in PARTITIONS:
        pname        = partition["name"]
        selinux_rel  = partition["selinux_path"]     # e.g. "vendor/etc/selinux"
        cil_filename = partition["cil_file"]
        context_files = partition["contexts"]
        mapping_rel  = partition.get("mapping_dir")  # may be None

        selinux_src = os.path.join(dump_path, selinux_rel)

        # Check if this partition even exists in the dump
        if not os.path.isdir(selinux_src):
            print(f"[SKIP] Partition '{pname}' not found at: {selinux_src}")
            continue

        print(f"\n[FOUND] Partition: {pname}  →  {selinux_src}")

        tmp_partition_dir = os.path.join(tmp_dir, pname)
        os.makedirs(tmp_partition_dir, exist_ok=True)

        partition_staged = {
            "cil": None,
            "contexts": {},
            "mappings": [],
            "tmp_dir": tmp_partition_dir,
        }

        # --- Stage the main .cil file ---
        cil_src = os.path.join(selinux_src, cil_filename)
        cil_dst = os.path.join(tmp_partition_dir, cil_filename)
        if _copy_file(cil_src, cil_dst):
            partition_staged["cil"] = cil_dst
            print(f"  [staged] {cil_filename}")
        else:
            print(f"  [MISS]   {cil_filename} (CIL not found — partition may be precompiled-only)")

        # --- Stage context files ---
        for ctx_fname in context_files:
            ctx_src = os.path.join(selinux_src, ctx_fname)
            ctx_dst = os.path.join(tmp_partition_dir, ctx_fname)
            if _copy_file(ctx_src, ctx_dst):
                partition_staged["contexts"][ctx_fname] = ctx_dst
                print(f"  [staged] {ctx_fname}")
            else:
                print(f"  [miss ]  {ctx_fname}")

        # --- Stage mapping/ .cil files if applicable ---
        if mapping_rel:
            copied_mappings = _copy_mapping_dir(dump_path, mapping_rel, tmp_partition_dir)
            partition_staged["mappings"] = copied_mappings

        # --- Special: read plat_sepolicy_vers.txt content directly ---
        if pname == "vendor":
            vers_src = os.path.join(selinux_src, "plat_sepolicy_vers.txt")
            if os.path.isfile(vers_src):
                with open(vers_src, "r") as f:
                    vers = f.read().strip()
                partition_staged["plat_vers"] = vers
                print(f"  [read ]  plat_sepolicy_vers.txt → version: {vers}")
            else:
                from config import DEFAULT_PLAT_VERSION
                partition_staged["plat_vers"] = DEFAULT_PLAT_VERSION
                print(f"  [warn ]  plat_sepolicy_vers.txt not found, using default: {DEFAULT_PLAT_VERSION}")

        staged[pname] = partition_staged

    return staged
