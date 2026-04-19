#!/usr/bin/env python3
"""
main.py — Entry point for the SEPolicy extraction tool.

Usage:
    python3 main.py <dump_path> [--out <output_path>]

Example:
    python3 main.py /mnt/dump/rodin
    python3 main.py /mnt/dump/rodin --out /home/user/my_sepolicy_out
"""

import argparse
import os
import shutil
import sys

# Internal modules
from config import DEFAULT_OUT_DIRNAME, TMP_DIRNAME
from stage import stage_files
from reader import read_staged, print_read_summary
from cil_parser import parse_all_cil
from contexts_writer import write_contexts
from writer import write_output


def resolve_output_dir(custom_out: str | None) -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if custom_out:
        return os.path.abspath(custom_out)
    return os.path.join(script_dir, DEFAULT_OUT_DIRNAME)


def resolve_tmp_dir() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, TMP_DIRNAME)


def validate_dump_path(dump_path: str) -> str:
    abs_path = os.path.abspath(dump_path)
    if not os.path.exists(abs_path):
        print(f"[ERROR] Dump path does not exist: {abs_path}")
        sys.exit(1)
    if not os.path.isdir(abs_path):
        print(f"[ERROR] Dump path is not a directory: {abs_path}")
        sys.exit(1)
    return abs_path


def clean_output_dir(out_dir: str):
    """Wipe out the old output directory to prevent ghost folders from previous runs."""
    if os.path.exists(out_dir):
        print(f"[INFO] Cleaning old output directory: {out_dir}")
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)


def verify_output(out_dir: str):
    """
    Post-Extraction Verification Check.
    Validates Folder Structuring, Braces Matching, and Empty Files.
    """
    print("\n" + "=" * 60)
    print("  [VERIFY] Running Post-Extraction Verification Check")
    print("=" * 60)

    allowed_dirs = {"private", "public", "vendor"}
    errors = 0
    warnings = 0

    # 1. Strict Directory Structure Check
    found_dirs = set()
    for item in os.listdir(out_dir):
        item_path = os.path.join(out_dir, item)
        if os.path.isdir(item_path):
            found_dirs.add(item)
            if item not in allowed_dirs:
                print(f"  [ERROR] Invalid folder found: {item} (Expected only private, public, vendor)")
                errors += 1

    if found_dirs.issubset(allowed_dirs):
        print(f"  [OK] Folder structure check passed (Found: {', '.join(found_dirs)})")
    else:
        print(f"  [FAIL] Expected only {allowed_dirs}, but got {found_dirs}")

    # 2. File size and integrity
    empty_files =[]
    te_files = 0
    ctx_files = 0
    brace_errors = 0

    for root, dirs, files in os.walk(out_dir):
        for file in files:
            filepath = os.path.join(root, file)

            # Check for 0 byte files
            if os.path.getsize(filepath) == 0:
                empty_files.append(filepath)

            # Syntax validation on .te files
            if file.endswith(".te"):
                te_files += 1
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.count('{') != content.count('}'):
                        print(f"  [ERROR] Unbalanced braces in {os.path.relpath(filepath, out_dir)}")
                        brace_errors += 1
                        errors += 1

            elif "contexts" in file or "mac_permissions" in file or "cil" in file:
                ctx_files += 1

    if empty_files:
        print(f"  [WARN] Found {len(empty_files)} completely empty files.")
        warnings += len(empty_files)
    else:
        print(f"[OK] No empty files generated.")

    if brace_errors == 0:
        print(f"[OK] Syntax braces {{ }} match perfectly across all .te files.")

    print(f"[OK] Successfully validated {te_files} .te files and {ctx_files} context aggregates.")

    print("-" * 60)
    if errors == 0:
        print(f"  [SUCCESS] Extraction & Verification Passed! (Warnings: {warnings})")
    else:
        print(f"  [FAILED] Verification Failed with {errors} Errors.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="extract_sepolicy",
        description="Extract and convert SELinux policy files from an Android firmware dump.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py /path/to/dump
  python3 main.py /path/to/dump --out /path/to/output
        """
    )
    parser.add_argument(
        "dump_path",
        help="Path to the root of the extracted Android firmware dump (e.g. dumpyara output folder)"
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=None,
        help="Optional: custom output directory path. Defaults to sepolicy_out/ next to this script."
    )
    parser.add_argument(
        "--keep-tmp",
        action="store_true",
        default=False,
        help="Keep the temporary staging directory after extraction (useful for debugging)"
    )
    return parser.parse_args()


def print_banner():
    print("=" * 60)
    print("  SEPolicy Extractor — Android Firmware Dump")
    print("  Supports: system, system_ext, product, vendor, odm")
    print("=" * 60)


def main():
    print_banner()
    args = parse_args()

    # --- Resolve and validate paths ---
    dump_path = validate_dump_path(args.dump_path)
    out_dir   = resolve_output_dir(args.out_path)
    tmp_dir   = resolve_tmp_dir()

    # Safety check: make sure out_dir and tmp_dir are NOT inside dump_path
    dump_real = os.path.realpath(dump_path)
    out_real  = os.path.realpath(out_dir)
    tmp_real  = os.path.realpath(tmp_dir)

    if out_real.startswith(dump_real):
        print(f"[ERROR] Output directory cannot be inside the dump path!")
        print(f"        dump : {dump_real}")
        print(f"        out  : {out_real}")
        sys.exit(1)

    if tmp_real.startswith(dump_real):
        print(f"[ERROR] Temp directory cannot be inside the dump path!")
        sys.exit(1)

    print(f"\n[INFO] Dump path : {dump_path}")
    print(f"[INFO] Output dir: {out_dir}")
    print(f"[INFO] Temp dir  : {tmp_dir}")
    print()

    # --- Part 1: Stage files from dump → tmp ---
    staged = stage_files(dump_path, tmp_dir)

    if not staged:
        print("\n[ERROR] No sepolicy files were found in the dump. Aborting.")
        sys.exit(1)

    print(f"\n[OK] Staging complete. Found files across {len(staged)} partition(s).")

    # --- Part 2: Read all staged files into memory ---
    data = read_staged(staged)
    print_read_summary(data)

    # --- Part 3: Parse all CIL files ---
    parsed = parse_all_cil(data)

    # --- PRE-WRITE: Wipe old output dir ---
    clean_output_dir(out_dir)

    # --- Part 4: Write context files ---
    write_contexts(data, parsed, out_dir)

    # --- Part 5: Write .te files (Pass Data for API mapping) ---
    write_output(parsed, data, out_dir)

    # --- Part 6: Validate output ---
    verify_output(out_dir)

    print("\n[INFO] Extraction complete.")

    # --- Cleanup tmp unless --keep-tmp ---
    if not args.keep_tmp:
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
            print(f"[INFO] Temp dir cleaned up: {tmp_dir}")
    else:
        print(f"[INFO] Temp dir kept at: {tmp_dir}")


if __name__ == "__main__":
    main()
