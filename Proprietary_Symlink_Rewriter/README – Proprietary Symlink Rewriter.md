<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# README – Proprietary Symlink Rewriter

This document explains how to use the script that rewrites `proprietary-files.txt` so that:

- Lines under chipset-specific subfolders (for example `mt6899`) are **kept and get `;SYMLINK=` added**.
- The corresponding “base” lines **without** the chipset folder are **removed**.
- The transformation is done **in place** on `proprietary-files.txt`.

> Adjust names and examples below to match your exact script filename and path logic.

***

## What the script does

Given a `proprietary-files.txt` formatted like LineageOS / AOSP device trees, the script:

1. Scans all non-comment, non-empty lines that **do not already contain `;SYMLINK=`**.
2. Detects **pairs** where the only difference is an extra directory segment (for example, `mt6899`) somewhere in the path:
    - Example pair:
        - `vendor/lib64/rodinimx882wide_mipi_raw_2_tuning.so`
        - `vendor/lib64/mt6899/rodinimx882wide_mipi_raw_2_tuning.so`
3. Gives **priority** to the deeper path that includes the chipset folder (`mt6899` in the examples).
4. Rewrites the deeper path to add a symlink annotation and **removes** its counterpart:
    - Final line:

```text
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_2_tuning.so;SYMLINK=vendor/lib64/rodinimx882wide_mipi_raw_2_tuning.so
```

5. Preserves comments, blank lines, and unrelated entries.

Optionally (depending on the version you use), the script can also:

- Generate `_IdxMgr.so` symlink entries based on existing `_tuning.so` entries (for matching paths).
- Work for any chipset folder name (not just `mt6899`).

***

## File format assumptions

The script assumes your `proprietary-files.txt` follows these conventions:

- Each relevant line is a path, optionally with `;SYMLINK=...` metadata:

```text
vendor/lib64/libfoo.so
vendor/lib64/mt6899/libfoo.so;SYMLINK=vendor/lib64/libfoo.so
```

- Comment lines start with `#`.
- Empty lines may appear and are allowed.
- Only one directional relationship is needed:
    - “Deeper” path (with chipset folder) should point to the “base” path (without that folder).

***

## Typical examples

### 1. Shared libraries

Input:

```text
vendor/lib64/rodinimx882wide_mipi_raw_2_tuning.so
vendor/lib64/rodinimx882wide_mipi_raw_3_tuning.so
vendor/lib64/rodinimx882wide_mipi_raw_4_tuning.so
vendor/lib64/rodinimx882wide_mipi_raw_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_2_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_3_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_4_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_tuning.so
```

After running the script, `proprietary-files.txt` will contain:

```text
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_2_tuning.so;SYMLINK=vendor/lib64/rodinimx882wide_mipi_raw_2_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_3_tuning.so;SYMLINK=vendor/lib64/rodinimx882wide_mipi_raw_3_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_4_tuning.so;SYMLINK=vendor/lib64/rodinimx882wide_mipi_raw_4_tuning.so
vendor/lib64/mt6899/rodinimx882wide_mipi_raw_tuning.so;SYMLINK=vendor/lib64/rodinimx882wide_mipi_raw_tuning.so
```

The non-`mt6899` lines are removed, and only the chipset-specific paths with proper symlink metadata remain.

### 2. Database files

Input:

```text
odm/bin/crossbuild/DataSet/SQLiteModule/db/tuning_DB/rodinimx882wide_mipi_raw/ISP_mapping.db
odm/bin/crossbuild/DataSet/SQLiteModule/db/tuning_DB/rodinimx882wide_mipi_raw/mt6899/ISP_mapping.db
```

Output:

```text
odm/bin/crossbuild/DataSet/SQLiteModule/db/tuning_DB/rodinimx882wide_mipi_raw/mt6899/ISP_mapping.db;SYMLINK=odm/bin/crossbuild/DataSet/SQLiteModule/db/tuning_DB/rodinimx882wide_mipi_raw/ISP_mapping.db
```


***

## Usage

### Requirements

- A POSIX-like shell (Linux, macOS, WSL, etc.).
- Python 3 if you’re using the Python version of the script.
- Your device’s `proprietary-files.txt` file.


### Basic usage

From the directory where `proprietary-files.txt` lives:

```bash
# Dry run (recommended first): create a backup copy
cp proprietary-files.txt proprietary-files.txt.bak

# In-place rewrite
python3 fix_symlinks.py proprietary-files.txt
```

After running:

- Re-open `proprietary-files.txt` and verify:
    - `mt6899` (or target chipset) entries now carry `;SYMLINK=...`.
    - The base counterparts without the chipset folder are removed.
    - Comments and unrelated lines remain as before.

If everything looks good, you can remove the backup. If something went wrong, restore:

```bash
mv proprietary-files.txt.bak proprietary-files.txt
```


***

## Options and variants

If you extended the script, you might have some or all of these behaviors:

- **Universal chipset priority**
Rather than only matching `mt6899`, the script can treat any single directory segment as a “chipset” folder and always keep the deeper path while replacing or annotating it.
- **`_IdxMgr.so` generation**
For paths ending in `_tuning.so`, you can generate a parallel `_IdxMgr.so` pair:

```text
vendor/lib64/mt6899/foo_IdxMgr.so;SYMLINK=vendor/lib64/foo_IdxMgr.so
```

Make sure the `_IdxMgr.so` counterparts actually exist (or that your extraction logic will handle them) before enabling this behavior.
- **Sorting and deduplication**
For tidier output, a variant may:
    - Remove duplicate lines.
    - Sort entries (excluding comments) lexicographically.

Document any extra flags or environment variables you add here (for example `--in-place`, `--with-idxmgr`, `--sort`).

***

## Safety tips

- **Always keep a backup** of `proprietary-files.txt` before running any in-place transformation.
- Test the script on a smaller, copied device tree first.
- After editing, re-run your usual proprietary-blob extraction or build step to confirm nothing is broken.

***

## Troubleshooting

- **No changes in file**
Ensure there are actual pairs where one path has an extra directory component and both paths appear in the file.
- **Unexpected deletions**
Compare with the backup to narrow down which pair was mis-detected, then refine the matching rule (for example, restrict which directory names are treated as chipset folders).
- **Build or extraction failures**
Restore from backup, adjust the matching rules or add explicit exceptions for sensitive paths, then rerun.

***

If you tell me which exact variant of the script you settled on (universal chipset + `_IdxMgr` or only `mt6899`), I can tailor this README to match the exact flags and behavior.

