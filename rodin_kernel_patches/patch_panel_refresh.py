#!/usr/bin/env python3
import os

PATCHES = [
    # 1. SAFELY HIDE 30Hz FROM ANDROID
    # Let the mode be created, but jump safely over `drm_mode_probed_add`
    # Original: cbz x0, <end> ; mov x20, x0
    # Patched:  b +0x20       ; mov x20, x0 (Jump safely to 60Hz block)
    (
        bytes.fromhex("00000094e00500b4f40300aa00000094"),
        bytes.fromhex("0000009408000014f40300aa00000094")
    ),

    # 2. INTERNAL FALLBACK: lcm_prepare (forces 60Hz if 30Hz is requested internally)
    (
        bytes.fromhex("1f790071e00100541ff10071"),
        bytes.fromhex("1f790071600000541ff10071")
    ),

    # 3. INTERNAL FALLBACK: mtk_panel_ext_param_set
    (
        bytes.fromhex("5f780071a00300545ff00071"),
        bytes.fromhex("5f780071600000545ff00071")
    ),

    # 4. INTERNAL FALLBACK: mtk_panel_ext_param_get
    (
        bytes.fromhex("5f780071e00100545ff00071"),
        bytes.fromhex("5f780071600000545ff00071")
    ),

    # 5a. DISABLE TEARDOWN: lcm_disable for panel-o10-36-02-0b-dsc-vdo.ko
    # Skips the proprietary 30Hz teardown command table entirely
    (
        bytes.fromhex("1f790071c100005401000090"),
        bytes.fromhex("1f7900710600001401000090")
    ),

    # 5b. DISABLE TEARDOWN: lcm_disable for panel-o10-42-02-0a-dsc-vdo.ko
    # Skips the proprietary 30Hz teardown command table entirely
    (
        bytes.fromhex("1f790071c1000054602200d1"),
        bytes.fromhex("1f79007106000014602200d1")
    ),
]

def patch_ko_file(filename):
    if not os.path.exists(filename):
        print(f"[-] File {filename} not found.")
        return

    with open(filename, 'rb') as f:
        data = f.read()

    patched_count = 0
    for search, replace in PATCHES:
        if search in data:
            data = data.replace(search, replace)
            patched_count += 1

    if patched_count > 0:
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"[+] Successfully applied {patched_count} safe patches to {filename}")
    else:
        print(f"[!] No patchable sequences found in {filename}. Ensure you are using UNMODIFIED STOCK files.")

if __name__ == '__main__':
    targets = [
        'panel-o10-36-02-0b-dsc-vdo.ko',
        'panel-o10-42-02-0a-dsc-vdo.ko'
    ]

    print("Applying relocation-safe 30Hz removal patches...")
    for t in targets:
        patch_ko_file(t)
