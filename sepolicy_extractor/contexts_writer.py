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

TAXONOMY = {
    "System Core & Framework": {
        "System Services":["system_server", "activity", "package", "window", "servicemanager", "hwservicemanager", "vndservicemanager"],
        "Init & Core Daemons":["init", "vold", "logd", "ueventd", "watchdogd", "llkd", "lmkd", "zygote"],
        "Kernel & Devices":["kernel", "devices", "module", "i2c", "pwrap", "consys", "driver", "blockio"]
    },
    "Fingerprint & Biometrics": {
        "Biometric Core":["biometrics", "fingerprint_service", "fingerprintextension", "fps"],
        "Biometric Vendor":["goodix", "fpc", "soter", "virtual_face", "jiiov"],
        "Biometric Modalities":["fingerprint", "faceauth", "iris", "voiceprint"]
    },
    "Camera": {
        "Camera Effects":["lomoeffect", "filters", "beautify"],
        "Camera Framework":["camera.bgservice", "postproc", "ccap", "camerapostalgo"],
        "Camera HAL":["camera", "isphal", "lens"]
    },
    "Audio & Video": {
        "Voice & Call Audio":["in_call", "voip", "telecom", "audiocmd"],
        "Media Framework":["omx", "media", "mediaserver", "mediacodec", "mediaextractor", "mediadrm", "mediatranscoding", "mediatuner", "codec", "extractor"],
        "Audio HAL":["audio", "mixer", "sound", "dolby", "dms"]
    },
    "Display & Graphics": {
        "Compositing":["surfaceflinger", "composer"],
        "GPU Stack":["graphics", "gpu", "mali", "vulkan", "opengl"],
        "Display Pipeline":["display", "hwc", "hardware.pq", "dfps", "hdmi"]
    },
    "Radio & Telephony": {
        "IMS & VoLTE":["ims", "volte", "isap", "sap", "uce", "rcs"],
        "Messaging":["sms", "isms"],
        "Modem & RIL":["radio", "ril", "modem", "telephony", "cdma"]
    },
    "Network (Wi-Fi, BT, NFC)": {
        "Bluetooth Stack":["bluetooth", "bt_hal", "btdbg"],
        "Proximity & Short-range":["nfc", "uwb", "nxp", "secure_element"],
        "Wi-Fi Stack":["wifi", "wlan", "netd", "macsec", "supplicant", "hotspot"]
    },
    "Power & Thermal": {
        "Battery & Charging":["battery", "charger", "charge", "charging", "fuelgauge", "fuel_gauge", "kpoc", "power_supply"],
        "Thermal Control":["thermal", "thermald", "cooling", "mi_thermald"],
        "Power Management":["power", "perf", "governor", "mtkpower"]
    },
    "Sensors & Location": {
        "Location Stack":["gnss", "gps", "agps", "lbs", "mnld"],
        "Sensor HAL":["sensor", "presence", "sensorhub", "contexthub"]
    },
    "Security & TEE": {
        "Crypto Services":["keymaster", "keymint", "keystore", "keymanage", "authgraph"],
        "Authentication Services":["gatekeeper", "weaver", "authsecret", "secretkeeper"],
        "TEE Core":["teei", "trustonic", "microtrust", "nxpese", "tee", "mitee", "soter"]
    },
    "Input & Touch": {
        "Touchscreen":["touch", "tp_"],
        "Input Devices":["input", "keypad", "keyboard", "mouse"]
    },
    "Hardware & Peripheral": {
        "USB":["usb", "typec", "xhci", "musb"],
        "Vibrator":["vibrator", "haptic"],
        "LEDs":["leds", "flashlight", "torch"]
    },
    "AI & Neural Networks": {
        "AI Accelerators":["neuron", "apuware", "neuropilot", "xrp", "hmp"],
        "NN Runtime":["neuralnetworks", "nnapi", "hal_nn"]
    },
    "Storage & Memory": {
        "Block Devices":["mmc", "ufs", "flash", "mtd", "blk_", "zram"],
        "NVRAM & Calibration":["nvram", "oem_cali", "factory", "meta_tst", "persist"],
        "Volume Management":["vold", "sdcard", "storage", "fuse", "exfat", "vfat", "firmware"]
    },
    "Apps & UX": {
        "Privileged/OEM Apps":["launcher", "updater", "diagapp", "permissioncontroller"],
        "System Apps":["settings", "dialer", "systemui"],
        "Third-party Apps":["untrusted_app", "isolated_app", "ephemeral_app", "sdk_sandbox"]
    },
    "Connectivity & Internet": {
        "Generic Network Services":["dns", "dhcp", "tether", "vpn", "firewall", "clatd", "ppp"],
        "Data Management":["quota", "bandwidth"]
    },
    "Debug, Logging & Diagnostics": {
        "Debug tools":["adb", "shell", "debuggerd", "simpleperf", "crash_dump", "tombstone", "debugfs"],
        "OEM Diagnostics":["diag", "engineer", "atci", "dtool"],
        "Logging":["logcat", "logd", "statsd", "traced", "mdlogger", "logger", "log_"]
    },
    "Update & Provisioning": {
        "Provisioning & Enrollment":["device_setup", "provision", "rkpd"],
        "OTA & Partitions":["update_engine", "otapreopt", "recovery", "boot_control", "cppreopts", "fastboot"]
    }
}

VENDORS = {
    "MediaTek":["mtk", "mediatek"],
    "Qualcomm":["qcom", "qualcomm", "qti"],
    "Exynos":["exynos", "slsi"],
    "Xiaomi":["xiaomi", "miui"],
    "Goodix":["goodix"],
    "Jiiov":["jiiov"],
    "NXP":["nxp"],
    "Samsung":["samsung", "sec"],
    "Trustonic":["trustonic", "microtrust", "teei"]
}

def _get_vendor(name: str) -> str:
    lower = name.lower()
    for v, kws in VENDORS.items():
        if any(kw in lower for kw in kws):
            return v
    return "AOSP / Generic"

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
            assigned = False
            vendor = _get_vendor(left)
            
            for cat, subcats in TAXONOMY.items():
                if assigned: break
                for subcat, keywords in subcats.items():
                    if any(kw in search_str for kw in keywords):
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

def write_contexts(data: dict, parsed: dict, out_dir: str):
    print(f"\n[CTX] Writing aligned, sorted, and categorized context files to: {out_dir}")
    aggregated = {"private": {}, "vendor": {}, "public": {}}

    for partition_name, partition_data in data["partitions"].items():
        tier = "vendor" if partition_name in["vendor", "odm"] else "private"
        prefix = PARTITION_PREFIX.get(partition_name, partition_name)
        contexts = partition_data.get("contexts", {})

        for output_name in CONTEXT_OUTPUT_NAMES:
            src_key = f"{prefix}_{output_name}"
            if src_key in contexts and contexts[src_key]:
                if output_name not in aggregated[tier]: aggregated[tier][output_name] = {}
                aggregated[tier][output_name][partition_name] = contexts[src_key]

        if partition_name == "vendor":
            for fname in VENDOR_EXTRA:
                if fname in contexts and contexts[fname]:
                    if fname not in aggregated[tier]: aggregated[tier][fname] = {}
                    aggregated[tier][fname][partition_name] = contexts[fname]

        if partition_name in parsed:
            genfs = parsed[partition_name].get("genfs_contexts",[])
            if genfs:
                if "genfs_contexts" not in aggregated[tier]: aggregated[tier]["genfs_contexts"] = {}
                aggregated[tier]["genfs_contexts"][partition_name] = genfs

    for tier, files in aggregated.items():
        if not files: continue
        tier_dir = os.path.join(out_dir, tier)
        
        for fname, partition_dict in files.items():
            final_lines =[f"# {fname} - Generated by sepolicy_extract", ""]
            
            owner_first = any(x in fname for x in["file_contexts", "genfs_contexts"])
            categorize = True
            
            for part_name in sorted(partition_dict.keys()):
                raw_lines = partition_dict[part_name]
                aligned_block = _format_and_align_contexts(raw_lines, categorize=categorize, owner_first=owner_first)
                
                if aligned_block:
                    final_lines.append(f"# {'=' * 40}")
                    final_lines.append(f"# Partition: {part_name}")
                    final_lines.append(f"# {'=' * 40}")
                    final_lines.append("")
                    final_lines.extend(aligned_block)
                    final_lines.append("")
            
            out_path = os.path.join(tier_dir, fname)
            _write_lines(out_path, final_lines)
            print(f"  [write] {tier}/{fname}  (Taxonomy Applied)")

    print("\n[CTX] Context writing complete.")