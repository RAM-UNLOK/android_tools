"""
writer.py — Part 5 of the pipeline.

Assembles the final per-domain (or grouped) .te files from the parsed CIL data.
Implements modern property macros, macro condensation, rule deduplication, 
advanced Taxonomy headers/sorters, and pristine blank-line spacing logic.
"""

import os
import re
from collections import defaultdict

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

def get_taxonomy(name: str) -> tuple:
    lower = name.lower()
    
    vendor = "AOSP / Generic"
    for v, kws in VENDORS.items():
        if any(kw in lower for kw in kws):
            vendor = v
            break

    if "hal_" in lower or lower.endswith("_hal"): role = "HAL"
    elif "app" in lower:
        if any(x in lower for x in["untrusted", "isolated", "ephemeral"]): role = "APP_UNTRUSTED"
        elif any(x in lower for x in["priv", "platform", "system"]): role = "APP_PRIV"
        else: role = "APP_SYSTEM"
    elif "service" in lower or "manager" in lower: role = "SERVICE"
    elif lower.endswith("d") and len(lower) > 2: role = "DAEMON"
    elif any(x in lower for x in ["sysfs", "proc", "dev"]): role = "DRIVER / KERNEL"
    elif "prop" in lower: role = "PROPERTY"
    else: role = "NATIVE / MISC"

    search_str = lower.replace("mediatek", "mtk")
    
    for cat, subcats in TAXONOMY.items():
        for subcat, keywords in subcats.items():
            if any(kw in search_str for kw in keywords):
                return (cat, subcat, role, vendor)
                
    return ("Uncategorized", "Misc", role, vendor)

def get_group_name(name: str) -> str:
    if name.endswith("_prop") or "property" in name: return "property"
    if name.startswith("base_typeattr_"):            return "base_typeattr"
    
    if name.startswith("pdx_"):           return "pdx"
    if name.startswith("fs_bpf"):         return "fs_bpf"
    if name.startswith("binderfs"):       return "binderfs"
    if name.startswith("debugfs"):        return "debugfs"
    if name.startswith("sysfs") or name.startswith("vendor_sysfs"): return "sysfs"
    if name.startswith("procfs_") or name.startswith("proc_") or name == "proc": return "proc"
    if name.startswith("cgroup"):         return "cgroup"
        
    if name.startswith("untrusted_app"):  return "untrusted_app"
    if name.startswith("isolated_app"):   return "isolated_app"
    if name.startswith("sdk_sandbox"):    return "sdk_sandbox"
        
    if name.startswith("apex_"):          return "apex"
    if name.startswith("traced"):         return "traced"
    if name.startswith("tombstoned"):     return "tombstoned"
    if name.startswith("compos"):         return "compos"

    base = name
    suffixes =["_exec", "_socket", "_tmpfs", "_userfaultfd", "_devpts", 
                "_key", "_marker", "_server", "_client", "_type", "_iouring"]
    for _ in range(2):
        for s in suffixes:
            if base.endswith(s):
                base = base[:-len(s)]
                break

    if base.startswith("rild"): return "rild"
    if base.endswith("_hwservice") or base == "hwservicemanager": return "hwservice"
    if base.endswith("_service") or base == "servicemanager":     return "service"
    if base.endswith("_device"): return "device"

    if "hal_" in base:
        for s in ["_default", "_impl"]:
            if base.endswith(s): base = base[:-len(s)]
        return base

    if base.endswith("_file") or base.endswith("_dir") or base.endswith("_fs"):
        return "file"

    return base

# ---------------------------------------------------------------------------
# Property Transformers
# ---------------------------------------------------------------------------

def _transform_property(domain_name: str, type_decls: list, attributes: list) -> tuple:
    MACRO_MAP = {
        "system_internal_property_type": "system_internal_prop",
        "system_restricted_property_type": "system_restricted_prop",
        "system_public_property_type": "system_public_prop",
        "system_vendor_config_property_type": "system_vendor_config_prop",
        "vendor_internal_property_type": "vendor_internal_prop",
        "vendor_restricted_property_type": "vendor_restricted_prop",
        "vendor_public_property_type": "vendor_public_prop",
        "product_internal_property_type": "product_internal_prop",
        "product_restricted_property_type": "product_restricted_prop",
        "product_public_property_type": "product_public_prop",
        "system_ext_internal_property_type": "system_ext_internal_prop",
        "system_ext_restricted_property_type": "system_ext_restricted_prop",
        "system_ext_public_property_type": "system_ext_public_prop",
    }
    
    attr_set = set()
    for attr_line in attributes:
        parts = attr_line.strip(";").split()
        if len(parts) >= 3 and parts[0] == "typeattribute":
            attr_set.add(parts[2])
            
    prop_macro = None
    for attr, macro in MACRO_MAP.items():
        if attr in attr_set:
            prop_macro = macro
            break
            
    is_prop = (prop_macro is not None) or ("property_type" in attr_set) or (domain_name.endswith("_prop"))
    if not is_prop:
        return type_decls, attributes
        
    new_type_decls =[]
    new_attributes =[]
    
    implied_attrs = {"property_type", "system_property_type", "vendor_property_type", 
                     "product_property_type", "system_ext_property_type"}
    if prop_macro:
        for attr, macro in MACRO_MAP.items():
            if macro == prop_macro:
                implied_attrs.add(attr)
                
    for attr_line in attributes:
        parts = attr_line.strip(";").split()
        if len(parts) >= 3 and parts[0] == "typeattribute":
            if prop_macro and parts[2] in implied_attrs:
                continue
        new_attributes.append(attr_line)
        
    for decl in type_decls:
        if decl.startswith(f"type {domain_name};") and prop_macro:
            continue
        new_type_decls.append(decl)
            
    if prop_macro:
        new_type_decls.insert(0, f"{prop_macro}({domain_name})")
        
    return new_type_decls, new_attributes

# ---------------------------------------------------------------------------
# Trigger-Based Permission Compression
# ---------------------------------------------------------------------------

class PermMacro:
    def __init__(self, name, triggers, swallows):
        self.name = name
        self.triggers = set(triggers)
        self.swallows = set(swallows)

OPT_PERMS = {"map", "watch", "watch_reads", "watch_mount", "watch_with_perm", "watch_sb", "ioctl"}

PERM_MACROS =[
    PermMacro("create_dir_perms", {"create", "search"}, {"read", "write", "create", "getattr", "setattr", "lock", "rename", "open", "add_name", "remove_name", "reparent", "search", "rmdir"} | OPT_PERMS),
    PermMacro("rw_dir_perms", {"read", "write", "search"}, {"read", "write", "getattr", "lock", "open", "add_name", "remove_name", "search"} | OPT_PERMS),
    PermMacro("r_dir_perms", {"read", "search"}, {"read", "getattr", "lock", "open", "search"} | OPT_PERMS),
    PermMacro("create_file_perms", {"create", "write", "open"}, {"read", "write", "create", "getattr", "setattr", "lock", "append", "unlink", "rename", "open"} | OPT_PERMS),
    PermMacro("rx_file_perms", {"read", "execute"}, {"read", "getattr", "lock", "open", "execute", "execute_no_trans"} | OPT_PERMS),
    PermMacro("rw_file_perms", {"read", "write", "open"}, {"read", "write", "getattr", "lock", "append", "open"} | OPT_PERMS),
    PermMacro("r_file_perms", {"read", "getattr"}, {"read", "getattr", "lock", "open"} | OPT_PERMS),
    PermMacro("x_file_perms", {"execute"}, {"getattr", "execute", "execute_no_trans"} | OPT_PERMS),
    PermMacro("w_file_perms", {"write", "append"}, {"write", "append", "open", "lock"} | OPT_PERMS),
    PermMacro("create_socket_perms", {"create", "bind", "connect"}, {"read", "write", "create", "getattr", "setattr", "lock", "append", "bind", "connect", "getopt", "setopt", "shutdown"} | OPT_PERMS),
    PermMacro("rw_socket_perms", {"read", "write", "bind"}, {"read", "write", "getattr", "setattr", "lock", "append", "bind", "connect", "getopt", "setopt", "shutdown"} | OPT_PERMS),
]

def compress_perms(perms_str: str) -> str:
    if not perms_str.startswith("{"): return perms_str
    
    perms = set(perms_str.replace("{", "").replace("}", "").split())
    used_macros =[]
    
    for m in PERM_MACROS:
        if m.triggers.issubset(perms):
            perms -= m.swallows
            used_macros.append(m.name)
            
    if used_macros:
        res = sorted(used_macros) + sorted(list(perms))
        if len(res) > 1: return f"{{ {' '.join(res)} }}"
        return res[0]
        
    return perms_str

# ---------------------------------------------------------------------------
# Modern Macro Condenser
# ---------------------------------------------------------------------------

class MacroCondenser:
    def __init__(self, domain, type_decls, attributes, rules):
        self.domain = domain
        self.type_decls = list(dict.fromkeys(type_decls))
        self.attributes = list(dict.fromkeys(attributes))
        self.rules      = list(dict.fromkeys(rules))
        
        self.macros = set()
        self.clean_rules =[]
        self.clean_attrs =[]
        self.has_set_prop = False

    def condense(self) -> tuple:
        drop_regexes =[]

        compressed_rules =[]
        for r in self.rules:
            m = re.match(r'^(allow|dontaudit|neverallow)\s+(\S+)\s+(\S+):(\S+)\s+(.+);$', r)
            if m:
                action, src, tgt, cls, perms_str = m.groups()
                comp_perms = compress_perms(perms_str)
                compressed_rules.append(f"{action} {src} {tgt}:{cls} {comp_perms};")
            else:
                compressed_rules.append(r)

        for r in compressed_rules:
            m = re.match(r'allow\s+(\S+)\s+(\S+)_exec:file\s+(.*entrypoint.*);', r)
            if m and m.group(1) == self.domain and m.group(2) == self.domain:
                self.macros.add(f"init_daemon_domain({self.domain})")
                drop_regexes.append(rf'^allow {self.domain} {self.domain}_exec:file .*$')
                continue
                
            m = re.match(r'allow\s+(\S+)\s+(\S+_prop):file\s+(r_file_perms|\{.*?read.*?\});', r)
            if m:
                self.macros.add(f"get_prop({m.group(1)}, {m.group(2)})")
                drop_regexes.append(rf'^allow {m.group(1)} {m.group(2)}:dir.*$')
                continue

            m = re.match(r'allow\s+(\S+)\s+(\S+_prop):property_service\s+set;', r)
            if m:
                self.macros.add(f"set_prop({m.group(1)}, {m.group(2)})")
                self.has_set_prop = True
                continue

            m = re.match(r'allow\s+(\S+)\s+(hw|vnd|)servicemanager:binder\s+(.*call.*);', r)
            if m:
                pfx = m.group(2)
                if pfx == "": self.macros.add(f"binder_use({m.group(1)})")
                elif pfx == "hw": self.macros.add(f"hwbinder_use({m.group(1)})")
                elif pfx == "vnd": self.macros.add(f"vndbinder_use({m.group(1)})")
                drop_regexes.append(rf'^allow {m.group(1)} {pfx}servicemanager:fd use;$')
                drop_regexes.append(rf'^allow {m.group(1)} {pfx}servicemanager:binder.*transfer.*;$')
                continue

            m = re.match(r'allow\s+(\S+)\s+(\S+):binder\s+(.*call.*);', r)
            if m and m.group(2) not in ("servicemanager", "hwservicemanager", "vndservicemanager", "self"):
                self.macros.add(f"binder_call({m.group(1)}, {m.group(2)})")
                drop_regexes.append(rf'^allow {m.group(1)} {m.group(2)}:fd use;$')
                drop_regexes.append(rf'^allow {m.group(1)} {m.group(2)}:binder.*transfer.*;$')
                continue

            m = re.match(r'allow\s+(\S+)\s+(\S+):service_manager\s+(.*add.*);', r)
            if m:
                self.macros.add(f"add_service({m.group(1)}, {m.group(2)})")
                drop_regexes.append(rf'^allow {m.group(1)} {m.group(2)}:service_manager.*find.*;$')
                continue

            m = re.match(r'allow\s+(\S+)\s+(\S+):hwservice_manager\s+(.*add.*);', r)
            if m:
                self.macros.add(f"add_hwservice({m.group(1)}, {m.group(2)})")
                drop_regexes.append(rf'^allow {m.group(1)} {m.group(2)}:hwservice_manager.*find.*;$')
                continue

            m = re.match(r'allow\s+(\S+)\s+sysfs_wake_lock:file\s+(.*write.*|w_file_perms|rw_file_perms);', r)
            if m:
                self.macros.add(f"wakelock_use({m.group(1)})")
                continue

            self.clean_rules.append(r)

        if self.has_set_prop:
            drop_regexes.append(rf'^allow {self.domain} property_socket:sock_file write;$')
            drop_regexes.append(rf'^allow {self.domain} init:unix_stream_socket connectto;$')
            
        if self.domain in ("servicemanager", "hwservicemanager", "vndservicemanager"):
            drop_regexes.append(rf'^allow {self.domain} \S+:dir.*search.*$')
            drop_regexes.append(rf'^allow {self.domain} \S+:file.*(read|map|open|r_file_perms).*$')
            drop_regexes.append(rf'^allow {self.domain} \S+:process getattr;$')
            drop_regexes.append(rf'^allow {self.domain} \S+:binder.*(call|transfer).*$')
            drop_regexes.append(rf'^allow {self.domain} \S+:fd use;$')

        final_rules =[]
        for r in self.clean_rules:
            drop = any(re.match(pattern, r) for pattern in drop_regexes)
            if not drop: final_rules.append(r)

        for attr in self.attributes:
            m = re.match(r'typeattribute\s+(\S+)\s+(hal_\S+)_client;', attr)
            if m:
                self.macros.add(f"hal_client_domain({m.group(1)}, {m.group(2)})")
                continue
            m = re.match(r'typeattribute\s+(\S+)\s+(hal_\S+)_server;', attr)
            if m:
                self.macros.add(f"hal_server_domain({m.group(1)}, {m.group(2)})")
                continue
                
            if " netdomain;" in attr: self.macros.add(f"net_domain({self.domain})"); continue
            if " appdomain;" in attr: self.macros.add(f"app_domain({self.domain})"); continue
            if " bluetoothdomain;" in attr: self.macros.add(f"bluetooth_domain({self.domain})"); continue
            
            self.clean_attrs.append(attr)

        is_domain = any(re.match(rf'^typeattribute\s+{re.escape(self.domain)}\s+domain;$', a) for a in self.clean_attrs)
        
        if not is_domain and len(self.type_decls) == 1 and self.type_decls[0].startswith("type "):
            attrs =[]
            for a in self.clean_attrs:
                m = re.match(r'^typeattribute\s+\S+\s+(\S+);$', a)
                if m:
                    attrs.append(m.group(1))
            if attrs:
                decl = self.type_decls[0].strip(';')
                self.type_decls[0] = f"{decl}, {', '.join(sorted(attrs))};"
                self.clean_attrs =[]

        return sorted(self.type_decls), sorted(self.clean_attrs), sorted(list(self.macros)) + sorted(final_rules)

# ---------------------------------------------------------------------------
# I/O Helpers
# ---------------------------------------------------------------------------

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

def _write_te_file(filepath: str, group_name: str, tier: str, content_by_domain: dict):
    cat, subcat, role, vendor = get_taxonomy(group_name)
    
    lines =[
        f"# {'=' * 60}",
        f"# File: {group_name}.te",
        f"# Tier: {tier}",
        f"# Vendor: {vendor}",
        f"# Category: {cat}",
        f"# Subcategory: {subcat}",
        f"# Role: {role}",
        f"# Generated by sepolicy_extract",
        f"# {'=' * 60}",
        ""
    ]
    
    multiple = len(content_by_domain) > 1
    for domain_name in sorted(content_by_domain.keys()):
        dom = content_by_domain[domain_name]
        if multiple:
            lines.append(f"# --- {domain_name} ---")
            
        if dom["type_decl"]:  
            lines += dom["type_decl"]
            lines.append("")
        if dom["attributes"]: 
            lines += dom["attributes"]
            lines.append("")
        if dom["rules"]:      
            lines += dom["rules"]
            lines.append("")
            
        lines.append("")

    _write_lines(filepath, lines)

def _write_attributes_file(filepath: str, partition: str, global_attrs: dict):
    base_attrs =[]
    hal_attrs = defaultdict(list)
    core_attrs =[]
    
    for attr_name in sorted(global_attrs.keys()):
        line = global_attrs[attr_name]
        if attr_name.startswith("base_typeattr_"):
            base_attrs.append(line)
        elif "hal_" in attr_name or "_client" in attr_name or "_server" in attr_name:
            cat, _, _, _ = get_taxonomy(attr_name)
            hal_attrs[cat].append(line)
        else:
            core_attrs.append(line)
            
    lines =[
        f"# Global attributes for {partition}",
        f"# Generated by sepolicy_extract",
        ""
    ]
    
    if core_attrs:
        lines.append("# [ Core Attributes ]")
        lines.extend(core_attrs)
        lines.append("")
        
    for cat, attrs in sorted(hal_attrs.items()):
        if cat == "Uncategorized": cat = "Misc HALs"
        lines.append(f"# [ HAL Attributes - {cat} ]")
        lines.extend(attrs)
        lines.append("")
        
    if base_attrs:
        lines.append("# [ Base Type Attributes ]")
        lines.extend(base_attrs)
        lines.append("")
        
    _write_lines(filepath, lines)

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def write_output(parsed: dict, data: dict, out_dir: str):
    print(f"\n[TE] Analyzing Android API mappings for public/private sorting...")
    
    public_types = set()
    for pdata in data["partitions"].values():
        for m_lines in pdata.get("mappings", {}).values():
            for line in m_lines:
                m = re.match(r'\(typeattributeset\s+\S+\s+\((.+?)\)\)', line)
                if m:
                    for t in m.group(1).split():
                        public_types.add(t)

    print(f"[TE] Found {len(public_types)} public types.")
    print(f"[TE] Writing aligned, sorted, and condensed AOSP-style .te files...")

    written = 0
    skipped = 0

    for partition_name, parse_result in parsed.items():
        domains      = parse_result.get("domains", {})
        global_attrs = parse_result.get("global_attributes", {})

        if not domains and not global_attrs:
            continue

        groups = {}
        for domain_name in sorted(domains.keys()):
            dom = domains[domain_name]
            g_name = get_group_name(domain_name)
            
            if g_name not in groups: groups[g_name] = {}
            
            t_decls, t_attrs = _transform_property(
                domain_name,
                dom.get("type_decl",[]),
                dom.get("attributes",[])
            )
            
            condenser = MacroCondenser(
                domain=domain_name,
                type_decls=t_decls,
                attributes=t_attrs,
                rules=dom.get("rules",[])
            )
            f_decls, f_attrs, f_rules = condenser.condense()
            
            groups[g_name][domain_name] = {
                "type_decl": f_decls,
                "attributes": f_attrs,
                "rules": f_rules
            }

        for g_name in sorted(groups.keys()):
            active_domains = {d: c for d, c in groups[g_name].items() if len(c["type_decl"]) + len(c["attributes"]) + len(c["rules"]) > 0}
            if not active_domains:
                skipped += 1
                continue

            is_public = any(d in public_types for d in active_domains)
            
            if partition_name in["vendor", "odm"]:
                tier = "vendor"
            else:
                tier = "public" if is_public else "private"

            tier_dir = os.path.join(out_dir, tier)
            te_path = os.path.join(tier_dir, f"{g_name}.te")

            _write_te_file(filepath=te_path, group_name=g_name, tier=tier, content_by_domain=active_domains)
            written += 1

        if global_attrs:
            tier = "vendor" if partition_name in["vendor", "odm"] else "private"
            attr_path = os.path.join(out_dir, tier, f"_attributes_{partition_name}.te")
            _write_attributes_file(filepath=attr_path, partition=partition_name, global_attrs=global_attrs)
                
    print(f"\n[DONE] Successfully wrote {written} perfectly formatted files.")