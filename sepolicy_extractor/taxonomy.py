"""
taxonomy.py — single shared copy of the keyword taxonomy (was duplicated in
writer.py and contexts_writer.py).

Matching change: very short / collision-prone keywords (e.g. "sec" matching
"security", "ims" matching "times", "tee" matching "settee") must now match a
whole token (names are split on non-alphanumerics). Everything else is still a
substring match, exactly as before.
"""
import re

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

TOKEN_ONLY = {"sec", "sap", "ims", "tee", "uce", "rcs", "dms", "hmp"}


def _tokens(lower: str) -> set:
    return set(t for t in re.split(r"[^a-z0-9]+", lower) if t)


def kw_match(kw: str, lower: str, toks: set) -> bool:
    if kw in TOKEN_ONLY:
        return kw in toks
    return kw in lower


def get_vendor(name: str) -> str:
    lower = name.lower()
    toks = _tokens(lower)
    for v, kws in VENDORS.items():
        if any(kw_match(kw, lower, toks) for kw in kws):
            return v
    return "AOSP / Generic"


def classify(name: str):
    """Return (category, subcategory) or None."""
    lower = name.lower().replace("mediatek", "mtk")
    toks = _tokens(lower)
    for cat, subcats in TAXONOMY.items():
        for subcat, keywords in subcats.items():
            if any(kw_match(kw, lower, toks) for kw in keywords):
                return cat, subcat
    return None
