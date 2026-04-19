#!/usr/bin/env python3
import sys
from collections import defaultdict

INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else "proprietary-files.txt"
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else "proprietary-files.refined.txt"

# Exact layout order based on paste.txt attachment
TAG_ORDER = [
    "AAL", "APU", "AEE", "Audio", "Audio Configs", "Audio Params",
    "Audio (SoundFX)", "Audio Soundtrigger", "Battery Secret",
    "Battery Aging", "Charger", "Health", "Bluetooth", "Bluetooth (Driver)",
    "Camera", "Camera-arcsoft", "Camera-bin", "Camera-configs",
    "Camera SQLiteModule", "Camera Tuning", "Camera Effects",
    "Camera Extension", "Camera Manifest", "Camera Plugins",
    "Camera Services", "Camera Firmware", "Camera AI", "Camera Algo",
    "Chipinfo", "Connectivity", "ConsumerIR", "Display", "Display Configs",
    "Display DSI", "Display Feature", "Picture Quality", "DRM (Widevine)",
    "Fido", "Fingerprint", "Sensor Calibration", "Firmware", "Fuel Gauge",
    "Gatekeeper", "GNSS", "GNSS (Configs)", "Graphics", "Graphics Configs",
    "HotwordEnrollment", "IMS", "Init modules", "Keymint", "MBrain", "Media",
    "Media (Codec2)", "Decode / Encode", "Dolby / DMS", "Mi Sound", "Mlipay",
    "MMAgent", "MMS", "MTD", "Neural Networks", "NFC", "NFC Configs", "NVRAM",
    "Radio", "Radio (Configs)", "RIL", "APNs", "Secure element", "Sensors",
    "Sensor (Proximity)", "Sensors (Configs)", "SQLite", "Sensors (citsensor)",
    "TEE", "TEE (mitee)", "Thermal", "Thermal Configs", "Tether Offload",
    "Touchfeature", "VPU", "UltraHDR", "WiFi", "Wi-Fi Configs", "Vibrator",
    "Vibrator Firmware", "Video AI", "Pixelworks", "Xiaomi System Services",
    "Miscellaneous"
]

EXT_CONFIGS = (
    ".xml", ".json", ".conf", ".cfg", ".ini", ".rc", ".txt",
    ".bin", ".dat", ".bfbs", ".db", ".prop"
)

EXACT_SECTION_MAP = {
    "audio configs": "Audio Configs",
    "audio calibration": "Audio Params",
    "bluetooth": "Bluetooth",
    "bluetooth (a2dp)": "Bluetooth",
    "gnss": "GNSS",
    "gnss configs": "GNSS (Configs)",
    "mbrain": "MBrain",
    "neural networks": "Neural Networks",
    "nvram": "NVRAM",
    "apu": "APU",
    "vpu": "VPU",
    "aee": "AEE",
    "camera sqlitemodule": "Camera SQLiteModule",
    "camera configs": "Camera-configs",
    "camera firmware": "Camera Firmware",
    "connectivity": "Connectivity",
    "connectivity firmware": "Firmware",
    "payment (xiaomi)": "Mlipay",
    "gatekeeper": "Gatekeeper",
    "drm": "DRM (Widevine)",
    "radio": "Radio",
    "radio (ims)": "IMS",
    "thermal": "Thermal",
    "thermal (xiaomi)": "Thermal",
    "thermal configs": "Thermal Configs",
    "tether offload": "Tether Offload",
    "wi-fi": "WiFi",
    "wi-fi configs": "Wi-Fi Configs",
    "sensors": "Sensors",
    "sensors configs": "Sensors (Configs)",
    "soundtrigger": "Audio Soundtrigger",
    "touchscreen": "Touchfeature",
    "touchscreen firmware": "Touchfeature",
    "display": "Display",
    "display calibration": "Display Configs",
    "media (dolby)": "Dolby / DMS",
    "mitee": "TEE (mitee)",
    "vibrator firmware": "Vibrator Firmware",
}

def l(s): return (s or "").lower()
def has_any(text, *needles): return any(n in text for n in needles)
def is_config_path(p): return "/etc/" in p or p.endswith(EXT_CONFIGS)

def parse_entries(path):
    entries = []
    current_section = None
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line: continue
            if line.startswith("#"):
                if "Unpinned blobs from" in line: continue
                current_section = line[1:].strip()
                continue
            entries.append((current_section, line))
    return entries

def sort_key(blob):
    return (blob.split(";SYMLINK=", 1)[0].lower(), blob.lower())

def classify(section, blob):
    s = l(section)
    p = l(blob)

    # Display / Picture Quality
    if has_any(p, "aivideo", "video_ai", "videoai", "video_enhance"): return "Video AI"
    if has_any(p, "/disp", "dsi") and has_any(p, "panel", "dsi", "disp"):
        if "dsi" in p: return "Display DSI"
    if (has_any(p, "displayconfig", "display_id_", "disp_") and is_config_path(p)) or s == "display calibration": return "Display Configs"
    if has_any(p, "pixelworks"): return "Pixelworks"
    if has_any(p, "displayfeature"): return "Display Feature"
    if has_any(p, "pq_", "mmlpq", "disp_pq", "picture_quality", "mml", "sdrparser"): return "Picture Quality"
    if has_any(p, "hwcomposer", "libdisplaylog", "disp_") or s == "display":
        if "dsi" in p: return "Display DSI"
        return "Display"

    # Hardware / Security
    if has_any(p, "aw8697_haptic.bin", "aw8697_rtp_"): return "Vibrator Firmware"
    if has_any(p, "vendor.mediatek.hardware.aee", "aee_", "aeev", "aedv", "rttv_v2"): return "AEE"
    if has_any(p, "libaalservice", "/libaal_", "aalservice"): return "AAL"
    if has_any(p, "vendor.mediatek.hardware.mms", "hardware.mms@", "mms-service"): return "MMS"
    if has_any(p, "widevine", "oemcrypto", "mediadrm", "drm-service", "clearkey"): return "DRM (Widevine)"
    if has_any(p, "keymint", "keymaster", "libsoft_attestation"): return "Keymint"
    if "gatekeeper" in p: return "Gatekeeper"
    if has_any(p, "mlipay", "mfidoca"): return "Mlipay"
    if has_any(p, "soter", "fido"): return "Fido"
    if has_any(p, "mitee", "/mitee/", "libtida_mitee", "libmt_mitee", "vsim_mitee"): return "TEE (mitee)"
    if has_any(p, "tee-supplicant", "trusty", "teecli", "gz_uree", "trusty-ut-ctrl"): return "TEE"
    if has_any(p, "fingerprint", "goodix", "fpc"): return "Fingerprint"
    if has_any(p, "consumerir", "irspi"): return "ConsumerIR"

    # Battery / Power
    if has_any(p, "batteryantiaging", "antiaging"): return "Battery Aging"
    if has_any(p, "batterysecret", "battery_secret"): return "Battery Secret"
    if has_any(p, "fuelgauge", "fuelgauged"): return "Fuel Gauge"
    if has_any(p, "charger"): return "Charger"
    if has_any(p, "health"): return "Health"

    # Connectivity
    if has_any(p, "wpa_supplicant", "hostapd", "wifi", "wlan_"):
        if is_config_path(p) or s == "wi-fi configs": return "Wi-Fi Configs"
        return "WiFi"
    if has_any(p, "bt_drv", "libbt-vendor", "autobt", "bt_dump", "init.bt_drv"): return "Bluetooth (Driver)"
    if "bluetooth" in p or "bt-" in p: return "Bluetooth"
    if has_any(p, "apdb_", "/apdb/", "ratconfig", "mtkconfig", "libmtkconfig", "hfp_codec_capabilities"): return "Radio (Configs)"
    if has_any(p, "ims", "volte", "rcs", "videotelephony", "ipsec_mon"): return "IMS"
    if has_any(p, "apns-conf", "ecc_list", "spn-conf"): return "APNs"
    if has_any(p, "rild", "libmtkril", "libril", "mtkfusionril"): return "RIL"
    if has_any(p, "mtkril", "radioex", "ccci", "modem", "gsm0710muxd", "atci") and "thriller" not in p: return "Radio"

    if "nvram" in p: return "NVRAM"
    if has_any(p, "gnss", "gps_", "gpsdump", "gps_dump", "lbs_service", "mtk_lbs_service"): return "GNSS (Configs)" if is_config_path(p) else "GNSS"
    if has_any(p, "pnscr"): return "NFC Configs"
    if has_any(p, "android.hardware.nqnfc", "hardware.nfc", "libnfc", "nfc-service"): return "NFC"
    if has_any(p, "secure_element", "android.hardware.secure_element", "_ese_", "ese_"): return "Secure element"

    # Sensors / Thermal
    if "/etc/sensors/" in p or "vendor/etc/sensors/" in p:
        if has_any(p, "cali", "calib", "ois_params"): return "Sensor Calibration"
        if "proximity" in p: return "Sensor (Proximity)"
        return "Sensors (Configs)"
    if "citsensor" in p: return "Sensors (citsensor)"
    if has_any(p, "android.hardware.sensors", "/hw/sensors.", "sensors-service", "dynamic_sensor_hal"): return "Sensors"
    if has_any(p, "touchfeature", "touchreport", "touch_boost", "touchscreen"): return "Touchfeature"
    if has_any(p, "tetheroffload"): return "Tether Offload"

    if "/etc/thermal" in p or "/thermal/" in p or p.endswith("thermal.conf") or p.endswith("thermal-map.conf"): return "Thermal Configs"
    if "thermal" in p or "thermald" in p: return "Thermal"
    if has_any(p, "/etc/gralloc/", "gpu.xml", "vpu.xml", "dpu.xml", "cam.xml"): return "Graphics Configs"
    if has_any(p, "allocator", "gralloc", "mali", "vulkan", "composer", "memtrack", "gpuserv", "libgpud", "libgles", "arm.graphics"): return "Graphics"
    if has_any(p, "ultrahdr", "hdr10p"): return "UltraHDR"

    # Deep learning / APU
    if has_any(p, ".dla", "/etc/nn/", "tensorflowlite", "neuron_", "nn/"): return "Neural Networks"
    if has_any(p, "apu_", "libapu", "apudc") or s == "apu": return "APU"
    if has_any(p, "mvpu", "/vpu", "videobox.json"): return "VPU"
    if "mbrain" in p: return "MBrain"
    if "chipinfo" in p: return "Chipinfo"
    if has_any(p, "conninfra", "connfem", "wmt_loader", "wmt_launcher", "minetd", "miwill", "minet", "connectivity"): return "Connectivity"
    if "/firmware/" in p: return "Firmware"

    # Media / Audio
    if has_any(p, "soundfx"): return "Audio (SoundFX)"
    if has_any(p, "soundtrigger"): return "Audio Soundtrigger"
    if has_any(p, "codec2", "c2.", "libsoft", "libstagefright"): return "Media (Codec2)"
    if has_any(p, "decode", "encode", "vcodec", "vdec", "venc"):
        if "jpeg" in p or "camera" in p or "swjpegencode" in p: return "Camera Plugins" if "plugin" in p else "Camera Algo"
        if "dolby" in p: return "Dolby / DMS"
        return "Decode / Encode"
    if has_any(p, "misound"): return "Mi Sound"
    if has_any(p, "dolby", "dlb", "dmshal", "dms-service"): return "Dolby / DMS"
    if has_any(p, "vow", "voicecommand", "hotword", "soundtrigger"): return "HotwordEnrollment"

    if has_any(p, "sqlite") and "camera" not in p: return "SQLite"

    # Camera
    if "tuning" in p: return "Camera Tuning"
    if "sqlitemodule" in p: return "Camera SQLiteModule"
    if "/etc/camera/" in p or s == "camera configs": return "Camera-configs"
    if "/vintf/manifest/" in p and "camera" in p: return "Camera Manifest"
    if has_any(p, "camerahalserver", "dynamiccameraserver", "camera.provider", "bgservice", "aovservice", "uieventservice", "injection-service"): return "Camera Services"
    if ("/bin/" in p and "camera" in p) or has_any(p, "cameratest", "camera_cal", "camsys_dump_tool", "sentest_v4l2", "jpegtool"): return "Camera-bin"
    if s == "camera firmware": return "Camera Firmware"
    if "/camera/plugins/" in p or "/camera/zsl/" in p: return "Camera Plugins"
    if has_any(p, "arcsoft", "arcraw", "arc.ion", "handgesture.arcsoft"): return "Camera-arcsoft"
    if has_any(p, "synthetic", "camera.injection", "postprocinterface", "extension"): return "Camera Extension"
    if has_any(p, "beauty", "bokeh", "filter", "watermark", "deblur", "depurple", "deflicker", "mimotion", "emoji", "photofilter", "facerelight", "gestureeffects"): return "Camera Effects"
    if has_any(p, "miai", "aiseg", "aicolor", "aiod", "aiot", "portrait_repair_apu", "ai3a", "aibc", "aics", "ainr", "aifr", "aitracking"): return "Camera AI"
    if s == "camera algo" or has_any(p, "camalgo", "mialgo", "featurepipe", "effecthal", "vsdof", "mfll", "cameracustom", "lib3a.", "aaa_", "isptuning", "hal3a"): return "Camera Algo"
    if "camera" in p or s == "camera": return "Camera"

    # Sound Fallback
    if has_any(p, "audio_policy", "audio_effects", "bluetooth_audio_policy", "usb_audio_policy", "default_volume_tables", "a2dp_audio_policy"): return "Audio Configs"
    if has_any(p, "/audio_param/", "/smartpa_param/", "smartpa_", "audioparam", "paramunitdesc", "paramtreeview"): return "Audio Params"
    if "audio" in p: return "Audio"

    # Catch-alls
    if "mms" in p: return "MMS"
    if has_any(p, "videoservice", "videobox", "media", "heif"): return "Media"
    if "vibrator" in p: return "Vibrator"
    if "mmagent" in p: return "MMAgent"
    if "mtd" in p: return "MTD"
    if p.startswith("vendor/etc/init/") or p.startswith("odm/etc/init/") or p.startswith("system_ext/etc/init/"): return "Init modules"
    if "vendor.xiaomi.hardware" in p or "xiaomi.system." in p: return "Xiaomi System Services"

    if s in EXACT_SECTION_MAP:
        return EXACT_SECTION_MAP[s]

    return "Miscellaneous"

def main():
    entries = parse_entries(INPUT_FILE)
    buckets = defaultdict(set)

    for section, blob in entries:
        tag = classify(section, blob)
        buckets[tag].add(blob)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("# Refined proprietary blobs\n")
        out.write(f"# Source: {INPUT_FILE}\n\n")
        for tag in TAG_ORDER:
            items = sorted(buckets.get(tag, set()), key=sort_key)
            if not items:
                continue
            out.write(f"# {tag}\n")
            for item in items:
                out.write(item + "\n")
            out.write("\n")

if __name__ == "__main__":
    main()
