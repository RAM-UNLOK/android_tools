"""
config.py — Central configuration for all partition paths, file mappings,
and constants used across the sepolicy extraction pipeline.
"""

# ---------------------------------------------------------------------------
# Platform policy version suffix (read from plat_sepolicy_vers.txt at runtime)
# Default fallback if file is missing
# ---------------------------------------------------------------------------
DEFAULT_PLAT_VERSION = "202404"

# ---------------------------------------------------------------------------
# Partition definitions
# Each entry:
#   key        = short partition name used in output folder naming
#   selinux_path = path relative to dump root where selinux files live
#   cil_file   = the .cil file name inside that selinux_path
#   prefix     = prefix used on context filenames (e.g. "plat" → plat_file_contexts)
#   contexts   = list of context filenames to look for (relative to selinux_path)
# ---------------------------------------------------------------------------
PARTITIONS = [
    {
        "name": "system",
        "selinux_path": "system/etc/selinux",
        "cil_file": "plat_sepolicy.cil",
        "contexts": [
            "plat_file_contexts",
            "plat_property_contexts",
            "plat_service_contexts",
            "plat_hwservice_contexts",
            "plat_seapp_contexts",
            "plat_mac_permissions.xml",
            "plat_keystore2_key_contexts",
            "plat_tee_service_contexts",
            "plat_sepolicy_and_mapping.sha256",
        ],
        "mapping_dir": "system/etc/selinux/mapping",
    },
    {
        "name": "system_ext",
        "selinux_path": "system_ext/etc/selinux",
        "cil_file": "system_ext_sepolicy.cil",
        "contexts": [
            "system_ext_file_contexts",
            "system_ext_property_contexts",
            "system_ext_service_contexts",
            "system_ext_hwservice_contexts",
            "system_ext_seapp_contexts",
            "system_ext_mac_permissions.xml",
            "system_ext_keystore2_key_contexts",
            "system_ext_tee_service_contexts",
            "system_ext_sepolicy_and_mapping.sha256",
            "userdebug_plat_sepolicy.cil",
        ],
        "mapping_dir": "system_ext/etc/selinux/mapping",
    },
    {
        "name": "product",
        "selinux_path": "product/etc/selinux",
        "cil_file": "product_sepolicy.cil",
        "contexts": [
            "product_file_contexts",
            "product_property_contexts",
            "product_service_contexts",
            "product_hwservice_contexts",
            "product_seapp_contexts",
            "product_mac_permissions.xml",
            "product_keystore2_key_contexts",
            "product_tee_service_contexts",
        ],
        "mapping_dir": "product/etc/selinux/mapping",
    },
    {
        "name": "vendor",
        "selinux_path": "vendor/etc/selinux",
        "cil_file": "vendor_sepolicy.cil",
        "contexts": [
            "vendor_file_contexts",
            "vendor_property_contexts",
            "vendor_service_contexts",
            "vendor_hwservice_contexts",
            "vendor_seapp_contexts",
            "vendor_mac_permissions.xml",
            "vendor_keystore2_key_contexts",
            "vndservice_contexts",
            "plat_pub_versioned.cil",
            "plat_sepolicy_vers.txt",
            "selinux_denial_metadata",
        ],
        "mapping_dir": None,  # vendor has no mapping/ subdir
    },
    {
        "name": "odm",
        "selinux_path": "odm/etc/selinux",
        "cil_file": "odm_sepolicy.cil",
        "contexts": [
            "odm_file_contexts",
            "odm_property_contexts",
            "odm_service_contexts",
            "odm_hwservice_contexts",
            "odm_seapp_contexts",
            "odm_mac_permissions.xml",
            "precompiled_sepolicy",
            "precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
            "precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256",
        ],
        "mapping_dir": None,
    },
]

# ---------------------------------------------------------------------------
# Context files that need #line header stripping before use
# ---------------------------------------------------------------------------
NEEDS_LINE_STRIP = {
    "vendor_property_contexts",
    "vndservice_contexts",
    "plat_property_contexts",
    "system_ext_property_contexts",
    "product_property_contexts",
    "odm_property_contexts",
}

# ---------------------------------------------------------------------------
# CIL statement types and how they map to .te output
# ---------------------------------------------------------------------------
# Statements that are keyed by their SUBJECT (first arg) → go into <subject>.te
SUBJECT_KEYED = {
    "allow",
    "dontaudit",
    "neverallow",
    "typetransition",
    "allowx",
}

# Statements that declare types/attributes → also go into <type>.te
TYPE_DECL = {
    "type",
    "typeattribute",
    "typealias",
    "typealiasactual",
}

# typeattributeset → membership lines go into each member's .te
# genfscon → goes into genfs_contexts file

# ---------------------------------------------------------------------------
# Output folder name
# ---------------------------------------------------------------------------
DEFAULT_OUT_DIRNAME = "sepolicy_out"
TMP_DIRNAME = "sepolicy_tmp"
