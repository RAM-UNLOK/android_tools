The previous script compared custom files against stock files and reported properties that were **missing in stock**.  
You actually want the opposite: **find properties that are present in the stock files but missing from your custom files**, and also list mismatched contexts.  
Additionally, comparisons should be **per‑partition** (private vs private, vendor vs vendor) so you know exactly what belongs where.

Below is a corrected script and an updated README.

---

## 🔧 Corrected Comparison Script

```python
#!/usr/bin/env python3
import re
import sys

def parse_property_contexts_file(filepath):
    """Parse property_contexts file, return dict {pattern: context}."""
    props = {}
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            pattern = parts[0]
            context = parts[1]
            if context.startswith('u:object_r:'):
                props[pattern] = context
            else:
                # fallback (should not happen)
                props[pattern] = context
    return props

def compare_files(custom_file, stock_file):
    """Compare a custom file against its stock counterpart.
       Returns (missing_in_custom, mismatched)
       missing_in_custom: list of (pattern, stock_context) - present in stock but missing in custom
       mismatched: list of (pattern, custom_context, stock_context) - present in both but different
    """
    custom_dict = parse_property_contexts_file(custom_file)
    stock_dict = parse_property_contexts_file(stock_file)

    missing = []
    mismatched = []

    # Check every property in stock
    for pattern, ctx_stock in stock_dict.items():
        if pattern in custom_dict:
            ctx_custom = custom_dict[pattern]
            if ctx_custom != ctx_stock:
                mismatched.append((pattern, ctx_custom, ctx_stock))
        else:
            missing.append((pattern, ctx_stock))

    return missing, mismatched

def print_results(results):
    """results: list of dicts with keys 'custom', 'stock', 'missing', 'mismatched'"""
    for entry in results:
        custom_file = entry['custom']
        stock_file = entry['stock']
        missing = entry['missing']
        mismatched = entry['mismatched']

        # Determine max pattern length for alignment
        max_len = 0
        for p, _, _ in mismatched:
            max_len = max(max_len, len(p))
        for p, _ in missing:
            max_len = max(max_len, len(p))
        max_len = max(max_len, 30)

        print("=" * 80)
        print(f"Comparing: {custom_file}  vs  {stock_file}")
        print(f"Properties missing in custom (present in stock): {len(missing)}")
        if missing:
            for pattern, ctx_stock in missing:
                print(f"  {pattern:<{max_len}}  stock: {ctx_stock}")
        else:
            print("  (none)")

        print(f"\nMismatched contexts: {len(mismatched)}")
        if mismatched:
            for pattern, ctx_custom, ctx_stock in mismatched:
                print(f"  {pattern:<{max_len}}  custom: {ctx_custom}  stock: {ctx_stock}")
        else:
            print("  (none)")
        print()

if __name__ == "__main__":
    # Custom file names – adjust as needed
    custom_private = "custom_private_property_contexts.txt"
    custom_vendor = "custom_vendor_property_contexts.txt"
    stock_private = "stock_private_property_contexts.txt"
    stock_vendor = "stock_vendor_property_contexts.txt"

    # Define pairs: (custom_file, stock_file)
    pairs = [
        {"custom": custom_private, "stock": stock_private},
        {"custom": custom_vendor,  "stock": stock_vendor},
    ]

    results = []
    for pair in pairs:
        missing, mismatched = compare_files(pair["custom"], pair["stock"])
        results.append({
            "custom": pair["custom"],
            "stock": pair["stock"],
            "missing": missing,
            "mismatched": mismatched
        })

    print_results(results)
```

---

## 📘 README.md

```markdown
# Property Contexts Comparator

This tool compares your custom `property_contexts` files against stock (reference) files for the **same partition** (private vs private, vendor vs vendor).  
It reports:

- **Missing properties** – entries present in stock but **not** in your custom file.
- **Mismatched contexts** – entries that exist in both but have different `u:object_r:` types.

This helps you identify which stock property contexts you still need to add or adjust in your custom policy.

---

## 🧰 Requirements

- Python 3.6+ (uses only the standard library)
- Linux (works on any OS, but instructions assume Linux)

---

## 📁 File Setup

Place the four files in the same directory:

| File | Description |
|------|-------------|
| `custom_private_property_contexts.txt` | Your custom private contexts |
| `custom_vendor_property_contexts.txt`  | Your custom vendor contexts  |
| `stock_private_property_contexts.txt`  | Stock private contexts (reference) |
| `stock_vendor_property_contexts.txt`   | Stock vendor contexts (reference) |

You can change the filenames in the script.

---

## 🚀 Setup & Run

### 1. Create a Python virtual environment (recommended)

```bash
python3 -m venv venv
```

### 2. Activate the environment

```bash
source venv/bin/activate
```

### 3. Save the script

Create `compare_property_contexts.py` with the code above.

### 4. Run the script

```bash
python3 compare_property_contexts.py
```

---

## 📊 Example Output

```
================================================================================
Comparing: custom_private_property_contexts.txt  vs  stock_private_property_contexts.txt
Properties missing in custom (present in stock): 5
  ro.product.marketname                     stock: u:object_r:build_prop:s0
  ro.product.mod_device                     stock: u:object_r:exported_default_prop:s0
  ...

Mismatched contexts: 3
  persist.vendor.sys.attestation.status     custom: u:object_r:vendor_mtdservice_prop:s0  stock: u:object_r:vendor_payment_security_prop:s0
  persist.vendor.sys.provision.status       custom: u:object_r:vendor_mtdservice_prop:s0  stock: u:object_r:vendor_payment_security_prop:s0
  ...

================================================================================
Comparing: custom_vendor_property_contexts.txt  vs  stock_vendor_property_contexts.txt
Properties missing in custom (present in stock): 0
  (none)

Mismatched contexts: 2
  ro.vendor.trustonic.ready                 custom: u:object_r:vendor_mtk_trustkernel_tee_prop:s0  stock: u:object_r:vendor_trustonic_prop:s0
  ...
```

The output is aligned for readability.

---

## 🧹 Deactivate

```bash
deactivate
```

---

## 🔧 Customizing File Names

Edit the bottom of the script:

```python
custom_private = "my_custom_private.txt"
custom_vendor = "my_custom_vendor.txt"
stock_private = "my_stock_private.txt"
stock_vendor = "my_stock_vendor.txt"
```

---

## 📝 Notes

- Comments and blank lines are ignored.
- Only the pattern and context are compared; extra flags like `exact bool` are ignored.
- Patterns with trailing dots (e.g., `ro.vendor.oem.`) are treated as exact strings (prefix matching is **not** performed – the comparison is exact).
- The script shows the file name in the output, so you know which partition needs attention.

---

## 📄 License

Free to use and modify for your sepolicy development.
```

---

## ✅ Key Changes

- **Comparison direction** – now finds properties present in stock but missing in custom.
- **Per‑partition** – private is compared to private, vendor to vendor.
- **Clear output** – shows missing and mismatched per file with aligned columns.
- **README** – updated to reflect the correct usage.

Run the script with your four files and it will tell you exactly what you need to add or fix in your custom property contexts.
