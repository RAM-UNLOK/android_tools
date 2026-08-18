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
