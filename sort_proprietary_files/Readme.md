# Proprietary Files Sorter

A Python utility designed to parse, clean, and meticulously categorize Android vendor blobs in `proprietary-files.txt`.

When extracting blobs from a device for custom ROM development (like LineageOS or AOSP), the generated list can often be messy, unorganized, or grouped under overly broad sections. This script uses path heuristics, keyword matching, and existing headers to sort thousands of blobs into highly specific, organized tags (e.g., splitting a massive `# Camera` block into `# Camera-configs`, `# Camera Algo`, `# Camera Plugins`, etc.).

## Features
- **Smart Categorization**: Classifies blobs into specific hardware/software buckets based on filenames, directories, and existing headers.
- **Strict Ordering**: Follows a predefined logical layout (Baseband, Compute, Security, Display, Camera, Audio, etc.) ensuring a clean and standard tree structure.
- **Deep Granularity**: Handles complex vendor trees (like Xiaomi and MediaTek), successfully isolating distinct components like `# APU`, `# TEE (mitee)`, `# Media (Codec2)`, `# Picture Quality`, and `# Fingerprint`.
- **Catch-All Safety**: Any unrecognized blobs are safely dropped into a `# Miscellaneous` block at the end of the file, guaranteeing no files are accidentally deleted or lost during the sort.
- **Symlink Preservation**: Properly parses and retains `SYMLINK=` rules and component suffixes.

## Prerequisites
- Python 3.6 or higher.
- No external dependencies required (uses standard Python libraries).

## Usage

1. Place your target `proprietary-files.txt` in the same directory as the script.
2. Run the script via the command line:

```bash
python3 sort_blobs.py
```

### Advanced Usage
You can manually specify the input and output filenames by passing them as arguments:

```bash
python3 sort_blobs.py <input_file.txt> <output_file.txt>

# Example:
python3 sort_blobs.py proprietary-files-vendor.txt proprietary-files-vendor.refined.txt
```

## How It Works

The script operates using a cascading priority system located in the `classify(section, blob)` function:
1. **Specific File Paths**: Checks if the file contains specific strings or directories (e.g., `aivideo`, `/dsi/`, `.xml`).
2. **Component Rules**: Matches component signatures to known tags (e.g., mapping `libstagefright` to `# Media (Codec2)`).
3. **Exact Header Matching**: If the file doesn't match specific strings, it checks if its original section header maps to a refined category in `EXACT_SECTION_MAP`.
4. **Miscellaneous Fallback**: If all checks fail, the blob is appended to `# Miscellaneous`.

## Customization

If you need to add new tags or change where specific files go, you can easily edit the script:

1. **Adding a New Tag**:
   Add your new tag name to the `TAG_ORDER` list where you want it to appear in the final text file.

2. **Routing Files to the Tag**:
   Scroll down to the `classify` function and add a simple `if` statement matching the keyword:
   ```python
   if has_any(p, "your_keyword", "another_keyword"): return "Your New Tag"
   ```

## License
Open-source. Feel free to modify and adapt it to fit the specific needs of your device tree.
