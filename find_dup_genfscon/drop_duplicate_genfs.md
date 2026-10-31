chmod +x dedup_contexts.py

# 1) genfs_contexts
./dedup_contexts.py genfs_contexts \
    plat/genfs_contexts vendor/genfs_contexts \
    -o genfs_contexts.dedup --diff

# 2) file_contexts (same logic, different parser)
./dedup_contexts.py file_contexts \
    plat_file_contexts vendor_file_contexts \
    -o file_contexts.dedup --diff

# Force a type if filenames are unconventional:
./dedup_contexts.py my_fc_primary.txt other1.txt --type file_contexts