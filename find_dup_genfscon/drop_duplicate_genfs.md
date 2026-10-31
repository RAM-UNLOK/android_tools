chmod +x drop_duplicate_genfs.py

# Default: writes genfs_contexts.dedup
./drop_duplicate_genfs.py genfs_contexts plat/genfs_contexts vendor/genfs_contexts

# Explicit output + see what got dropped and why
./drop_duplicate_genfs.py genfs_contexts plat/genfs_contexts vendor/genfs_contexts \
    -o genfs_contexts.clean --diff

# Only remove entries that are 100% identical (fs+path+context all equal)
./drop_duplicate_genfs.py genfs_contexts plat/genfs_contexts vendor/genfs_contexts \
    --by-context
