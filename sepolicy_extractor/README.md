# sepolicy_extract

Rebuild SELinux `.te` / `*_contexts` source from a stock Android firmware dump.

```
python3 main.py /path/to/dump [--out /path/to/out]
python3 main.py /path/to/dump --global-macros ~/aosp/system/sepolicy/public/global_macros \
                              --te-macros     ~/aosp/system/sepolicy/public/te_macros
```

| flag | meaning |
|---|---|
| `--global-macros PATH` | use the perm macros (`rx_file_perms`...) from **your** tree instead of the built-in A14/15 set |
| `--te-macros PATH` | only emit domain macros (`get_prop`, `binder_use`...) / `*_prop()` macros that your tree defines |
| `--no-perm-macros` | write explicit permission lists, no `*_perms` macros at all |
| `--no-domain-macros` | no `get_prop/set_prop/binder_use/...` |
| `--variant-macros` | allow `add_service()` on user-build dumps (adds a userdebug-only `su` rule, so not byte-exact) |
| `--keep-tmp` | keep the staging dir |

## Correctness model

**The output must grant exactly what the stock CIL grants - no more, no less.**

* A permission macro is used only if *every* perm it expands to is in the original rule.
* A domain macro is used only if *its whole expansion* is already in the policy; only those rules are removed.
* Every perm compression is re-expanded and asserted equal to its input.
* After writing, `verify.py` re-reads all `.te` files, expands every macro, and diffs against the CIL:
  `missing` = would break the device, `over-granted` = would trip `neverallow`.
  Exit code is 2 if either is non-zero.

## Pipeline

1. `stage.py` copy policy files from the dump into a tmp dir
2. `reader.py` load into memory (`#line` stripping for property_contexts)
3. `cil_parser.py` real S-expression parser -> structured model
4. `contexts_writer.py` `*_contexts` (aligned/sorted/categorised where order is irrelevant; verbatim otherwise)
5. `writer.py` + `perm_macros.py` + `macro_condenser.py` merged index -> `.te`
6. `verify.py` semantic equivalence check
