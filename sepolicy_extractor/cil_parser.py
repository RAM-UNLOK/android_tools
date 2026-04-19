"""
cil_parser.py — Part 3 of the pipeline.

Parses raw CIL lines into structured per-domain .te content.

CIL format recap:
    Every statement is a single S-expression on one line:
        (keyword arg1 arg2 ...)

CIL → .te conversion table:
    (type X)                              → type X;
    (typeattribute X)                     → attribute X;
    (typealias X)                         → (collected, paired with typealiasactual)
    (typealiasactual ALIAS REAL)          → typealias REAL ALIAS;
    (typeattributeset ATTR (T1 T2 ...))   → typeattribute T1 ATTR;  (one per member, into each member's .te)
    (allow S T (CLASS (PERM...)))         → allow S T:CLASS { PERM... };
    (dontaudit S T (CLASS (PERM...)))     → dontaudit S T:CLASS { PERM... };
    (neverallow S T (CLASS (PERM...)))    → neverallow S T:CLASS { PERM... };
    (typetransition S E process D)        → type_transition S E:process D;
    (typetransition S E CLASS D NAME)     → type_transition S E:CLASS D:NAME;  (file name trans)
    (allowx S T (ioctl CLASS (RANGE...))) → allowxperm S T:CLASS ioctl { RANGE... };
    (expandtypeattribute (X...) true)     → expandtypeattribute X true;
    (genfscon FS PATH (u o TYPE s))       → genfscon FS PATH u:o:TYPE:s0
                                            (collected into genfs_contexts, not .te)

Output structure returned by parse_all_cil():
{
    "vendor": {
        "domains": {
            "hal_audio_default": {
                "type_decl":      ["type hal_audio_default;"],
                "attributes":     ["typeattribute hal_audio_default domain;", ...],
                "rules":          ["allow hal_audio_default ...", ...],
            },
            "init": {        ← _202404 suffix stripped
                ...
            },
            ...
        },
        "global_attributes": {
            # typeattribute declarations with no member assignments
            "domain": ["attribute domain;"],
            ...
        },
        "genfs_contexts": [
            "genfscon debugfs /mali0/ctx/kcpu_queues u:object_r:debugfs_mali_ctx_kcpu_queues:s0",
            ...
        ],
    },
    "odm": { ... },
    ...
}
"""

import re
from config import DEFAULT_PLAT_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_version(name: str, version: str) -> str:
    """
    Remove the platform version suffix from a type name.
    e.g. init_202404 → init,  servicemanager_202404 → servicemanager
    Leaves vendor-native names unchanged (hal_audio_default → hal_audio_default).
    """
    suffix = f"_{version}"
    if name.endswith(suffix):
        return name[: -len(suffix)]
    return name


def _sv(name: str, version: str) -> str:
    """Shorthand for _strip_version."""
    return _strip_version(name, version)


def _parse_perm_list(token: str) -> str:
    """
    Convert a CIL perm token to .te format.
    Single perm:  read         → read
    Multi perm:   (read write) → { read write }
    """
    token = token.strip()
    if token.startswith("(") and token.endswith(")"):
        perms = token[1:-1].split()
        if len(perms) == 1:
            return perms[0]
        return "{ " + " ".join(perms) + " }"
    return token


def _parse_genfscon(parts: list, version: str) -> str:
    """
    Convert a genfscon CIL statement into text genfs_contexts format.

    CIL:  (genfscon debugfs "/mali0/ctx" (u object_r some_type ((s0) (s0))))
    parts after keyword: ['debugfs', '"/mali0/ctx"', '(u', 'object_r', 'some_type', '((s0)', '(s0)))']

    Output: genfscon debugfs /mali0/ctx u:object_r:some_type:s0
    """
    if len(parts) < 3:
        return None

    fs_type = parts[0]
    path    = parts[1].strip('"')

    # Extract the security context — find the type name
    # The context block looks like: (u object_r TYPE_NAME ((s0) (s0)))
    # Join remaining parts and extract via regex
    remainder = " ".join(parts[2:])
    # Match: (u object_r <type> ...)
    m = re.search(r'\(\s*u\s+object_r\s+(\S+)', remainder)
    if not m:
        return None

    type_name = _sv(m.group(1), version)
    return f"genfscon {fs_type} {path} u:object_r:{type_name}:s0"


# ---------------------------------------------------------------------------
# Core CIL line tokeniser
# ---------------------------------------------------------------------------

def _tokenise(line: str) -> tuple:
    """
    Extract the keyword and raw argument string from a CIL S-expression line.

    Input:  "(allow init_202404 hal_audio_default_exec (file (read getattr)))"
    Output: ("allow", "init_202404 hal_audio_default_exec (file (read getattr))")

    Returns (None, None) if the line is not a valid CIL statement.
    """
    line = line.strip()
    if not line.startswith("(") or not line.endswith(")"):
        return None, None

    # Remove outer parens
    inner = line[1:-1].strip()
    # Split keyword from the rest
    space_idx = inner.find(" ")
    if space_idx == -1:
        keyword = inner
        rest = ""
    else:
        keyword = inner[:space_idx]
        rest = inner[space_idx + 1:].strip()

    return keyword, rest


def _split_top_level(s: str) -> list:
    """
    Split a string into top-level tokens, respecting nested parentheses.

    e.g. 'init_202404 hal_exec (file (read write))'
      → ['init_202404', 'hal_exec', '(file (read write))']
    """
    tokens = []
    depth = 0
    current = []

    for ch in s:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
            if depth == 0:
                tokens.append("".join(current).strip())
                current = []
        elif ch in (" ", "\t") and depth == 0:
            if current:
                tokens.append("".join(current).strip())
                current = []
        else:
            current.append(ch)

    if current:
        tokens.append("".join(current).strip())

    return [t for t in tokens if t]


# ---------------------------------------------------------------------------
# Statement converters
# ---------------------------------------------------------------------------

def _convert_av_rule(keyword: str, rest: str, version: str) -> tuple:
    """
    Convert allow / dontaudit / neverallow.

    CIL:  (allow SUBJECT TARGET (CLASS (PERM PERM)))
    .te:   allow SUBJECT TARGET:CLASS { PERM PERM };

    Returns (subject_name, te_line) or (None, None) on parse error.
    """
    tokens = _split_top_level(rest)
    if len(tokens) < 3:
        return None, None

    subject = _sv(tokens[0], version)
    target  = _sv(tokens[1], version)
    # tokens[2] is like "(file (read write))" or "(file (read))"
    class_block = tokens[2].strip()

    if not (class_block.startswith("(") and class_block.endswith(")")):
        return None, None

    class_inner = class_block[1:-1].strip()
    class_tokens = _split_top_level(class_inner)

    if len(class_tokens) < 2:
        return None, None

    obj_class = class_tokens[0]
    perms     = _parse_perm_list(class_tokens[1] if len(class_tokens) > 1 else class_tokens[0])

    te_line = f"{keyword} {subject} {target}:{obj_class} {perms};"
    return subject, te_line


def _convert_typetransition(rest: str, version: str) -> tuple:
    """
    Convert typetransition.

    Process transition:
      CIL: (typetransition INIT EXEC process DOMAIN)
      .te:  type_transition INIT EXEC:process DOMAIN;

    File name transition:
      CIL: (typetransition SOURCE PARENT dir NEW_TYPE "filename")
      .te:  type_transition SOURCE PARENT:dir NEW_TYPE "filename";

    Returns (subject, te_line).
    """
    tokens = _split_top_level(rest)
    if len(tokens) < 4:
        return None, None

    subject = _sv(tokens[0], version)
    exe     = _sv(tokens[1], version)
    cls     = tokens[2]
    new_type = _sv(tokens[3], version)

    if len(tokens) == 4:
        # process transition
        te_line = f"type_transition {subject} {exe}:{cls} {new_type};"
    else:
        # file name transition — 5th token is the filename in quotes
        filename = tokens[4]
        te_line = f"type_transition {subject} {exe}:{cls} {new_type} {filename};"

    return subject, te_line


def _convert_allowx(rest: str, version: str) -> tuple:
    """
    Convert allowx (extended permissions — typically ioctl ranges).

    CIL: (allowx SOURCE TARGET (ioctl CLASS (RANGE...)))
    .te:  allowxperm SOURCE TARGET:CLASS ioctl { RANGE... };

    Returns (subject, te_line).
    """
    tokens = _split_top_level(rest)
    if len(tokens) < 3:
        return None, None

    subject = _sv(tokens[0], version)
    target  = _sv(tokens[1], version)
    perm_block = tokens[2]

    if not (perm_block.startswith("(") and perm_block.endswith(")")):
        return None, None

    inner_tokens = _split_top_level(perm_block[1:-1])
    if len(inner_tokens) < 3:
        return None, None

    perm_type  = inner_tokens[0]  # usually "ioctl"
    obj_class  = inner_tokens[1]
    xperms     = _parse_perm_list(inner_tokens[2] if len(inner_tokens) > 2 else "")

    te_line = f"allowxperm {subject} {target}:{obj_class} {perm_type} {xperms};"
    return subject, te_line


def _convert_typeattributeset(rest: str, version: str) -> list:
    """
    Convert typeattributeset into per-member typeattribute lines.

    CIL: (typeattributeset ATTR (T1 T2 T3 ...))
    .te:  typeattribute T1 ATTR;
          typeattribute T2 ATTR;
          ...

    Complex set expressions like:
      (typeattributeset base_X (and (appdomain) (not (shell))))
    are skipped — they use CIL boolean algebra that has no direct .te equivalent
    and only appear in auto-generated base_typeattr_N intermediate attributes.

    Returns list of (member_name, te_line) tuples.
    """
    tokens = _split_top_level(rest)
    if len(tokens) < 2:
        return []

    attr = _sv(tokens[0], version)
    members_block = tokens[1]

    # Detect CIL set expressions (and/or/not/xor) — skip these entirely
    # They look like: (and (appdomain) (not (shell)))
    if members_block.startswith("("):
        inner = members_block[1:-1].strip()
        first_token = inner.split()[0] if inner.split() else ""
        if first_token in ("and", "or", "not", "xor"):
            return []  # skip complex boolean set expressions

        # Plain list of type names: (T1 T2 T3)
        members_raw = inner.split()
    else:
        # Single bare type name
        members_raw = [members_block]

    result = []
    for m in members_raw:
        # Skip anything that still has parens (nested expressions we missed)
        if "(" in m or ")" in m:
            continue
        member = _sv(m, version)
        te_line = f"typeattribute {member} {attr};"
        result.append((member, te_line))

    return result


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_partition_cil(cil_lines: list, version: str, partition_name: str) -> dict:
    """
    Parse all CIL lines for one partition.

    Returns:
    {
        "domains": {
            "domain_name": {
                "type_decl":  [...],
                "attributes": [...],
                "rules":      [...],
            }
        },
        "global_attributes": { "attr_name": ["attribute attr_name;"] },
        "genfs_contexts": [...],
        "parse_errors": [...]
    }
    """

    domains          = {}   # domain_name → { type_decl, attributes, rules }
    global_attrs     = {}   # attribute name → declaration line
    genfs_contexts   = []
    parse_errors     = []
    pending_aliases  = {}   # alias_name → None (waiting for typealiasactual)

    def get_domain(name: str) -> dict:
        if name not in domains:
            domains[name] = {
                "type_decl":  [],
                "attributes": [],
                "rules":      [],
            }
        return domains[name]

    total = len(cil_lines)
    dots  = max(1, total // 20)  # progress every 5%

    print(f"  [parse] {partition_name}: processing {total} CIL lines...")

    for i, raw_line in enumerate(cil_lines):
        if i % dots == 0:
            pct = int(i / total * 100)
            print(f"  [parse] {pct:3d}% ({i}/{total})", end="\r")

        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue

        keyword, rest = _tokenise(line)
        if keyword is None:
            continue

        # ---- type declaration ----
        if keyword == "type":
            type_name = _sv(rest.strip(), version)
            get_domain(type_name)["type_decl"].append(f"type {type_name};")

        # ---- attribute declaration ----
        elif keyword == "typeattribute":
            attr_name = _sv(rest.strip(), version)
            global_attrs[attr_name] = f"attribute {attr_name};"

        # ---- typealias (just the name declaration, pair with typealiasactual) ----
        elif keyword == "typealias":
            alias_name = rest.strip()
            pending_aliases[alias_name] = None

        # ---- typealiasactual pairs with typealias ----
        elif keyword == "typealiasactual":
            tokens = _split_top_level(rest)
            if len(tokens) >= 2:
                alias_name = _sv(tokens[0], version)
                real_name  = _sv(tokens[1], version)
                te_line    = f"typealias {real_name} {alias_name};"
                get_domain(real_name)["type_decl"].append(te_line)

        # ---- typeattributeset → membership lines per member ----
        elif keyword == "typeattributeset":
            memberships = _convert_typeattributeset(rest, version)
            for (member, te_line) in memberships:
                get_domain(member)["attributes"].append(te_line)

        # ---- allow / dontaudit / neverallow ----
        elif keyword in ("allow", "dontaudit", "neverallow"):
            subject, te_line = _convert_av_rule(keyword, rest, version)
            if subject:
                get_domain(subject)["rules"].append(te_line)
            else:
                parse_errors.append(f"[{keyword}] parse fail: {line[:80]}")

        # ---- typetransition ----
        elif keyword == "typetransition":
            subject, te_line = _convert_typetransition(rest, version)
            if subject:
                get_domain(subject)["rules"].append(te_line)
            else:
                parse_errors.append(f"[typetransition] parse fail: {line[:80]}")

        # ---- allowx (extended perms) ----
        elif keyword == "allowx":
            subject, te_line = _convert_allowx(rest, version)
            if subject:
                get_domain(subject)["rules"].append(te_line)
            else:
                parse_errors.append(f"[allowx] parse fail: {line[:80]}")

        # ---- genfscon → goes to genfs_contexts ----
        elif keyword == "genfscon":
            parts = _split_top_level(rest)
            result = _parse_genfscon(parts, version)
            if result:
                genfs_contexts.append(result)
            else:
                parse_errors.append(f"[genfscon] parse fail: {line[:80]}")

        # ---- expandtypeattribute ----
        elif keyword == "expandtypeattribute":
            tokens = _split_top_level(rest)
            if len(tokens) >= 2:
                # (expandtypeattribute (T1 T2) true)
                type_block = tokens[0]
                value      = tokens[1]
                if type_block.startswith("(") and type_block.endswith(")"):
                    type_list = type_block[1:-1].split()
                else:
                    type_list = [type_block]
                for t in type_list:
                    tname = _sv(t, version)
                    get_domain(tname)["rules"].append(
                        f"expandtypeattribute {tname} {value};"
                    )

        # ---- roletype — skip, not needed in .te output ----
        elif keyword == "roletype":
            pass

        # ---- anything else we don't handle yet ----
        else:
            pass  # silently skip unknown keywords

    print(f"  [parse] 100% ({total}/{total}) — done.          ")

    return {
        "domains":           domains,
        "global_attributes": global_attrs,
        "genfs_contexts":    genfs_contexts,
        "parse_errors":      parse_errors,
    }


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def parse_all_cil(data: dict) -> dict:
    """
    Parse CIL for all partitions.

    Parameters
    ----------
    data : dict
        Output from reader.read_staged()

    Returns
    -------
    dict  {partition_name: parse_result, ...}
    """
    version = data.get("plat_version") or DEFAULT_PLAT_VERSION
    print(f"\n[CIL] Using platform version suffix: _{version}")

    results = {}

    for pname, pdata in data["partitions"].items():
        cil_lines = pdata.get("cil_lines", [])
        if not cil_lines:
            print(f"\n[CIL] Skipping {pname} — no CIL lines")
            continue

        print(f"\n[CIL] Parsing partition: {pname}")
        result = parse_partition_cil(cil_lines, version, pname)

        domain_count  = len(result["domains"])
        genfs_count   = len(result["genfs_contexts"])
        error_count   = len(result["parse_errors"])
        attr_count    = len(result["global_attributes"])

        print(f"  [done] domains={domain_count}  attributes={attr_count}  "
              f"genfscon={genfs_count}  errors={error_count}")

        if result["parse_errors"]:
            print(f"  [warn] First 5 parse errors:")
            for e in result["parse_errors"][:5]:
                print(f"         {e}")

        results[pname] = result

    return results
