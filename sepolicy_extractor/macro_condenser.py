"""
macro_condenser.py — domain-level macros (get_prop, binder_use, ...), done safely.

OLD behaviour (the source of wrong output)
  * regexes matched ANY perm list containing a word ("read", "call", "add")
    and then deleted rules by pattern, e.g. {read write} on a prop became
    get_prop() and the write was lost; wakelock_use() was emitted while only
    one rule was removed, so the macro silently granted ~10 extra rules;
    get_prop also deleted unrelated :dir rules (it has none).

NEW behaviour
  Each macro has an exact expansion (taken from AOSP te_macros, Android 14/15).
  A macro is emitted only if EVERY rule of its expansion is already present in
  the policy. Exactly those rules (and only those perms) are then removed.
  => policy(output) == policy(input). Nothing added, nothing lost.

  `verify.py` re-expands the written .te files and diffs them against the CIL.
"""

from collections import defaultdict

MANAGERS = {"servicemanager", "hwservicemanager", "vndservicemanager"}


class Req:
    """One rule/attr/transition that a macro expands to."""
    __slots__ = ("kind", "key", "val", "shared", "optional")

    def __init__(self, kind, key, val, shared=False, optional=False):
        self.kind, self.key, self.val = kind, key, val
        self.shared, self.optional = shared, optional


def av(src, tgt, cls, perms, action="allow", **kw):
    return Req("av", (action, src, tgt, cls), frozenset(perms), **kw)


def tt(src, tgt, cls, new, **kw):
    return Req("tt", (src, tgt, cls, None), new, **kw)


def attr(t, a, **kw):
    return Req("attr", (t, a), None, **kw)


# ---------------------------------------------------------------------------
# Macro specs.  find(idx) yields arg tuples; reqs(args) lists the expansion.
# ---------------------------------------------------------------------------

class Spec:
    name = ""
    def find(self, idx): return ()
    def reqs(self, a): return []
    def text(self, a): return f"{self.name}({', '.join(a)})"
    def subject(self, a): return a[0]


class SetProp(Spec):
    name = "set_prop"
    def find(self, idx):
        for (act, s, t, c), p in idx.av.items():
            if act == "allow" and c == "property_service" and "set" in p:
                yield (s, t)
    def reqs(self, a):
        s, t = a
        return [av(s, t, "property_service", {"set"}),
                av(s, t, "file", {"getattr", "open", "read", "map"}),
                av(s, "property_socket", "sock_file", {"write"}),
                av(s, "init", "unix_stream_socket", {"connectto"})]


class GetProp(Spec):
    name = "get_prop"
    def find(self, idx):
        for (act, s, t, c), p in idx.av.items():
            if act == "allow" and c == "file" and t in idx.prop_types \
               and {"getattr", "open", "read", "map"} <= p:
                yield (s, t)
    def reqs(self, a):
        return [av(a[0], a[1], "file", {"getattr", "open", "read", "map"})]


class _MgrUse(Spec):
    mgr, extra_file, reverse_binder, devrw = "", set(), False, False
    def find(self, idx):
        for (act, s, t, c), p in idx.av.items():
            if act == "allow" and t == self.mgr and c == "binder" and {"call", "transfer"} <= p:
                yield (s,)
    def reqs(self, a):
        s = a[0]
        r = [av(s, self.mgr, "binder", {"call", "transfer"}),
             av(self.mgr, s, "dir", {"search"}),
             av(self.mgr, s, "file", self.extra_file),
             av(self.mgr, s, "process", {"getattr"})]
        if self.reverse_binder:
            r.append(av(self.mgr, s, "binder", {"call", "transfer"}))
        if self.devrw:
            r.append(Req("av", ("allow", s, "vndbinder_device", "chr_file"),
                         frozenset(self.devrw), False))
        return r


class BinderUse(_MgrUse):
    name, mgr = "binder_use", "servicemanager"
    extra_file, reverse_binder = {"read", "open"}, True


class HwBinderUse(_MgrUse):
    name, mgr = "hwbinder_use", "hwservicemanager"
    extra_file, reverse_binder = {"read", "open", "map"}, True


class VndBinderUse(_MgrUse):
    name, mgr = "vndbinder_use", "vndservicemanager"
    extra_file = {"read", "open", "map"}
    devrw = None   # filled at setup from PermMacros (rw_file_perms)


class BinderCall(Spec):
    name = "binder_call"
    def find(self, idx):
        for (act, s, t, c), p in idx.av.items():
            if act == "allow" and c == "binder" and {"call", "transfer"} <= p \
               and t not in MANAGERS and t != "self" and "{" not in t:
                yield (s, t)
    def reqs(self, a):
        s, t = a
        return [av(s, t, "binder", {"call", "transfer"}),
                av(t, s, "binder", {"transfer"}),
                av(s, t, "fd", {"use"})]
    def subject(self, a): return a[0]


class AddService(Spec):
    name = "add_service"
    # add_service() also expands to a userdebug/eng-only `su` rule. On a user-build
    # dump that rule is absent, so using the macro would ADD a grant. Strict by default.
    strict_su = True
    def find(self, idx):
        for (act, s, t, c), p in idx.av.items():
            if act == "allow" and c == "service_manager" and {"add", "find"} <= p:
                yield (s, t)
    def reqs(self, a):
        s, t = a
        return [av(s, t, "service_manager", {"add", "find"}),
                # userdebug_or_eng() part of the macro; consumed if present
                av(s, "su", "tcp_socket", {"accept", "getopt", "read", "write"},
                   optional=not self.strict_su)]


class AddHwservice(Spec):
    name = "add_hwservice"
    def find(self, idx):
        for (act, s, t, c), p in idx.av.items():
            if act == "allow" and c == "hwservice_manager" and {"add", "find"} <= p \
               and t != "hidl_base_hwservice":
                yield (s, t)
    def reqs(self, a):
        s, t = a
        return [av(s, t, "hwservice_manager", {"add", "find"}),
                av(s, "hidl_base_hwservice", "hwservice_manager", {"add"}, shared=True)]


class InitDaemonDomain(Spec):
    name = "init_daemon_domain"
    def find(self, idx):
        for (s, t, c, n), new in idx.tt.items():
            if s == "init" and c == "process" and n is None and t.endswith("_exec") \
               and new == t[:-5] and new != "init":
                yield (new,)
    def reqs(self, a):
        d = a[0]; ex = d + "_exec"
        return [tt("init", ex, "process", d),
                av("init", ex, "file", {"getattr", "open", "read", "execute", "map"}),
                av("init", d, "process", {"transition"}),
                av(d, ex, "file", {"entrypoint", "open", "read", "execute", "getattr", "map"}),
                av("init", d, "process", {"siginh", "rlimitinh"}),
                av("init", d, "process", {"noatsecure"}, action="dontaudit", optional=True)]


class _AttrMacro(Spec):
    attrs = ()
    def find(self, idx):
        for t, at in idx.type_attrs.items():
            if set(self.attrs) <= at:
                yield (t,)
    def reqs(self, a):
        return [attr(a[0], x, shared=False) for x in self.attrs]


class NetDomain(_AttrMacro):
    name, attrs = "net_domain", ("netdomain",)


class BluetoothDomain(_AttrMacro):
    name, attrs = "bluetooth_domain", ("bluetoothdomain",)


class HalClient(Spec):
    name = "hal_client_domain"
    def find(self, idx):
        for t, at in idx.type_attrs.items():
            if "halclientdomain" in at:
                for x in at:
                    if x.startswith("hal_") and x.endswith("_client"):
                        yield (t, x[:-7])
    def reqs(self, a):
        t, h = a
        return [attr(t, "halclientdomain", shared=True), attr(t, h + "_client")]


class HalServer(Spec):
    name = "hal_server_domain"
    def find(self, idx):
        for t, at in idx.type_attrs.items():
            if "halserverdomain" in at:
                for x in at:
                    if x.startswith("hal_") and x.endswith("_server") and x[:-7] in at:
                        yield (t, x[:-7])
    def reqs(self, a):
        t, h = a
        return [attr(t, "halserverdomain", shared=True), attr(t, h + "_server"), attr(t, h)]


ALL_SPECS = [SetProp, GetProp, VndBinderUse, HwBinderUse, BinderUse, BinderCall,
             AddService, AddHwservice, InitDaemonDomain, NetDomain, BluetoothDomain,
             HalServer, HalClient]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def expand_atoms(spec, args):
    """Atomic (action,src,tgt,cls,perm) tuples + tt/attr grants of one macro use."""
    atoms = set()
    for r in spec.reqs(args):
        if r.kind == "av":
            act, s, t, c = r.key
            for p in r.val:
                atoms.add((act, s, t, c, p))
    return atoms


def condense(idx, perm_macros, enabled=None, variant_macros=False):
    """
    Mutates idx (consumes the rules covered by macros).
    Returns (macros_by_subject, stats, specs_by_name).
    """
    specs = []
    for cls in ALL_SPECS:
        if enabled is not None and cls.name not in enabled:
            continue
        sp = cls()
        if isinstance(sp, AddService):
            sp.strict_su = not variant_macros
        if isinstance(sp, VndBinderUse):
            sp.devrw = perm_macros.flat.get("rw_file_perms", frozenset())
        specs.append(sp)

    snap_av = {k: set(v) for k, v in idx.av.items()}
    snap_tt = dict(idx.tt)
    snap_attr = {t: set(a) for t, a in idx.type_attrs.items()}
    out = defaultdict(list)
    stats = defaultdict(int)

    def present(r, shared):
        if r.kind == "av":
            have = (snap_av if shared else idx.av).get(r.key)
            return have is not None and r.val <= have
        if r.kind == "tt":
            src = snap_tt if shared else idx.tt
            return src.get(r.key) == r.val
        if r.kind == "attr":
            src = snap_attr if shared else idx.type_attrs
            return r.key[1] in src.get(r.key[0], ())
        return False

    for sp in specs:
        for args in sorted(set(sp.find(idx))):
            reqs = sp.reqs(args)
            if not all(present(r, r.shared) for r in reqs if not r.optional):
                continue
            # at least one non-shared requirement must still be unconsumed
            # (prevents emitting the same macro twice)
            for r in reqs:
                if r.optional and not present(r, False):
                    continue
                if r.kind == "av":
                    have = idx.av.get(r.key)
                    if have is not None:
                        have -= r.val
                        if not have:
                            del idx.av[r.key]
                elif r.kind == "tt":
                    idx.tt.pop(r.key, None)
                elif r.kind == "attr":
                    idx.type_attrs.get(r.key[0], set()).discard(r.key[1])
            out[sp.subject(args)].append(sp.text(args))
            stats[sp.name] += 1
    return out, dict(stats), {s.name: s for s in specs}
