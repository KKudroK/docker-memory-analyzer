"""Recover task credentials and capability evidence for container analyses.
Process, capability, and task views use these readers for IDs, capability sets,
user namespaces, and security state with explicit kernel-layout validation.
Raw bytes and unknown bits are preserved, and the reader never decides privilege.
"""

from volatility3.framework import exceptions, objects
from volatility3.framework.constants import linux

from . import core as artifact_core
from . import namespaces as namespace_readers

MAX_CAPABILITY_BYTES = 256
CAP_FIELDS = (
    "cap_inheritable",
    "cap_permitted",
    "cap_effective",
    "cap_bounding",
    "cap_ambient",
)
ID_FIELDS = ("uid", "euid", "suid", "fsuid", "gid", "egid", "sgid", "fsgid")
SAFETY_ITEMS = 65536


def namespace_inum(namespace):
    return namespace_readers.namespace_inum(
        namespace,
        member_reader=artifact_core.member,
        missing_error=artifact_core.UnsupportedLayout(
            "Neither namespace.ns.inum nor namespace.proc_inum exists"
        ),
    )


def capability_mask(value):
    """Read a capability mask after validating the concrete val/cap field layout.

    Select the val or cap field, validate signedness, width, and array length,
    then combine the values into a mask. Unknown layouts are never treated as zero.
    """
    fields = [name for name in ("val", "cap") if value.has_member(name)]
    if len(fields) != 1:
        raise artifact_core.Unsupported("Capability needs one val/cap member")
    name = fields[0]
    offset, template = value.vol.members[name]
    if offset < 0 or offset + template.size > value.vol.size:
        raise artifact_core.Unsupported("Capability exceeds its structure")

    def unsigned(t, sizes):
        """Check that the type is a supported unsigned integer, not a pointer.

        Inspect the object class, signedness, and width before accepting it.
        """
        return (
            issubclass(t.vol.object_class, objects.Integer)
            and not issubclass(t.vol.object_class, objects.Pointer)
            and t.size in sizes
            and not t.vol.data_format.signed
        )

    if issubclass(template.vol.object_class, objects.Array):
        if (
            name != "cap"
            or template.vol.count not in (1, 2)
            or not unsigned(template.vol.subtype, (4,))
        ):
            raise artifact_core.Unsupported("Unsupported capability array")
        return sum(int(word) << (32 * i) for i, word in enumerate(value.member(name)))
    if not unsigned(template, (8,) if name == "val" else (4, 8)):
        raise artifact_core.Unsupported("Unsupported capability integer")
    return int(value.member(name))


def _unsigned(value, width, cap, raw):
    if not isinstance(width, int) or not 1 <= width <= MAX_CAPABILITY_BYTES:
        raise artifact_core.UnsupportedLayout(
            "Invalid capability integer size or safety limit exceeded"
        )
    if not isinstance(value, objects.Integer) or isinstance(value, objects.Pointer):
        raise artifact_core.UnsupportedLayout(
            "Capability component is not a symbol-defined integer"
        )
    fmt = value.vol.data_format
    if value.vol.size != width or fmt.length != width or fmt.signed:
        raise artifact_core.UnsupportedLayout(
            f"Capability component must be an unsigned {width * 8}-bit integer"
        )
    if fmt.byteorder not in ("little", "big"):
        raise artifact_core.UnsupportedLayout("Unknown integer byte order")
    relative = value.vol.offset - cap.vol.offset
    if (
        value.vol.layer_name != cap.vol.layer_name
        or relative < 0
        or relative + width > len(raw)
    ):
        raise ValueError("Capability component lies outside its recorded structure")
    result = int(value)
    if not 0 <= result < (1 << (width * 8)):
        raise ValueError("Capability integer exceeds its unsigned storage width")

    if result != int.from_bytes(
        raw[relative : relative + width], fmt.byteorder, signed=False
    ):
        raise ValueError("Capability value disagrees with the preserved raw bytes")
    return result


def _read_mask(cap, raw):


    if isinstance(cap, objects.Pointer):
        raise artifact_core.UnsupportedLayout(
            "A capability pointer is not a stored capability mask"
        )
    if isinstance(cap, objects.Integer):
        width = cap.vol.size
        return _unsigned(cap, width, cap, raw), f"integer_u{width * 8}", width * 8
    has_val, has_cap = cap.has_member("val"), cap.has_member("cap")
    if has_val and has_cap:
        raise artifact_core.UnsupportedLayout(
            "Ambiguous capability structure contains both val and cap"
        )
    if has_val:
        value = cap.member("val")
        width = value.vol.size
        return _unsigned(value, width, cap, raw), f"val_u{width * 8}", width * 8
    if not has_cap:
        raise artifact_core.UnsupportedLayout(
            "Capability structure has neither val nor cap"
        )
    value = cap.member("cap")
    if isinstance(value, objects.Array):
        count = len(value)
        if not 1 <= count <= MAX_CAPABILITY_BYTES:
            raise artifact_core.UnsupportedLayout(
                "Capability cap array is empty or exceeds the safety limit"
            )
        width = value.vol.subtype.size
        if (
            not isinstance(width, int)
            or width < 1
            or count * width > MAX_CAPABILITY_BYTES
        ):
            raise artifact_core.UnsupportedLayout(
                "Invalid capability array element size or safety limit exceeded"
            )
        mask = 0
        for index, word in enumerate(value):
            mask |= _unsigned(word, width, cap, raw) << (width * 8 * index)
        return mask, f"cap_u{width * 8}_array_{count}", width * 8 * count
    width = value.vol.size
    return _unsigned(value, width, cap, raw), f"cap_u{width * 8}_scalar", width * 8


def _kernel_range(module, storage_bits=64):


    details = {}
    try:
        if not module.has_symbol("cap_last_cap"):
            return (
                None,
                None,
                artifact_core.observation(
                    "capability_kernel_range",
                    "not_present",
                    "cap_last_cap symbol is absent; kernel capability range is unknown",
                ),
            )
        if module.get_symbol("cap_last_cap").type is None:
            details = {"type_source": "linux_int_fallback", "object_type": "int"}
            try:
                integer_type = module.get_type("int")
            except exceptions.SymbolError as exc:
                raise artifact_core.UnsupportedLayout(
                    "Untyped cap_last_cap requires an available int type: "
                    + artifact_core.exception_detail(exc)
                ) from exc


            if (
                getattr(integer_type.vol, "object_class", None) is not objects.Integer
                or integer_type.size != 4
                or getattr(integer_type.vol, "data_format", None)
                != objects.DataFormatInfo(4, "little", True)
            ):
                raise artifact_core.UnsupportedLayout(
                    "Untyped cap_last_cap requires a signed 32-bit little-endian int type"
                )
            details["object_type"] = integer_type.vol.type_name


            value = module.object_from_symbol("cap_last_cap", object_type=integer_type)
        else:
            value = module.object_from_symbol("cap_last_cap")
        if not isinstance(value, objects.Integer):
            return (
                None,
                None,
                artifact_core.observation(
                    "capability_kernel_range",
                    "unsupported",
                    "cap_last_cap is not a symbol-defined integer",
                    **details,
                ),
            )
        last = int(value)
        if last < 0:
            return (
                None,
                None,
                artifact_core.observation(
                    "capability_kernel_range",
                    "inconsistent",
                    "cap_last_cap is negative",
                    value=last,
                    **details,
                ),
            )
        if last >= storage_bits:
            return (
                None,
                None,
                artifact_core.observation(
                    "capability_kernel_range",
                    "unsupported",
                    "cap_last_cap exceeds this capability storage width",
                    value=last,
                    storage_bits=storage_bits,
                    **details,
                ),
            )
        return (
            (1 << (last + 1)) - 1,
            last,
            artifact_core.observation(
                "capability_kernel_range",
                "ok",
                "Kernel capability range read from cap_last_cap",
                value=last,
                **details,
            ),
        )
    except artifact_core.UnsupportedLayout as exc:
        return (
            None,
            None,
            artifact_core.observation(
                "capability_kernel_range",
                "unsupported",
                artifact_core.exception_detail(exc),
                **details,
            ),
        )
    except exceptions.SymbolError as exc:
        return (
            None,
            None,
            artifact_core.observation(
                "capability_kernel_range",
                "not_present",
                f"cap_last_cap is unavailable: {exc}",
                **details,
            ),
        )
    except exceptions.InvalidAddressException as exc:
        return (
            None,
            None,
            artifact_core.observation(
                "capability_kernel_range",
                "read_error",
                f"Cannot read cap_last_cap: {artifact_core.exception_text(exc)}",
                **details,
            ),
        )
    except Exception as exc:


        return (
            None,
            None,
            artifact_core.observation(
                "capability_kernel_range",
                "read_error",
                f"Cannot read cap_last_cap: {artifact_core.exception_text(exc)}",
                **details,
            ),
        )


def _bit_labels(mask):
    return [f"CAP_BIT_{bit}" for bit in range(mask.bit_length()) if mask & (1 << bit)]


def decode_capability(context, module, cap):
    """Return text, byte evidence and feature observations for one cap set.

    ``decoded_mask`` is restricted to the kernel's valid range when known. With
    no usable ``cap_last_cap``, it retains every stored bit and never claims
    ``all``. ``unknown_bits`` concerns the name dictionary; it can overlap with
    ``out_of_range_bits``. The latter is null when the kernel range is unknown.
    Core layout/read errors propagate so callers can report the affected set.
    """
    size = cap.vol.size
    if not isinstance(size, int) or not 1 <= size <= MAX_CAPABILITY_BYTES:
        raise artifact_core.UnsupportedLayout("Unsupported capability structure size")
    raw = context.layers[cap.vol.layer_name].read(cap.vol.offset, size, pad=False)
    if len(raw) != size:
        raise ValueError("Short read of capability structure")
    try:
        raw_mask, layout, storage_bits = _read_mask(cap, raw)
    except Exception as exc:

        exc.capability_evidence = {
            "virtual_address": hex(int(cap.vol.offset)),
            "size": size,
            "type_name": getattr(cap.vol, "type_name", None),
            "bytes_hex": raw.hex(),
            "raw_mask": None,
            "decoded_mask": None,
            "names": None,
            "layout": None,
            "kernel_mask": None,
            "kernel_last_cap": None,
            "unknown_bits": None,
            "out_of_range_bits": None,
        }
        raise

    kernel_mask, last_cap, range_observation = _kernel_range(module, storage_bits)


    decoded_mask = raw_mask if kernel_mask is None else raw_mask & kernel_mask
    known_mask = (1 << len(linux.CAPABILITIES)) - 1
    unknown_bits = raw_mask & ~known_mask
    out_of_range = None if kernel_mask is None else raw_mask & ~kernel_mask
    names = [
        linux.CAPABILITIES[bit] if bit < len(linux.CAPABILITIES) else f"CAP_BIT_{bit}"
        for bit in range(decoded_mask.bit_length())
        if decoded_mask & (1 << bit)
    ]
    observations = [
        artifact_core.observation(
            "capability_layout",
            "ok",
            "Capability storage read and checked against raw bytes",
            layout=layout,
        ),
        range_observation,
    ]
    if unknown_bits:
        observations.append(
            artifact_core.observation(
                "capability_names",
                "unsupported",
                "Stored bits have no name in the installed capability dictionary",
                bits=_bit_labels(unknown_bits),
            )
        )
    if out_of_range:
        observations.append(
            artifact_core.observation(
                "capability_value",
                "inconsistent",
                "Stored bits exceed the kernel cap_last_cap range",
                bits=_bit_labels(out_of_range),
            )
        )
    text = ", ".join(names)

    if kernel_mask is not None and raw_mask == kernel_mask and not unknown_bits:
        text = "all"
    if out_of_range:
        suffix = "[out_of_range: " + ", ".join(_bit_labels(out_of_range)) + "]"
        text = (text + " " + suffix).lstrip()


    return {
        "text": text,
        "evidence": {
            "virtual_address": hex(int(cap.vol.offset)),
            "size": size,
            "storage_bits": storage_bits,
            "bytes_hex": raw.hex(),
            "decoded_mask": hex(decoded_mask),
            "names": names,
            "raw_mask": hex(raw_mask),
            "kernel_mask": None if kernel_mask is None else hex(kernel_mask),
            "kernel_last_cap": last_cap,
            "unknown_bits": hex(unknown_bits),
            "out_of_range_bits": None if out_of_range is None else hex(out_of_range),
            "layout": layout,
        },
        "observations": observations,
    }


def kernel_id(value, *, require_member_api=False):
    wrapped = (
        value.has_member("val")
        if require_member_api or hasattr(value, "has_member")
        else False
    )
    return int(value.val) if wrapped else int(value)


def anonymous_member(obj, name, depth=0):
    if obj.has_member(name):
        return obj.member(name)
    if depth >= 8:
        raise artifact_core.InconsistentData(
            "Anonymous member nesting exceeds safety limit"
        )
    for key in obj.vol.members:
        if key.startswith("unnamed_member_"):
            try:
                return anonymous_member(obj.member(key), name, depth + 1)
            except artifact_core.UnsupportedLayout:
                pass
    raise artifact_core.UnsupportedLayout(
        "Member " + name + " is absent from the symbols"
    )


def map_kernel_id(extents, value):


    matches = [
        e["namespace_first"] + value - e["kernel_first"]
        for e in extents
        if e["kernel_first"] <= value < e["kernel_first"] + e["count"]
    ]
    if len(matches) > 1:
        raise artifact_core.InconsistentData("Overlapping ID mappings")
    return matches[0] if matches else None


def read_id_map(idmap, module):
    count = int(anonymous_member(idmap, "nr_extents"))
    if not 0 <= count <= SAFETY_ITEMS:
        raise artifact_core.InconsistentData(
            "Invalid uid/gid map extent count or traversal safety limit exceeded"
        )
    if count == 0:
        return []
    source = anonymous_member(idmap, "extent")

    if count <= len(source):
        values = [source[i] for i in range(count)]
    else:
        pointer = anonymous_member(idmap, "forward")
        if not int(pointer):
            raise artifact_core.InconsistentData("Null large ID map pointer")
        size = module.get_type("uid_gid_extent").size
        values = [
            module.object(
                "uid_gid_extent", offset=int(pointer) + i * size, absolute=True
            )
            for i in range(count)
        ]
    result = []
    for extent in values:
        first, lower, size = (
            int(extent.first),
            int(extent.lower_first),
            int(extent.count),
        )
        if (
            first < 0
            or lower < 0
            or size <= 0
            or first + size > 0xFFFFFFFF
            or lower + size > 0xFFFFFFFF
        ):
            raise artifact_core.InconsistentData("Invalid uid/gid map extent")
        result.append({"namespace_first": first, "kernel_first": lower, "count": size})
    for field in ("namespace_first", "kernel_first"):
        ordered = sorted(result, key=lambda item: item[field])
        for index in range(1, len(ordered)):
            previous, current = ordered[index - 1], ordered[index]
            if previous[field] + previous["count"] > current[field]:
                raise artifact_core.InconsistentData("Overlapping uid/gid map extents")
    return result


class SecurityReader:
    def __init__(self, context, module):
        self.context, self.module = context, module
        self.observations = []
        self.compatibility = self.observations
        self.ns_cache = {}
        self.banner = artifact_core.capture(
            self.observations,
            "kernel.banner",
            lambda: str(
                module.object_from_symbol("linux_banner").cast(
                    "string", max_length=512, encoding="utf-8", errors="replace"
                )
            ).rstrip("\n"),
        )
        self.initial_ns = None
        self.initial_address = None
        try:
            if not module.has_symbol("init_user_ns"):
                raise artifact_core.UnsupportedLayout(
                    "init_user_ns symbol is absent; scope cannot be anchored"
                )
            self.initial_ns = module.object_from_symbol("init_user_ns")
            self.initial_address = int(self.initial_ns.vol.offset)
        except artifact_core.UnsupportedLayout as exc:
            self.observations.append(
                artifact_core.observation(
                    "user_namespace.initial",
                    "unsupported",
                    artifact_core.exception_detail(exc),
                )
            )
        except Exception as exc:
            self.observations.append(
                artifact_core.observation(
                    "user_namespace.initial",
                    "read_error",
                    artifact_core.exception_text(exc),
                )
            )

    def raw(self, obj):
        return {
            "virtual_address": hex(int(obj.vol.offset)),
            "size": obj.vol.size,
            "bytes_hex": self.context.layers[obj.vol.layer_name]
            .read(obj.vol.offset, obj.vol.size, pad=False)
            .hex(),
        }

    def user_namespace(self, start):
        address = int(start.vol.offset)
        if address in self.ns_cache:
            return self.ns_cache[address]
        observations = []
        result = {
            "scope": "unknown",
            "chain_leaf_to_initial": [],
            "initial_address": None,
            "initial_inum": None,
            "observations": observations,
        }
        if self.initial_address is not None:
            result["initial_address"] = hex(self.initial_address)
            result["initial_inum"] = artifact_core.capture(
                observations,
                "user_namespace.initial_inum",
                lambda: namespace_inum(self.initial_ns),
            )
        else:
            observations.append(
                artifact_core.observation(
                    "user_namespace.scope",
                    "unsupported",
                    "init_user_ns unavailable; root cannot be authenticated",
                )
            )
        current, seen, previous_level = start, set(), None
        chain_complete = False
        while current is not None:
            try:
                key = int(current.vol.offset)
                if key in seen or len(seen) >= 33:
                    raise artifact_core.InconsistentData(
                        "Invalid/oversized user namespace parent chain"
                    )
                seen.add(key)
                node = {
                    "address": hex(key),
                    "inum": None,
                    "level": None,
                    "owner_kernel_uid": None,
                    "group_kernel_gid": None,
                    "uid_map": None,
                    "gid_map": None,
                }

                result["chain_leaf_to_initial"].append(node)
                feature = "user_namespace." + hex(key)
                node["inum"] = artifact_core.capture(
                    observations,
                    feature + ".inum",
                    lambda current=current: namespace_inum(current),
                )
                for field, output in (
                    ("owner", "owner_kernel_uid"),
                    ("group", "group_kernel_gid"),
                ):
                    node[output] = artifact_core.capture(
                        observations,
                        feature + "." + field,
                        lambda field=field, current=current: kernel_id(
                            artifact_core.member(current, field)
                        ),
                    )
                for field in ("uid_map", "gid_map"):
                    node[field] = artifact_core.capture(
                        observations,
                        feature + "." + field,
                        lambda field=field, current=current: read_id_map(
                            artifact_core.member(current, field), self.module
                        ),
                    )
                level = int(artifact_core.member(current, "level"))
                node["level"] = level
                if not 0 <= level <= 32 or (
                    previous_level is not None and level != previous_level - 1
                ):
                    raise artifact_core.InconsistentData(
                        "Inconsistent user namespace levels"
                    )
                previous_level = level
                pointer = artifact_core.member(current, "parent")
                if not int(pointer):
                    if self.initial_address is not None and (
                        key != self.initial_address or level != 0
                    ):
                        raise artifact_core.InconsistentData(
                            "User namespace chain does not reach init_user_ns"
                        )
                    chain_complete = True
                    break
                current = pointer.dereference()
            except artifact_core.UnsupportedLayout as exc:
                observations.append(
                    artifact_core.observation(
                        "user_namespace.parent_chain",
                        "unsupported",
                        artifact_core.exception_detail(exc),
                    )
                )
                break
            except artifact_core.InconsistentData as exc:
                observations.append(
                    artifact_core.observation(
                        "user_namespace.parent_chain",
                        "inconsistent",
                        artifact_core.exception_detail(exc),
                    )
                )
                break
            except Exception as exc:
                observations.append(
                    artifact_core.observation(
                        "user_namespace.parent_chain",
                        "read_error",
                        artifact_core.exception_text(exc),
                    )
                )
                break
        if chain_complete and self.initial_address is not None:


            result["scope"] = (
                "initial_user_namespace"
                if address == self.initial_address
                else "descendant_user_namespace"
            )
            observations.append(
                artifact_core.observation(
                    "user_namespace.scope",
                    "ok",
                    "Parent and level chain reaches init_user_ns",
                )
            )
        if result["scope"] != "unknown" and all(
            x["status"] == "ok" for x in observations
        ):
            self.ns_cache[address] = result
        return result

    def credentials(self, cred):


        observations = []
        result = {
            "address": hex(int(cred.vol.offset)),
            "ids_kernel": {},
            "ids_in_user_namespace": {},
            "capability_evidence": {},
            "capabilities": {},
            "securebits": None,
            "lsm_policy": "not_evaluated",
            "observations": observations,
        }
        for name in ID_FIELDS:
            result["ids_kernel"][name] = artifact_core.capture(
                observations,
                "credentials." + name,
                lambda name=name: kernel_id(artifact_core.member(cred, name)),
            )
        result["securebits"] = artifact_core.capture(
            observations,
            "credentials.securebits",
            lambda: int(artifact_core.member(cred, "securebits")),
        )
        for name in CAP_FIELDS:
            result["capabilities"][name] = None
            result["capability_evidence"][name] = None
            field = "cap_bset" if name == "cap_bounding" else name
            try:
                if not cred.has_member(field):
                    observations.append(
                        artifact_core.observation(
                            name,
                            "not_present",
                            "Credential member "
                            + field
                            + " is absent from the symbols",
                        )
                    )
                    continue
                decoded = decode_capability(
                    self.context, self.module, cred.member(field)
                )
            except artifact_core.UnsupportedLayout as exc:
                result["capability_evidence"][name] = getattr(
                    exc, "capability_evidence", None
                )
                observations.append(
                    artifact_core.observation(
                        name, "unsupported", artifact_core.exception_detail(exc)
                    )
                )
            except ValueError as exc:
                result["capability_evidence"][name] = getattr(
                    exc, "capability_evidence", None
                )
                observations.append(
                    artifact_core.observation(
                        name, "inconsistent", artifact_core.exception_detail(exc)
                    )
                )
            except Exception as exc:
                result["capability_evidence"][name] = getattr(
                    exc, "capability_evidence", None
                )
                observations.append(
                    artifact_core.observation(
                        name, "read_error", artifact_core.exception_text(exc)
                    )
                )
            else:
                result["capabilities"][name] = decoded["text"]
                result["capability_evidence"][name] = decoded["evidence"]
                observations.append(
                    artifact_core.observation(
                        name,
                        "ok",
                        "Capability read from memory",
                        decoded["evidence"].get("layout"),
                    )
                )
                for item in decoded.get("observations", []):
                    observations.append(
                        {**item, "feature": item["feature"] + "." + name}
                    )
        return result

    def _array_values(self, source, count):
        if len(source) >= count:
            return [source[index] for index in range(count)]
        if (
            self.module is None
            or not hasattr(source, "vol")
            or not hasattr(source.vol, "subtype")
        ):
            raise artifact_core.UnsupportedLayout(
                "Flexible-array subtype metadata unavailable"
            )
        expanded = self.module.object(
            "array",
            offset=int(source.vol.offset),
            absolute=True,
            subtype=source.vol.subtype,
            count=count,
        )
        return list(expanded)

    def supplementary_groups(self, groups):
        count = int(artifact_core.member(groups, "ngroups"))
        if not 0 <= count <= SAFETY_ITEMS:
            raise artifact_core.InconsistentData(
                "Invalid supplementary group count or safety limit exceeded"
            )
        if count == 0:
            return [], "empty"
        if groups.has_member("gid"):
            return [
                kernel_id(x) for x in self._array_values(groups.gid, count)
            ], "group_info.gid"
        if groups.has_member("small_block") and groups.has_member("blocks"):
            small = groups.small_block
            if count <= len(small):
                return [
                    kernel_id(small[index]) for index in range(count)
                ], "group_info.small_block"
            if not hasattr(small, "vol") or not hasattr(small.vol, "subtype"):
                raise artifact_core.UnsupportedLayout(
                    "Legacy group element type unavailable"
                )
            subtype = small.vol.subtype
            item_size = int(subtype.size)
            layer = self.context.layers[self.module.layer_name]
            page_size = getattr(layer, "page_size", None)
            if page_size is None or item_size <= 0 or int(page_size) % item_size:
                raise artifact_core.UnsupportedLayout(
                    "Legacy group block page/element size unavailable"
                )
            per_block = int(page_size) // item_size
            needed = (count + per_block - 1) // per_block
            blocks = int(artifact_core.member(groups, "nblocks"))
            if not needed <= blocks <= SAFETY_ITEMS:
                raise artifact_core.InconsistentData(
                    "Legacy group block count cannot hold ngroups"
                )
            pointers = self._array_values(groups.blocks, needed)
            values = []
            for pointer in pointers:
                if not int(pointer):
                    raise artifact_core.InconsistentData(
                        "Null legacy supplementary group block"
                    )
                size = min(per_block, count - len(values))
                block = self.module.object(
                    "array",
                    offset=int(pointer),
                    absolute=True,
                    subtype=subtype,
                    count=size,
                )
                values.extend(kernel_id(value) for value in block)
            return values, "group_info.blocks"
        raise artifact_core.UnsupportedLayout(
            "Neither contiguous gid nor small_block/blocks layout exists"
        )

    def enrich_identity(self, result, cred):

        observations = result.setdefault("observations", [])
        result["user_namespace"] = {
            "scope": "unknown",
            "chain_leaf_to_initial": [],
            "observations": [],
        }
        scope = artifact_core.capture(
            observations,
            "credentials.user_namespace",
            lambda: self.user_namespace(
                artifact_core.dereference(
                    artifact_core.member(cred, "user_ns"), "user namespace"
                )
            ),
        )
        if scope is not None:
            result["user_namespace"] = scope
            observations.extend(scope["observations"])
        chain = result["user_namespace"]["chain_leaf_to_initial"]

        leaf = chain[0] if chain else {}
        for name, value in result["ids_kernel"].items():
            mappings = leaf.get("uid_map" if "uid" in name else "gid_map")
            result["ids_in_user_namespace"][name] = None
            if value is not None and mappings is not None:
                result["ids_in_user_namespace"][name] = artifact_core.capture(
                    observations,
                    "credentials.mapped_" + name,
                    lambda mappings=mappings, value=value: map_kernel_id(
                        mappings, value
                    ),
                )
        result["supplementary_gids_kernel"] = None
        result["supplementary_gids_in_user_namespace"] = None
        groups = artifact_core.capture(
            observations,
            "credentials.supplementary_groups",
            lambda: self.supplementary_groups(
                artifact_core.dereference(
                    artifact_core.member(cred, "group_info"), "group_info"
                )
            ),
        )
        if groups is not None:
            gids, layout = groups
            result["supplementary_gids_kernel"] = gids
            observations[-1]["layout"] = layout
            if leaf.get("gid_map") is not None:
                result["supplementary_gids_in_user_namespace"] = artifact_core.capture(
                    observations,
                    "credentials.mapped_groups",
                    lambda: [map_kernel_id(leaf["gid_map"], value) for value in gids],
                )

    def seccomp(self, task):

        observations = []
        result = {
            "mode": None,
            "mode_name": None,
            "filter_count": None,
            "declared_filter_count": None,
            "observed_filter_count": None,
            "filter_count_source": None,
            "filter_count_cross_checked": False,
            "filters": [],
            "chain_complete": False,
            "rules_evaluated": False,
            "no_new_privs": None,
            "atomic_flags": None,
            "observations": observations,
        }
        if task.has_member("no_new_privs"):
            result["no_new_privs"] = artifact_core.capture(
                observations,
                "no_new_privs",
                lambda: bool(int(task.no_new_privs)),
                "task.no_new_privs",
            )
        elif task.has_member("atomic_flags"):
            flags = artifact_core.capture(
                observations,
                "no_new_privs",
                lambda: int(task.atomic_flags),
                "task.atomic_flags/PFA_NO_NEW_PRIVS=0",
            )
            if flags is not None:
                result["no_new_privs"] = bool(flags & 1)
                raw = artifact_core.capture(
                    observations,
                    "no_new_privs.raw",
                    lambda: self.raw(task.atomic_flags),
                )
                result["atomic_flags"] = {
                    **(raw or {}),
                    "no_new_privs_bit": 0,
                    "rule_source": "Linux include/linux/sched.h PFA_NO_NEW_PRIVS bit 0 (verified through Linux 7.0); future semantics not inferred",
                }
        else:
            observations.append(
                artifact_core.observation(
                    "no_new_privs",
                    "unsupported",
                    "No supported no_new_privs storage member",
                )
            )
        seccomp = artifact_core.capture(
            observations,
            "seccomp.structure",
            lambda: artifact_core.member(task, "seccomp"),
        )
        if seccomp is None:
            return result

        def read_mode():
            value = int(artifact_core.member(seccomp, "mode"))
            if value not in (0, 1, 2):
                raise artifact_core.InconsistentData(
                    "Unknown seccomp mode value: " + str(value)
                )
            return value

        result["mode"] = artifact_core.capture(observations, "seccomp.mode", read_mode)
        if result["mode"] is not None:
            result["mode_name"] = ("disabled", "strict", "filter")[result["mode"]]

        def read_count():
            field = artifact_core.member(seccomp, "filter_count")
            value = (
                int(field.counter)
                if hasattr(field, "has_member") and field.has_member("counter")
                else int(field)
            )
            if not 0 <= value <= SAFETY_ITEMS:
                raise artifact_core.InconsistentData(
                    "Invalid seccomp filter count or safety limit exceeded"
                )
            return value

        declared = artifact_core.capture(
            observations, "seccomp.filter_count", read_count
        )
        result["declared_filter_count"] = declared
        if declared is not None:
            result["filter_count"], result["filter_count_source"] = (
                declared,
                "seccomp.filter_count",
            )

        def walk_filters():
            pointer, seen = artifact_core.member(seccomp, "filter"), set()
            while int(pointer):
                key = int(pointer)
                if key in seen or len(seen) >= 4096:
                    raise artifact_core.InconsistentData(
                        "Invalid/oversized seccomp filter chain"
                    )
                seen.add(key)
                item = pointer.dereference()
                record = {"address": hex(key), "program_address": None, "log": None}
                result["filters"].append(record)
                record["program_address"] = artifact_core.capture(
                    observations,
                    "seccomp.filter." + hex(key) + ".prog",
                    lambda item=item: hex(int(artifact_core.member(item, "prog"))),
                )
                record["log"] = artifact_core.capture(
                    observations,
                    "seccomp.filter." + hex(key) + ".log",
                    lambda item=item: bool(int(artifact_core.member(item, "log"))),
                )
                pointer = artifact_core.member(item, "prev")
            return len(seen)

        observed = artifact_core.capture(
            observations, "seccomp.filter_chain", walk_filters
        )

        result["observed_filter_count"] = len(result["filters"])
        result["chain_complete"] = observed is not None
        if observed is not None:
            if declared is None:

                result["filter_count"], result["filter_count_source"] = (
                    observed,
                    "complete_filter_chain",
                )
            else:
                result["filter_count_cross_checked"] = observed == declared
                if observed != declared:
                    observations.append(
                        artifact_core.observation(
                            "seccomp.filter_consistency",
                            "inconsistent",
                            "Declared count and observed filter chain disagree",
                        )
                    )
            if result["mode"] is not None and (
                (result["mode"] == 2 and observed == 0)
                or (result["mode"] != 2 and observed != 0)
            ):
                observations.append(
                    artifact_core.observation(
                        "seccomp.mode_consistency",
                        "inconsistent",
                        "Seccomp mode and observed filter chain disagree",
                    )
                )
        return result

    def resource_namespaces(self, task):
        observations = []
        result = {"observations": observations}
        proxy = artifact_core.capture(
            observations,
            "resource_namespaces.nsproxy",
            lambda: artifact_core.dereference(
                artifact_core.member(task, "nsproxy"), "nsproxy"
            ),
        )
        for name, field in (
            ("mount", "mnt_ns"),
            ("network", "net_ns"),
            ("ipc", "ipc_ns"),
            ("uts", "uts_ns"),
            ("cgroup", "cgroup_ns"),
        ):
            record = {
                "address": None,
                "inum": None,
                "owner_user_namespace_address": None,
                "owner_user_namespace_inum": None,
            }
            result[name] = record
            if proxy is None:
                continue
            namespace = artifact_core.capture(
                observations,
                "namespace." + name,
                lambda field=field: artifact_core.dereference(
                    artifact_core.member(proxy, field), field
                ),
            )
            if namespace is None:
                continue
            record["address"] = hex(int(namespace.vol.offset))
            record["inum"] = artifact_core.capture(
                observations,
                "namespace." + name + ".inum",
                lambda namespace=namespace: namespace_inum(namespace),
            )
            owner = artifact_core.capture(
                observations,
                "namespace." + name + ".owner",
                lambda namespace=namespace: artifact_core.dereference(
                    artifact_core.member(namespace, "user_ns"), "namespace owner"
                ),
            )
            if owner is not None:
                record["owner_user_namespace_address"] = hex(int(owner.vol.offset))
                record["owner_user_namespace_inum"] = artifact_core.capture(
                    observations,
                    "namespace." + name + ".owner_inum",
                    lambda owner=owner: namespace_inum(owner),
                )
        return result

    def mounts(self, task):


        observations = []
        result = {
            "namespace_address": None,
            "task_root_mount": None,
            "task_root_dentry": None,
            "mount_list_collected": False,
            "file_access_policy_evaluated": False,
            "observations": observations,
        }
        namespace = artifact_core.capture(
            observations,
            "mounts.namespace",
            lambda: artifact_core.dereference(
                artifact_core.member(
                    artifact_core.dereference(
                        artifact_core.member(task, "nsproxy"), "nsproxy"
                    ),
                    "mnt_ns",
                ),
                "mount namespace",
            ),
        )
        root = artifact_core.capture(
            observations,
            "mounts.task_root",
            lambda: artifact_core.member(
                artifact_core.dereference(artifact_core.member(task, "fs"), "fs"),
                "root",
            ),
        )
        if namespace is not None:
            result["namespace_address"] = hex(int(namespace.vol.offset))
        if root is not None:
            result["task_root_mount"] = artifact_core.capture(
                observations,
                "mounts.root_mnt",
                lambda: hex(int(artifact_core.member(root, "mnt"))),
            )
            result["task_root_dentry"] = artifact_core.capture(
                observations,
                "mounts.root_dentry",
                lambda: hex(int(artifact_core.member(root, "dentry"))),
            )
        return result
