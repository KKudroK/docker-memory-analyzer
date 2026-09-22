# SPDX-License-Identifier: MIT
# Includes readers by the container-mounts contributors (c) 2026.
"""Kernel access and bounded readers shared by Docker analysis backends.

No report schema or container attribution belongs here. Callers retain their
exception boundaries, so a failed read never silently becomes an empty value.
"""
from dataclasses import dataclass
from volatility3.framework import exceptions, objects
from volatility3.framework.objects import utility

READ_ERRORS = (
    AttributeError, IndexError, KeyError, TypeError, ValueError,
    exceptions.InvalidAddressException, exceptions.VolatilityException,
)


@dataclass(frozen=True)
class CStringErrors:
    invalid_bound: str = "null string pointer or invalid string bound"
    short_read: str = "short unpadded string read"
    empty: str = "empty kernel string"
    unterminated: str = "kernel string has no NUL terminator within its bound"


KERNEL_STRING_ERRORS = CStringErrors()
FILE_STRING_ERRORS = CStringErrors(
    "invalid string address/bound", "short string read", "empty string", "unterminated string",
)

class Unsupported(ValueError):
    """A layout cannot be interpreted without guessing."""


class Incomplete(ValueError):
    """An otherwise supported traversal could not be completed."""


class UnsupportedLayoutError(exceptions.VolatilityException):
    """A required type or field is absent from the supplied kernel symbols."""

    def __init__(self, feature, field, reason):
        self.feature, self.field = feature, field
        self.message = f'{feature}: {field}: {reason}'
        self.compatibility = {
            'feature': feature, 'status': 'unsupported',
            'field': field, 'message': self.message,
        }
        super().__init__(self.message)


def require_type(module, name, feature):
    try:
        template = module.get_type(name)
    except (exceptions.SymbolError, KeyError) as exc:
        raise UnsupportedLayoutError(feature, name, 'required symbol type is missing') from exc
    if template is None:
        raise UnsupportedLayoutError(feature, name, 'required symbol type is missing')
    return template


def require_fields(module, name, fields, feature):
    # 메모리를 읽기 전에 ISF 타입에 필수 멤버가 있는지 검사하고, 같은 타입 템플릿을 돌려준다.
    template = require_type(module, name, feature)
    for field in fields:
        if not template.has_member(field):
            raise UnsupportedLayoutError(feature, f'{name}.{field}', 'required symbol field is missing')
    return template


class UnsupportedLayout(ValueError):
    """The supplied symbol types do not describe a supported capability layout."""


def observation(feature, status, reason, layout=None, **details):
    value = {'feature': feature, 'status': status, 'reason': reason, **details}
    if layout is not None:
        value['layout'] = layout
    return value


class InconsistentData(ValueError):
    """Successfully read fields fail a structural consistency check."""


def member(obj, name):
    if not obj.has_member(name):
        raise UnsupportedLayout('Member ' + name + ' is absent from the symbols')
    return obj.member(name)


def capture(observations, feature, fn, layout=None):
    # 필드별 실패를 None과 상태로 남긴다. 실패를 0/빈 집합으로 바꾸거나 다른 성공값을 버리지 않는다.
    try:
        value = fn()
    except UnsupportedLayout as exc:
        observations.append(observation(feature, 'unsupported', str(exc), layout))
    except InconsistentData as exc:
        observations.append(observation(feature, 'inconsistent', str(exc), layout))
    except Exception as exc:
        observations.append(observation(feature, 'read_error', type(exc).__name__ + ': ' + str(exc), layout))
    else:
        observations.append(observation(feature, 'ok', 'Read from memory', layout))
        return value
    return None


def dereference(pointer, name):
    if not int(pointer):
        raise InconsistentData('Null ' + name + ' pointer')
    return pointer.dereference()


def _object_address(obj) -> int:
    """Return a pointer target or struct address without assuming its wrapper."""

    try:
        return int(obj)
    except (TypeError, ValueError):
        return int(obj.vol.offset)


def _object_readable(obj) -> bool:
    """Validate pointer targets and embedded structs with their own layer APIs.

    Pointer.is_readable() checks the pointed-to object.  Embedded StructType
    objects (for example mount.mnt and list heads) do not provide that method;
    their storage range must be checked in their layer instead.  Do not treat
    an absent pointer-only method as unreadable memory.
    """

    try:
        if obj is None:
            return False
        pointer_check = getattr(obj, "is_readable", None)
        if callable(pointer_check):
            return bool(obj) and bool(pointer_check())
        return bool(obj._context.layers[obj.vol.layer_name].is_valid(
            int(obj.vol.offset), int(obj.vol.size)
        ))
    except (
        AttributeError, KeyError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        return False


def _read_kernel_cstring(pointer, max_bytes: int = 4096, *, allow_empty: bool = False,
                         errors=KERNEL_STRING_ERRORS) -> str:
    """Read a bounded C string only when its NUL terminator was captured.

    pointer_to_string() may return a readable prefix without a terminator.
    Never use that prefix as a complete name or a container-identity source.
    Chunk reads are unpadded; on a boundary fault, retry single bytes only
    until the terminator or the actual missing byte, preserving short strings
    immediately before an unreadable page.
    """
    address = _object_address(pointer)
    if not address or max_bytes <= 0:
        raise ValueError(errors.invalid_bound)
    layer = pointer._context.layers[pointer.vol.native_layer_name]
    value = bytearray()
    while len(value) < max_bytes:
        count = min(64, max_bytes - len(value))
        try:
            block = layer.read(address + len(value), count, pad=False)
        except exceptions.InvalidAddressException:
            block = layer.read(address + len(value), 1, pad=False)
            count = 1
        if len(block) != count:
            raise ValueError(errors.short_read)
        end = block.find(b"\x00")
        if end >= 0:
            value.extend(block[:end])
            if not value and not allow_empty:
                raise ValueError(errors.empty)
            return bytes(value).decode("utf-8", errors="strict")
        value.extend(block)
    raise ValueError(errors.unterminated)


def read_file_cstring(pointer, max_bytes=4096, *, allow_empty=False):
    """Same bounded reader, retaining the file collector's diagnostic text."""
    return _read_kernel_cstring(pointer, max_bytes, allow_empty=allow_empty, errors=FILE_STRING_ERRORS)


def containing_object(owner, link, type_name, member):
    """Resolve an embedded link using its owner's symbol table and layers."""
    context = owner._context
    table = owner.vol.type_name.split("!", 1)[0]
    qualified = table + "!" + type_name
    displacement = context.symbol_space.get_type(qualified).relative_child_offset(member)
    address = _object_address(link) - displacement
    if address <= 0:
        raise ValueError("invalid containing object")
    return context.object(
        qualified, offset=address, layer_name=owner.vol.layer_name,
        native_layer_name=owner.vol.native_layer_name,
    )


class CollectionSession:
    """Access to one context/kernel; no global or cross-dump caches."""

    def __init__(self, context, kernel_name):
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]

    def obj(self, name, address):
        return self.kernel.object(name, offset=int(address), absolute=True)

    def symbol(self, name, typename):
        # A symbol can have an address without type metadata in a BTF ISF.
        return self.kernel.object(typename, offset=self.kernel.get_symbol(name).address, absolute=False)


def pointer_string(pointer, maximum=4096):
    """Compatibility reader: NULL is empty; stock string semantics retained."""
    return utility.pointer_to_string(pointer, maximum) if pointer else ''


def bounded(iterator, limit):
    for index, value in enumerate(iterator):
        if index >= limit:
            raise Incomplete('Traversal budget exceeded')
        yield value


def strict_string(layer, pointer, maximum=4096):
    """포인터에서 문자열을 읽는다. 길이와 NUL 종료를 확인한 뒤 UTF-8로 변환한다."""
    if not pointer:
        raise Incomplete("NULL string pointer")
    address, data = int(pointer), bytearray()
    # Require a real terminator. Some generic string helpers return a
    # readable prefix when a later page is absent; that is not a full name.
    while len(data) < maximum:
        cursor = address + len(data)
        size = min(32, maximum - len(data), 4096 - (cursor & 4095))
        block = layer.read(cursor, size, pad=False)
        end = block.find(b"\0")
        if end >= 0:
            data.extend(block[:end])
            return data.decode("utf-8", errors="strict")
        data.extend(block)
    raise Incomplete("Unterminated or over-limit string")


def strict_array_string(layer, array):
    """문자 배열의 타입·길이·NUL 종료를 확인한 뒤 UTF-8 문자열로 변환한다."""
    if not isinstance(array, objects.Array) or not 0 < array.vol.count <= 4096:
        raise Unsupported("Name is not a bounded character array")
    raw = layer.read(int(array.vol.offset), array.vol.count, pad=False)
    end = raw.find(b"\0")
    if end < 0:
        raise Incomplete("Unterminated character array")
    return raw[:end].decode("utf-8", errors="strict")
