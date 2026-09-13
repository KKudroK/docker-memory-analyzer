"""Read supported kernel capability layouts without discarding unknown bits."""

# 자체 구조 판독기다. 공식 Capabilities._decode_cap은 호출하지 않으며,
# Volatility의 Integer/Array 객체와 linux.CAPABILITIES 이름 목록만 재사용한다.
from volatility3.framework import exceptions, objects
from volatility3.framework.constants import linux


class UnsupportedLayout(ValueError):
    """The supplied symbol types do not describe a supported capability layout."""


def _observation(feature, status, reason, **details):
    return {'feature': feature, 'status': status, 'reason': reason, **details}


def _unsigned(value, width, cap, raw):
    if not isinstance(value, objects.Integer):
        raise UnsupportedLayout('Capability component is not a symbol-defined integer')
    fmt = value.vol.data_format
    if value.vol.size != width or fmt.length != width or fmt.signed:
        raise UnsupportedLayout(f'Capability component must be an unsigned {width * 8}-bit integer')
    if fmt.byteorder not in ('little', 'big'):
        raise UnsupportedLayout('Unknown integer byte order')
    relative = value.vol.offset - cap.vol.offset
    if value.vol.layer_name != cap.vol.layer_name or relative < 0 or relative + width > len(raw):
        raise ValueError('Capability component lies outside its recorded structure')
    result = int(value)
    if not 0 <= result < (1 << (width * 8)):
        raise ValueError('Capability integer exceeds its unsigned storage width')
    # 심볼 객체가 해석한 값과 보고서에 보존할 바이트가 같은 위치·값을 가리키는지 확인한다.
    if result != int.from_bytes(raw[relative:relative + width], fmt.byteorder, signed=False):
        raise ValueError('Capability value disagrees with the preserved raw bytes')
    return result


def _read_mask(cap, raw):
    has_val, has_cap = cap.has_member('val'), cap.has_member('cap')
    if has_val and has_cap:
        raise UnsupportedLayout('Ambiguous capability structure contains both val and cap')
    if has_val:
        return _unsigned(cap.member('val'), 8, cap, raw), 'val_u64'
    if not has_cap:
        raise UnsupportedLayout('Capability structure has neither val nor cap')
    value = cap.member('cap')
    if isinstance(value, objects.Array):
        count = len(value)
        if count not in (1, 2):
            raise UnsupportedLayout('Capability cap array must contain one or two u32 words')
        mask = 0
        for index, word in enumerate(value):
            # cap[0]은 하위 32비트다. 각 원소의 바이트 순서 해석은 _unsigned에서 끝난다.
            mask |= _unsigned(word, 4, cap, raw) << (32 * index)
        return mask, f'cap_u32_array_{count}'
    return _unsigned(value, 4, cap, raw), 'cap_u32_scalar'


def _kernel_range(module):
    try:
        if not module.has_symbol('cap_last_cap'):
            return None, None, _observation(
                'capability_kernel_range', 'not_present',
                'cap_last_cap symbol is absent; kernel capability range is unknown')
        value = module.object_from_symbol('cap_last_cap')
        if not isinstance(value, objects.Integer):
            return None, None, _observation(
                'capability_kernel_range', 'unsupported',
                'cap_last_cap is not a symbol-defined integer')
        last = int(value)
        if last < 0:
            return None, None, _observation(
                'capability_kernel_range', 'inconsistent', 'cap_last_cap is negative', value=last)
        if last > 63:
            return None, None, _observation(
                'capability_kernel_range', 'unsupported',
                'cap_last_cap exceeds the supported 64-bit capability representation', value=last)
        return (1 << (last + 1)) - 1, last, _observation(
            'capability_kernel_range', 'ok', 'Kernel capability range read from cap_last_cap', value=last)
    except exceptions.SymbolError as exc:
        return None, None, _observation(
            'capability_kernel_range', 'not_present', f'cap_last_cap is unavailable: {exc}')
    except exceptions.InvalidAddressException as exc:
        return None, None, _observation(
            'capability_kernel_range', 'read_error', f'Cannot read cap_last_cap: {exc}')


def _bit_labels(mask):
    return [f'CAP_BIT_{bit}' for bit in range(mask.bit_length()) if mask & (1 << bit)]


def decode_capability(context, module, cap):
    """Return text, byte evidence and feature observations for one cap set.

    ``decoded_mask`` is restricted to the kernel's valid range when known. With
    no usable ``cap_last_cap``, it retains every stored bit and never claims
    ``all``. ``unknown_bits`` concerns the name dictionary; it can overlap with
    ``out_of_range_bits``. The latter is null when the kernel range is unknown.
    Core layout/read errors propagate so callers can report the affected set.
    """
    size = cap.vol.size
    if not isinstance(size, int) or not 1 <= size <= 64:
        raise UnsupportedLayout('Unsupported capability structure size')
    raw = context.layers[cap.vol.layer_name].read(cap.vol.offset, size, pad=False)
    if len(raw) != size:
        raise ValueError('Short read of capability structure')
    raw_mask, layout = _read_mask(cap, raw)
    kernel_mask, last_cap, range_observation = _kernel_range(module)
    # 표시용 decoded_mask와 원래 저장된 raw_mask를 분리한다. 커널 범위 밖 비트나
    # 설치된 이름 목록에 없는 비트도 JSON에서 사라지지 않게 보존한다.
    decoded_mask = raw_mask if kernel_mask is None else raw_mask & kernel_mask
    known_mask = (1 << len(linux.CAPABILITIES)) - 1
    unknown_bits = raw_mask & ~known_mask
    out_of_range = None if kernel_mask is None else raw_mask & ~kernel_mask
    names = [
        linux.CAPABILITIES[bit] if bit < len(linux.CAPABILITIES) else f'CAP_BIT_{bit}'
        for bit in range(decoded_mask.bit_length()) if decoded_mask & (1 << bit)
    ]
    observations = [
        _observation('capability_layout', 'ok', 'Capability storage read and checked against raw bytes', layout=layout),
        range_observation,
    ]
    if unknown_bits:
        observations.append(_observation(
            'capability_names', 'unsupported', 'Stored bits have no name in the installed capability dictionary',
            bits=_bit_labels(unknown_bits)))
    if out_of_range:
        observations.append(_observation(
            'capability_value', 'inconsistent', 'Stored bits exceed the kernel cap_last_cap range',
            bits=_bit_labels(out_of_range)))
    text = ', '.join(names)
    # all은 확인된 커널 capability 범위의 모든 비트라는 뜻이며 호스트 접근 허용 판정이 아니다.
    if kernel_mask is not None and raw_mask == kernel_mask and not unknown_bits:
        text = 'all'
    if out_of_range:
        suffix = '[out_of_range: ' + ', '.join(_bit_labels(out_of_range)) + ']'
        text = (text + ' ' + suffix).lstrip()
    # text는 표시용, evidence는 재검증용 원시 값, observations는 해석의 지원·일관성 상태다.
    # 호출자는 빈 text(읽힌 권한 없음)와 판독 예외(읽지 못함)를 별도로 처리한다.
    return {
        'text': text,
        'evidence': {
            'virtual_address': hex(int(cap.vol.offset)), 'size': size,
            'bytes_hex': raw.hex(), 'decoded_mask': hex(decoded_mask), 'names': names,
            'raw_mask': hex(raw_mask), 'kernel_mask': None if kernel_mask is None else hex(kernel_mask),
            'kernel_last_cap': last_cap, 'unknown_bits': hex(unknown_bits),
            'out_of_range_bits': None if out_of_range is None else hex(out_of_range), 'layout': layout,
        },
        'observations': observations,
    }
