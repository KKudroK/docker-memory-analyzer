"""Scoped ledger of actual Volatility structure-member resolutions."""
from contextlib import contextmanager


@contextmanager
def kernel_members(context, ledger):
    from volatility3.framework.objects import StructType
    original = StructType.__getattr__
    seen = set()

    def traced(obj, name):
        value = original(obj, name)
        if obj._context is context and hasattr(value, 'vol'):
            parent, member = obj.vol, value.vol
            key = (parent.layer_name, parent.offset, parent.type_name, name)
            if key not in seen:
                seen.add(key)
                ledger.append({'source': 'kernel.memory', 'layer': parent.layer_name,
                               'structure': parent.type_name, 'field': name,
                               'base_address': hex(parent.offset), 'field_address': hex(member.offset),
                               'offset': hex(member.offset - parent.offset), 'size': member.size,
                               'type': member.type_name, 'read_status': 'member_resolved',
                               'note': 'Address resolved by loaded ISF; value/decoding errors are retained in the result'})
        return value

    StructType.__getattr__ = traced
    try:
        yield
    finally:
        StructType.__getattr__ = original
