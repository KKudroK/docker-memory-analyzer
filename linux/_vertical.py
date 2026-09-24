"""Render one collected record as a category/value block, like Docker --ps."""

from volatility3.framework import renderers
from volatility3.framework.renderers import format_hints


def _cell(value):
    if value is None or value == "":
        return "-"
    if isinstance(value, format_hints.Hex):
        return hex(value)
    if isinstance(value, format_hints.Bin):
        return bin(value)
    return str(value).replace("\n", "\\n").replace("\t", "\\t")


def vertical_grid(columns, records):
    """Convert the backend's flat rows without collecting them in memory."""

    def rows():
        started = False
        for level, values in records:
            if level != 0:
                raise ValueError("Vertical Docker output requires flat records")
            if len(values) != len(columns):
                raise ValueError("The record does not match its output columns")
            if started:
                yield 0, ("", "")
            started = True
            for (name, _type), value in zip(columns, values):
                yield 0, (name, _cell(value))

    return renderers.TreeGrid([("category", str), ("value", str)], rows())
