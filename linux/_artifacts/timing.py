# SPDX-License-Identifier: MIT
"""Kernel boot/task start time reads; callers own caches, provenance and formatting."""
from dataclasses import dataclass
from volatility3.framework import constants, objects
from .core import Unsupported


@dataclass(frozen=True)
class BootTime:
    nanoseconds: int
    symbol: str
    layout: str
    keeper: object


def read_kernel_boot(session):
    for symbol_name in ("timekeeper_data", "tk_core", "tk_core_mono", "timekeeper"):
        if not session.kernel.has_symbol(symbol_name):
            continue
        if symbol_name == "timekeeper" and session.kernel.has_type("timekeeper"):
            type_name = "timekeeper"
        elif session.kernel.has_type("tk_data") and session.kernel.get_type("tk_data").has_member("timekeeper"):
            type_name = "tk_data"
        else:
            candidates = []
            table = session.context.symbol_space[session.kernel.symbol_table_name]
            for candidate_name in table.types:
                if candidate_name == "timekeeper":
                    continue
                template = session.kernel.get_type(candidate_name)
                if not template.has_member("timekeeper"):
                    continue
                child = template.child_template("timekeeper")
                if child.vol.type_name.split(constants.BANG)[-1] == "timekeeper":
                    candidates.append(candidate_name)
            if len(candidates) != 1:
                raise Unsupported("No unique tk_core timekeeper layout")
            type_name = candidates[0]
        container = session.symbol(symbol_name, type_name)
        keeper = container if type_name == "timekeeper" else container.timekeeper
        if not keeper.has_member("offs_real") or not keeper.has_member("offs_boot"):
            raise Unsupported("Timekeeper has no boot offsets")

        def offset_ns(field):
            value = keeper.member(field)
            if value.has_member("tv64"):
                value = value.tv64
            if not issubclass(type(value), objects.Integer) or value.vol.size != 8:
                raise Unsupported("Unsupported timekeeper offset: " + field)
            return int(value)

        boot = offset_ns("offs_real") - offset_ns("offs_boot")
        if boot <= 0:
            raise Unsupported("Invalid kernel boot time")
        return BootTime(boot, symbol_name, type_name, keeper)
    raise Unsupported("No supported timekeeper symbol")


def read_process_start_ns(task, boot_ns):
    for field in ("start_boottime", "real_start_time", "start_time"):
        if not task.has_member(field):
            continue
        value = task.member(field)
        if value.has_member("tv_sec") and value.has_member("tv_nsec"):
            start_ns = int(value.tv_sec) * 1000000000 + int(value.tv_nsec)
        elif issubclass(type(value), objects.Integer) and value.vol.size == 8:
            start_ns = int(value)
        else:
            raise Unsupported("Unsupported process start field: " + field)
        if start_ns < 0:
            raise Unsupported("Negative process start time")
        return boot_ns + start_ns
    raise Unsupported("No supported process start field")
