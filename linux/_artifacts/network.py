"""Read Linux network-device primitives for detection and network inspection.
The helpers enumerate namespace interfaces and expose stable device attributes.
They do not infer container identity or render plugin output.
"""


def devices(reader, namespace):
    return reader.walk(namespace.dev_base_head, "net_device", "dev_list")


def link_kind(device, string, *, missing_error=None):
    if not device.has_member("rtnl_link_ops"):
        if missing_error is not None:
            raise missing_error
        return None
    return string(device.rtnl_link_ops.kind) if device.rtnl_link_ops else ""
