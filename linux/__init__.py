"""Expose Docker analyses alongside the official Volatility Linux plugins.
This package makes linux.docker.Docker and its shared helper modules discoverable.
It adds external analyses without replacing framework or core Linux plugin files.
"""

import pkgutil


__path__ = pkgutil.extend_path(__path__, __name__)
