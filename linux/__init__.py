"""Add Docker v2 alongside the official Volatility Linux plugins."""

from pkgutil import extend_path

# Keep official linux.pslist, linux.mountinfo, etc. importable with -p plugins.
__path__ = extend_path(__path__, __name__)
