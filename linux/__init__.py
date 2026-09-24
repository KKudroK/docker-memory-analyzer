"""Add Docker v2 alongside the official Volatility Linux plugins."""

import pkgutil

# Keep official linux.pslist, linux.mountinfo, etc. importable with -p plugins.
__path__ = pkgutil.extend_path(__path__, __name__)
