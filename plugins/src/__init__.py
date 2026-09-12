"""Analysis modules, physically grouped by feature.

Keep the established ``src.memory`` / ``src.pipeline`` import API while placing
implementation files in feature directories. These are search directories, not
alternative subpackage APIs: import ``src.memory``, not ``src.core.memory``.
"""
from pathlib import Path

_source_root = Path(__file__).resolve().parent
__path__.extend(str(_source_root / name) for name in (
    'core', 'runtime', 'artifacts', 'reports', 'symbol_tools',
))
