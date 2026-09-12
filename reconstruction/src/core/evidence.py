"""Loss-aware result serialization and diagnostics shared by both entry points."""
import datetime
import hashlib
import json
import re
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECRET = re.compile(r'(secret|password|passwd|token|credential|api.?key|private.?key|access.?key)', re.I)


def redact(value, key=''):
    if SECRET.search(key) and value is not None:
        return '<redacted>'
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact(v, key) for v in value]
    if isinstance(value, bytes):
        # Raw opaque payloads can contain secrets. Preserve identity and length.
        return {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                'content': 'omitted_from_user_output'}
    if isinstance(value, str):
        def mask_assignment(match):
            return match.group(1) + '=<redacted>' if SECRET.search(match.group(1)) else match.group(0)
        # Environment entries may contain spaces, quotes, or additional '='.
        # Consume through the next assignment or record boundary, not whitespace.
        value = re.sub(r'([A-Za-z_][A-Za-z0-9_]*)=([^\x00\r\n]*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|[\x00\r\n]|$)', mask_assignment, value)
    return value


def default(value):
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    raise TypeError(f'Unserializable evidence: {type(value).__name__}')


def save_json(value, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(redact(value), stream, ensure_ascii=False, indent=2, default=default)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def error(stage, exc, **context):
    return {'stage': stage, 'kind': type(exc).__name__, 'message': str(exc), **context}


def source_manifest():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((ROOT / 'src').rglob('*.py'))}
