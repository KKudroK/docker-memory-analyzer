"""Evidence-first summaries and compact artifact/provenance reports."""
import unicodedata
from .evidence import redact

TECHNICAL = {'confidence', 'dockerd_candidates', 'containerd_candidates',
             'containerd_image_candidates', 'shim_candidates',
             'selected_allocation_status', 'decision_factors', 'field_reads', 'field_sources',
             'source_hashes', 'layout_profile', 'state_conflicts', 'candidate_states'}


def clean(value):
    if value is None:
        return '(unavailable)'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if value == '':
        return '(empty)'
    return ''.join(c if c.isprintable() or c in '\n\t' else f'\\x{ord(c):02x}' for c in str(value))


def width(text):
    return sum(2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in text)


def folded(text, limit):
    for line in text.split('\n'):
        chunk, used = '', 0
        for char in line.expandtabs(4):
            step = width(char)
            if used + step > limit and chunk:
                boundary = chunk.rfind(' ')
                if boundary > len(chunk) // 2:
                    yield chunk[:boundary]
                    chunk = chunk[boundary + 1:]
                    used = width(chunk)
                else:
                    yield chunk
                    chunk, used = '', 0
            chunk += char; used += step
        yield chunk


def fields(value, indent=2, verbose=False):
    """Render every semantic field without truncation, including empty values."""
    pad = ' ' * indent
    if isinstance(value, dict):
        selected = [(str(k), v) for k, v in value.items() if k != 'confidence' and (verbose or k not in TECHNICAL)]
        if not selected:
            print(pad + '{}')
            return
        label_width = max(width(k) for k, _ in selected)
        for key, item in selected:
            if isinstance(item, (dict, list, tuple)) and item:
                print(f'{pad}{key}:')
                fields(item, indent + 2, verbose)
            else:
                label = key + ' ' * max(0, label_width - width(key))
                prefix = f'{pad}{label} : '
                text = '[]' if isinstance(item, (list, tuple)) else '{}' if isinstance(item, dict) else clean(item)
                for i, line in enumerate(folded(text, max(24, 100 - width(prefix)))):
                    print((prefix if i == 0 else ' ' * width(prefix)) + line)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            print(f'{pad}[{index + 1}]')
            fields(item, indent + 2, verbose)
            if isinstance(item, dict):
                print()
    else:
        for line in folded(clean(value), max(24, 100 - indent)):
            print(pad + line)


def table(headers, rows):
    for row in rows:
        fields(dict(zip(headers, row)))
        print()


def without_payload(value):
    """Display-only projection; never mutates or filters collected evidence."""
    if isinstance(value, dict):
        return {k: without_payload(v) for k, v in value.items()
                if k not in {'segments', 'text', 'raw', 'field_reads', 'file_contents', '_alternatives'}}
    if isinstance(value, (tuple, list)):
        return [without_payload(v) for v in value]
    return value


def artifact_row(label, path, metadata, content=None, errors=None, indent=4):
    """Keep every artifact visible without recursively expanding page metadata."""
    import json
    fields({label: path or '(anonymous)'}, indent=indent, verbose=True)
    projected = without_payload(metadata)
    sock = projected.pop('socket', None)
    tokens = [f'{key}={hex(value) if isinstance(value, int) and ("address" in key) else json.dumps(redact(value), ensure_ascii=False)}'
              for key, value in projected.items() if key != 'confidence']
    line = ''
    for token in tokens:
        if line and width(line + ' | ' + token) > 100 - indent - 2:
            print(' ' * (indent + 2) + line)
            line = ''
        line = line + ' | ' + token if line else token
        if width(line) > 100 - indent - 2:
            for chunk in folded(line, 100 - indent - 2):
                print(' ' * (indent + 2) + chunk)
            line = ''
    if line:
        print(' ' * (indent + 2) + line)
    if sock:
        if sock.get('family') in ('AF_INET', 'AF_INET6'):
            fields({'Socket': f'{sock.get("family")} / {sock.get("protocol")} / {sock.get("state")}',
                    'Local': f'[{sock.get("source_address")}]:{sock.get("source_port")}',
                    'Remote': f'[{sock.get("destination_address")}]:{sock.get("destination_port")}',
                    'Socket address': hex(sock.get('socket_address', 0))}, indent=indent + 2)
        else:
            fields(redact(sock), indent=indent + 2)
    if content:
        fields({'Content': f'{content.get("recovered_bytes", 0)}/{content.get("size", "?")} bytes; '
                           f'{"COMPLETE" if content.get("complete") else "PARTIAL"}'}, indent=indent + 2)
        if content.get('missing_ranges') or content.get('errors'):
            fields({'Missing ranges': json.dumps(content.get('missing_ranges', [])),
                    'Errors': content.get('errors', [])}, indent=indent + 2)
    if errors:
        fields({'Errors': redact(errors)}, indent=indent + 2)


def destination(path):
    print(f'Full evidence JSON: {path}\n')


def show(result, reconstruction=False, verbose=False):
    if reconstruction:
        from .semantic_reporting import show as semantic_show
        return semantic_show(result, verbose)
    from .layered_reporting import show as layered_show
    layered_show(result, reconstruction, verbose)
