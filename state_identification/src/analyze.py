#!/usr/bin/env python3
"""Container state identification CLI."""
import argparse
import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.evidence import ROOT, save_json
from src.pipeline import collect
from src.state_identification import state_to_status as _state_to_status

EXPECTED_STATES = {'S00': 'baseline', 'S01': 'created', 'S02': 'running', 'S03': 'paused',
                   'S04': 'restarting', 'S05': 'exited', 'S06': 'removing', 'S07': 'dead', 'T0': 'destroyed'}


def state_to_status(state):
    return _state_to_status(state).title()


def find_dump_files(path):
    path = Path(path)
    files = [path] if path.is_file() else sorted(p for p in path.rglob('*') if p.suffix.lower() in ('.lime', '.raw'))
    return [(p.stem, str(p), next((state for prefix, state in EXPECTED_STATES.items()
                                 if p.stem == prefix + '_' + state or p.stem.startswith(prefix + '_' + state + '_')), None)) for p in files]


def analyze_single_dump(dump_path, label=None, expected_state=None, skip_events=False,
                        name_hints=None, eval_artifacts=False, verbose=False, symbol_paths=None):
    result = collect(dump_path, skip_events=skip_events, symbol_paths=symbol_paths,
                     log=lambda *args: None)
    result['label'] = label or result['label']
    result['scenario_hint'] = expected_state
    return result


def serialize_results(results, output_path):
    save_json(results, output_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input')
    parser.add_argument('--output', '-o')
    parser.add_argument('--no-events', action='store_true')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--symbols', action='append')
    parser.add_argument('--names', nargs='*', help='Compatibility option; all IDs are scanned')
    parser.add_argument('--eval', '--eval-artifacts', action='store_true', help='Evaluate saved results with scripts/evaluate_dump_results.py')
    args = parser.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    entries = find_dump_files(args.input)
    if not entries:
        parser.error('No memory images found')
    output = args.output or ROOT / 'outputs' / datetime.datetime.now().strftime('%Y%m%d_%H%M%S_state') / 'state_results.json'
    results = []
    for label, path, hint in entries:
        print(f'[{len(results) + 1}/{len(entries)}] Analyzing {label} ...', flush=True)
        result = analyze_single_dump(path, label, hint, skip_events=args.no_events, verbose=args.verbose, symbol_paths=args.symbols)
        results.append(result)
        save_json(results, output)
        from src.reporting import show
        show(result, verbose=args.verbose)
    from src.reporting import destination
    destination(output)


if __name__ == '__main__':
    main()
