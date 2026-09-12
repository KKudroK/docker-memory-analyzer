#!/usr/bin/env python3
"""Execution-context reconstruction, separate from state identification."""
import argparse
import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.evidence import ROOT, save_json
from src.pipeline import collect


def analyze_dump(dump_path, verbose=False, symbol_paths=None):
    return collect(dump_path, reconstruct=True, symbol_paths=symbol_paths,
                   log=lambda *args: None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump_path')
    parser.add_argument('--output', '-o')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--symbols', action='append')
    args = parser.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    output = args.output or ROOT / 'outputs' / datetime.datetime.now().strftime('%Y%m%d_%H%M%S_reconstruction') / 'reconstruction.json'
    from src.analyze import find_dump_files
    entries = find_dump_files(args.dump_path)
    if not entries:
        parser.error('No memory images found')
    results = []
    for label, path, hint in entries:
        print(f'[{len(results) + 1}/{len(entries)}] Reconstructing {label} ...', flush=True)
        result = analyze_dump(path, args.verbose, args.symbols)
        results.append(result)
        save_json(result if Path(args.dump_path).is_file() else results, output)
        from src.reporting import show
        show(result, reconstruction=True, verbose=args.verbose)
    from src.reporting import destination
    destination(output)


if __name__ == '__main__':
    main()
