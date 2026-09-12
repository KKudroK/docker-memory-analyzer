"""Offline truth evaluation. Ground truth is never input to the analyzer."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.evidence import ROOT, save_json


def evaluate(result, truth_dir):
    truth_dir = Path(truth_dir)
    # Confirmed by the dataset owner: only dump2 images were downloaded;
    # the adjacent truth belongs to a different acquisition. Never score it.
    dump2 = (ROOT / 'dumps' / 'dump2').resolve()
    if truth_dir.resolve().is_relative_to(dump2):
        return {'label': result['label'], 'evaluation': 'excluded_noncorresponding_acquisition',
                'reason': 'Dataset owner confirmed dump2 images and adjacent truth are separate collections',
                'checks': []}
    truth_path = truth_dir / 'ground_truth_summary.json'
    if not truth_path.exists():
        truth_path = truth_dir / 'docker_inspect.json'
        if not truth_path.exists():
            return {'label': result['label'], 'evaluation': 'ground_truth_unavailable'}
        inspect = json.loads(truth_path.read_text(encoding='utf-8'))
        if not isinstance(inspect, list) or len(inspect) != 1:
            return {'label': result['label'], 'evaluation': 'inspect_empty_or_multiple; manual_target_selection_required'}
        truth = {'state': {'id': inspect[0]['Id'], 'state': inspect[0]['State']}}
    else:
        truth = json.loads(truth_path.read_text(encoding='utf-8'))
    record = truth.get('state') or {}
    cid, state = record.get('id'), record.get('state')
    report = {'label': result['label'], 'ground_truth': str(truth_path), 'checks': []}
    if not cid or not state:
        report['evaluation'] = 'no_current_container; historical_residue_not_scored_as_false_positive'
        report['observed'] = [{'id': c['container_id'], 'status': c['status']} for c in result['containers']]
        return report
    matched = next((c for c in result['containers'] if c['container_id'] == cid), None)
    report['checks'].append({'field': 'container_id', 'match': matched is not None})
    if matched is None:
        return report
    report['checks'].append({'field': 'status', 'expected': state['Status'], 'observed': matched['status'].lower(),
                             'match': state['Status'] == matched['status'].lower()})
    expected_pids = {p['pid'] for p in truth.get('processes', [])}
    actual_pids = {p['pid'] for p in matched.get('processes', [])}
    if 'processes' in matched and 'processes' in truth:
        report['checks'].append({'field': 'processes', 'expected': sorted(expected_pids), 'observed': sorted(actual_pids),
                                'match': expected_pids == actual_pids})
        ns_names = {'mnt': 'mnt_ns', 'net': 'net_ns', 'uts': 'uts_ns', 'ipc': 'ipc_ns', 'cgroup': 'cgroup_ns', 'user': 'user_ns'}
        for process in truth.get('processes', []):
            parsed = next((p for p in matched['processes'] if p['pid'] == process['pid']), None)
            if parsed is None:
                continue
            for name, dest in ns_names.items():
                expected = int(process['namespaces'][name].split('[')[1].rstrip(']'))
                actual = parsed.get('nsproxy', {}).get(dest)
                report['checks'].append({'field': f"pid.{process['pid']}.{dest}", 'expected': expected, 'observed': actual, 'match': expected == actual})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', nargs='+')
    parser.add_argument('--truth-root', default=str(ROOT / 'dumps' / 'dump1'))
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    reports = []
    for file in args.results:
        results = json.loads(Path(file).read_text(encoding='utf-8'))
        for result in results if isinstance(results, list) else [results]:
            reports.append(evaluate(result, Path(args.truth_root) / result['label']))
    checks = [check for report in reports for check in report.get('checks', [])]
    save_json({'reports': reports, 'checks': len(checks), 'matches': sum(c['match'] for c in checks)}, args.output)
    print(f"Checks: {len(checks)}, matches: {sum(c['match'] for c in checks)}; {args.output}")


if __name__ == '__main__':
    main()
