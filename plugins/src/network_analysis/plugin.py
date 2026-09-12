"""Container attachment reconstruction with opt-in detailed evidence."""
import json
import logging
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.linux import network
from .collector import Collector
from .presentation import table

vollog = logging.getLogger(__name__)


class InspectNetworks(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 22, 0)
    _version = (3, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name='kernel', description='Linux kernel', architectures=['Intel32','Intel64']),
                requirements.VersionRequirement(name='net_symbols', component=network.NetSymbols, version=(1,0,0)),
                requirements.IntRequirement(name='limit', description='Corruption safety budget per traversal', default=100000, optional=True),
                requirements.StringRequirement(name='identity-mode', description='Container identity strategy: combined, cgroup, or shim', default='combined', optional=True),
                requirements.BooleanRequirement(name='disable-cgroup-cache', description='Benchmark-only: recompute cgroup paths for every task/thread', default=False, optional=True),
                requirements.BooleanRequirement(name='identity-only', description='Benchmark-only: skip socket and optional network collectors', default=False, optional=True),
                requirements.BooleanRequirement(name='include-host', description='Include host/unattributed namespaces', default=False, optional=True),
                requirements.BooleanRequirement(name='containers-only', description='Compatibility alias for default scope', default=False, optional=True),
                requirements.BooleanRequirement(name='dump-evidence', description='Collect all supported evidence and save JSON', default=False, optional=True),
                requirements.BooleanRequirement(name='dump-metrics', description='Save traversal/timing metrics without enabling optional evidence collectors', default=False, optional=True)]

    def run(self):
        features = (set() if self.config['identity-only'] else
                    (None if self.config['dump-evidence'] else {'sockets'}))
        report=Collector(self.context,self.config['kernel'],self.config['limit'],
                         identity_mode=self.config['identity-mode'],
                         cgroup_cache=not self.config['disable-cgroup-cache']).collect(features=features)
        if self.config['dump-evidence']:
            with self.open('network_evidence.json') as handle:
                handle.write(json.dumps(report,indent=2,ensure_ascii=False).encode('utf-8'))
        if self.config['dump-metrics']:
            payload = {'metadata': report['metadata'], 'summary': report['summary'],
                       'container_candidates': sorted({cid for task in report['tasks'] for cid in task['container_candidates']}),
                       'identity_assignments': [{'pid': task['pid'], 'tgid': task['tgid'],
                                                 'container_candidates': task['container_candidates'],
                                                 'evidence': task.get('identity_evidence'),
                                                 'conflict': task.get('identity_conflict', False)}
                                                for task in report['tasks'] if task['container_candidates']],
                       'errors': report['errors']}
            with self.open('network_metrics.json') as handle:
                handle.write(json.dumps(payload,indent=2,ensure_ascii=False).encode('utf-8'))
        if report['errors']:
            vollog.warning('%d parsing errors: partial result. Use --dump-evidence for error details.',len(report['errors']))
        if not any(n['container_candidates'] for n in report['namespaces']) and not self.config['include-host']:
            vollog.warning('No attributed container namespaces. Use --include-host to inspect unattributed namespaces.')
        columns,rows=table(report,self.config['include-host'] and not self.config['containers-only'])
        return renderers.TreeGrid(columns,((0,row) for row in rows))
