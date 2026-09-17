"""Typed socket/holder records; rendering belongs to the selected CLI renderer."""
import json
import logging
from volatility3.framework import interfaces, renderers
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.linux import network
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from .collector import Collector
from . import context, identity, views

vollog = logging.getLogger(__name__)


def value_or_absent(value, converter=None):
    if value is None:
        return renderers.NotAvailableValue()
    return converter(value) if converter else value


def address_value(value):
    if value in (None, '', '0x0', 0):
        return renderers.NotAvailableValue()
    return format_hints.Hex(int(value, 16) if isinstance(value, str) else int(value))


def namespace_inode(nets, address):
    net = nets.get(address)
    if net is None:
        return renderers.NotAvailableValue()
    if net.get('inode') is None:
        return renderers.UnreadableValue()
    return int(net['inode'])


class InspectNetworks(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 22, 0)
    _version = (11, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name='kernel', description='Linux kernel (validated x86-64 scope)', architectures=['Intel64']),
                requirements.VersionRequirement(name='net_symbols', component=network.NetSymbols, version=(1,0,0)),
                requirements.VersionRequirement(name='linuxutils', component=linux.LinuxUtilities, version=(2,0,0)),
                requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(4,0,0)),
                requirements.ListRequirement(name='container', description='Filter by unambiguous observed ID reference(s) or prefix(es); not Docker inventory', element_type=str, optional=True),
                requirements.ChoiceRequirement(name='view', description='Container evidence view; diagnostics checks all retained collectors', choices=['sockets', 'relations', 'containers', 'interfaces', 'conntrack', 'diagnostics'], default='sockets', optional=True),
                requirements.BooleanRequirement(name='dump-evidence', description='Save evidence for this view; does not enable extra collectors', default=False, optional=True)]

    def run(self):
        view = self.config.get('view', 'sockets')
        features_by_view = {'sockets': {'sockets'}, 'relations': {'sockets'},
                            'containers': {'sockets'}, 'interfaces': {'interfaces'},
                            'conntrack': {'conntrack'},
                            'diagnostics': {'sockets', 'interfaces', 'conntrack'}}
        if view not in features_by_view:
            raise ValueError('Unsupported view: ' + str(view))
        report = Collector(self.context, self.config['kernel']).collect(features=features_by_view[view])
        known = {cid for task in report['tasks'] if (cid := container_member_id(task))}
        select_containers(known, self.config.get('container'))
        if self.config.get('dump-evidence', False):
            with self.open('network_evidence.json') as handle:
                handle.write(json.dumps(report, indent=2, ensure_ascii=False).encode('utf-8'))
        self._log_diagnostics(report)
        if view == 'relations':
            return renderers.TreeGrid(relation_columns(), relation_rows(report, self.config.get('container')))
        if view != 'sockets':
            return renderers.TreeGrid(views.columns(view), views.rows(report, view, self.config.get('container')))
        return renderers.TreeGrid(self._columns(), self._generator(report))

    def _log_diagnostics(self, report):
        for error in report.get('errors', []):
            vollog.debug('Parse error stage=%s object=%s type=%s detail=%s affected_holders=%s',
                           error['stage'], error['address'], error['error'], error['detail'],
                           error.get('affected_holders', []))
        for item in report.get('unsupported', []):
            vollog.debug('Unsupported feature=%s object=%s reason=%s',
                           item['feature'], item.get('interface', item.get('namespace', '')),
                           item['reason'])
        for address in report['container_context'].get('unresolved_tasks', []):
            vollog.debug('Conflicting or multiple ID references for task %s; ID not assigned', address)

    @staticmethod
    def _columns():
        return [('Container ID', str), ('NetNS', int), ('Proto', str),
                ('PID', int), ('Process', str), ('FD', int),
                ('Local', str), ('Remote', str), ('State', str)]

    def _generator(self, report):
        tasks = {task['pid']: task for task in report['tasks']}
        nets = {net['address']: net for net in report['namespaces']}
        eligible = {pid: container_member_id(task) for pid, task in tasks.items()}
        known = {cid for cid in eligible.values() if cid}
        selected, labels = select_containers(known, self.config.get('container'))
        seen = set()
        for sock in report['sockets']:
            for holder in sock['holders']:
                cid = eligible.get(holder['pid'])
                if cid is None or cid not in selected:
                    continue
                task = tasks[holder['pid']]
                # Collapse only the same process/FD/file/socket observation across threads.
                key = (cid, task['tgid'], holder['fd'], holder.get('file'), sock['socket'])
                if key in seen:
                    continue
                seen.add(key)
                proto, state = socket_labels(sock)
                yield 0, (labels[cid], namespace_inode(nets, sock['namespace']), proto,
                          task['tgid'], task['comm'], holder['fd'],
                          socket_endpoint(sock, 'source'), socket_endpoint(sock, 'destination'), state)


def container_member_id(task):
    return identity.member_id(task)


def select_containers(known, prefixes):
    selected = set(known)
    if prefixes:
        selected = set()
        for prefix in prefixes:
            matches = {cid for cid in known if cid.startswith(prefix.lower())}
            if len(matches) != 1:
                raise ValueError(f'Container prefix {prefix!r} matched {len(matches)} IDs; use a longer/existing ID')
            selected.update(matches)
    return selected, identity.display_labels(known)


def relation_columns():
    return [('Relation', str), ('Container ID', str), ('Object', format_hints.Hex),
            ('Peer Container', str), ('Peer Object', format_hints.Hex), ('Evidence', str)]


def relation_rows(report, prefixes=None):
    # Build a display projection with the same membership gate as the socket table.
    # The original candidate/ancestry evidence is neither mutated nor promoted.
    tasks = []
    for task in report['tasks']:
        cid = container_member_id(task)
        if cid:
            tasks.append(dict(task, container_candidates=[cid], identity_conflict=False))
    pids = {task['pid'] for task in tasks}
    sockets = [dict(sock, holders=[h for h in sock['holders'] if h['pid'] in pids])
               for sock in report['sockets']]
    model = context.build(dict(report, tasks=tasks, sockets=sockets))
    known = {item['id'] for item in model['containers']}
    selected, labels = select_containers(known, prefixes)
    for item in model['structural_relations']:
        # One row per membership, not a clique of inferred communicating pairs.
        for cid in item['members']:
            if cid in selected:
                yield 0, (item['kind'], labels[cid], address_value(item['evidence'][0]),
                          renderers.NotApplicableValue(), renderers.NotApplicableValue(), item['confidence'])
    for item in model['relations']:
        for left in item['left_containers'] or [None]:
            for right in item['right_containers'] or [None]:
                if left not in selected and right not in selected:
                    continue
                yield 0, (item['kind'], value_or_absent(labels.get(left)), address_value(item['left_socket']),
                          value_or_absent(labels.get(right)), address_value(item['right_socket']), item['confidence'])


def socket_endpoint(sock, side):
    if sock['family'] == 1:
        if side == 'destination':
            return renderers.NotApplicableValue()
        path = sock.get('path')
        # Keep terminal control characters out of the summary; raw bytes stay in evidence.
        return value_or_absent(path, lambda value: value.encode('unicode_escape').decode('ascii'))
    if sock['family'] not in (2, 10):
        return renderers.NotApplicableValue()
    ip, port = sock.get(side + '_ip'), sock.get(side + '_port')
    if ip is None or port is None:
        return renderers.NotAvailableValue()
    return f'[{ip}]:{port}' if sock['family'] == 10 else f'{ip}:{port}'


def socket_labels(sock):
    family, protocol = sock['family'], sock.get('protocol_number')
    if family == 1:
        return 'UNIX', value_or_absent(sock.get('state_name'), str)
    if family in (2, 10):
        label = {6: 'TCP', 17: 'UDP'}.get(protocol, str(sock.get('protocol', protocol)))
        if family == 10:
            label += 'v6'
        states = {1: 'ESTABLISHED', 2: 'SYN_SENT', 3: 'SYN_RECV', 4: 'FIN_WAIT1',
                  5: 'FIN_WAIT2', 6: 'TIME_WAIT', 7: 'CLOSE', 8: 'CLOSE_WAIT',
                  9: 'LAST_ACK', 10: 'LISTEN', 11: 'CLOSING', 12: 'NEW_SYN_RECV'}
        state = sock.get('state')
        return label, (states.get(state, str(state)) if protocol == 6 and state is not None
                       else value_or_absent(state, str))
    return f'AF_{family}/PROTO_{protocol}', value_or_absent(sock.get('state'), str)
