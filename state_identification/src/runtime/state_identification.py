"""State decisions, independent from execution-context reconstruction."""


def state_to_status(state):
    if not state:
        return 'unknown'
    for field in ('Running', 'Paused', 'Restarting', 'RemovalInProgress', 'Dead'):
        if type(state.get(field)) is not bool:
            return 'unknown'
    if state['Running']:
        if state['Paused']:
            return 'paused'
        if state['Restarting']:
            return 'restarting'
        return 'running'
    if state['Restarting']:
        return 'restarting'
    if state['RemovalInProgress']:
        return 'removing'
    if state['Dead']:
        if state.get('Removed') is True and state.get('ErrorMsg') == '':
            return 'destroyed'
        return 'dead'
    if state.get('Removed') is True and state.get('ErrorMsg') == '':
        return 'destroyed'
    if state.get('HasBeenStartedBefore') is True or state.get('StartedAt'):
        return 'exited'
    if state.get('HasBeenStartedBefore') is False:
        return 'created'
    return 'unknown'


def identify(state, valid, events, kernel=None):
    evidence = []
    status = state_to_status(state) if valid else 'unknown'
    confidence = 'unknown'
    if status != 'unknown':
        confidence = 'high'
        evidence.append({'source': 'dockerd.State', 'kind': 'parsed_flags', 'status': status})
    lifecycle = [e for e in events if e.get('action') in
                 {'create', 'start', 'die', 'stop', 'pause', 'unpause', 'destroy'}]
    last = lifecycle[-1] if lifecycle else None
    if last:
        evidence.append({'source': 'dockerd.event_carving', 'kind': 'historical_observation',
                         'action': last['action'], 'address': last.get('addr'), 'timestamp': last.get('timestamp')})
    candidates = []
    return {'status': status.title(), 'confidence': confidence, 'evidence': evidence,
            'candidate_states': candidates,
            'limitations': ['heap candidates may be stale; snapshot is not necessarily atomic']}


def select_candidate(candidates):
    """Choose a readable dockerd object; preserve stale alternatives separately.

    Lifecycle timestamps break ties between otherwise valid heap allocations.
    Kernel tasks and scenario names never influence this selection.
    """
    def rank(candidate):
        state = candidate.get('state') or {}
        times = [str(state[k]) for k in ('StartedAt', 'FinishedAt') if state.get(k)]
        return (bool(candidate.get('state_valid')),
                bool(candidate.get('root')), bool((candidate.get('container') or {}).get('Name')),
                max(times, default=''))
    return max(candidates, key=rank, default={})
