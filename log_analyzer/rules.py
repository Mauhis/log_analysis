"""Validated, declarative rules with exact sliding-window aggregation."""
from collections import defaultdict, deque
from dataclasses import dataclass
import json
from itertools import islice


@dataclass(frozen=True)
class Rule:
    """One literal-match detector with a time-window threshold.

    id identifies findings; sources selects normalized categories. contains is
    an OR-list of case-insensitive substrings (empty means match all). threshold
    counts records within window_seconds, grouped by host/source_ip/unit and
    always isolated by host. severity and explanation describe the finding;
    neither changes matching behavior. Loaded rules are validated by load_rules.
    """
    id: str
    sources: tuple
    contains: tuple
    threshold: int
    window_seconds: int
    group_by: str
    severity: str
    explanation: str


# These are tunable heuristics, not learned baselines. Authentication counts
# combine SSH/sudo records per host; repeated-IP counts also include benign events.
DEFAULT_RULES = [
    Rule('authentication_failures', ('ssh', 'sudo'),
         ('failed password', 'authentication failure', 'invalid user', 'incorrect password'),
         5, 300, 'host', 'high',
         'Frequent authentication failures may indicate password guessing or a misconfigured client. Verify accounts and expected activity.'),
    Rule('repeated_source_ip', ('ssh', 'sudo', 'firewall'), (), 10, 300, 'source_ip', 'medium',
         'Repeated events from one source IP may indicate probing or automated activity. Shared addresses and normal clients can also produce repetition.'),
    Rule('firewall_blocks', ('firewall',), ('[ufw block]', '[ufw reject]'),
         5, 300, 'source_ip', 'medium',
         'Repeated blocked traffic may indicate scanning. Compare ports and the source with expected network activity.'),
    Rule('kernel_errors', ('kernel',), ('oom-kill', 'out of memory', 'segfault', 'kernel panic'),
         1, 300, 'host', 'medium',
         'Kernel faults or resource exhaustion can affect availability and may merit checking workloads and recent changes.'),
    Rule('service_failures', ('systemd',), ('failed to start', 'failed with result'),
         1, 300, 'unit', 'medium',
         'A failed service may interrupt monitoring or other functions. Check the service and preceding events; a failure alone does not imply compromise.'),
]


def load_rules(path):
    """Read a UTF-8 JSON rule list and validate every field before analysis.

    The file replaces all defaults; [] explicitly disables detection. Reject
    extra/missing keys, duplicate IDs, unsupported selectors, and invalid values.
    Return immutable Rule objects; propagate file/JSON/validation errors to the
    CLI. Rules contain data only, with no executable expressions or regex input.
    """
    with open(path, encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, list):
        raise ValueError('Rules must be a JSON array')
    result = []
    ids = set()  # Unique rule IDs keep findings unambiguous in downstream reports.
    for item in data:
        if not isinstance(item, dict) or set(item) != set(Rule.__dataclass_fields__):
            raise ValueError('Each rule must contain exactly the documented rule fields')
        for name in ('id', 'explanation'):
            if not isinstance(item[name], str) or not item[name].strip():
                raise ValueError(f'{name} must be a nonempty string')
        if item['id'] in ids:
            raise ValueError('Rule IDs must be unique')
        ids.add(item['id'])
        # Exact int checks reject booleans, which JSON also supports.
        for name in ('threshold', 'window_seconds'):
            if type(item[name]) is not int or item[name] <= 0:
                raise ValueError(f'{name} must be a positive integer')
        for name in ('sources', 'contains'):
            if not isinstance(item[name], list) or not all(isinstance(x, str) and x for x in item[name]):
                raise ValueError(f'{name} must be an array of nonempty strings')
        if not item['sources'] or not set(item['sources']) <= {'ssh', 'sudo', 'firewall', 'kernel', 'systemd', 'other'}:
            raise ValueError('Invalid sources')
        if item['group_by'] not in ('host', 'source_ip', 'unit'):
            raise ValueError('Invalid group_by')
        if item['severity'] not in ('low', 'medium', 'high'):
            raise ValueError('Invalid severity')
        # Convert mutable JSON arrays before placing them in frozen Rule objects.
        result.append(Rule(**{**item, 'sources': tuple(item['sources']), 'contains': tuple(item['contains'])}))
    return result


def detect(events, rules=None):
    """Return the highest-count qualifying window for each rule and host/group.

    Input need not be ordered. None selects defaults; an empty rule list yields
    no findings. Window endpoints are inclusive. Equal-size peaks retain the
    earlier finding. Each finding has at most three earliest evidence records
    from its selected window, plus an explanation; it is not a compromise verdict.
    """
    findings = []
    ordered = sorted(events, key=lambda event: event.timestamp)  # Do not mutate input.
    for rule in DEFAULT_RULES if rules is None else rules:
        groups = defaultdict(deque)  # Active matching-record window per host/group.
        best = {}  # Peak finding per group, suppressing overlapping alert floods.
        for event in ordered:
            if event.source not in rule.sources:
                continue
            if rule.contains and not any(term.casefold() in event.message.casefold() for term in rule.contains):
                continue
            group = getattr(event, rule.group_by)
            if not group:
                # Unknown IPs/units must not be merged into a shared false group.
                continue
            # Hosts are separate security contexts, even when source IPs match.
            key = (event.host, group)
            window = groups[key]
            window.append(event)
            # Expire only records strictly outside the inclusive window. Each
            # matching record enters/leaves its deque at most once per rule.
            while (event.timestamp - window[0].timestamp).total_seconds() > rule.window_seconds:
                window.popleft()
            if len(window) >= rule.threshold and len(window) > best.get(key, {}).get('count', 0):
                best[key] = {
                    'rule_id': rule.id, 'severity': rule.severity,
                    'group_by': rule.group_by, 'group': group, 'host': event.host,
                    'count': len(window), 'window_seconds': rule.window_seconds,
                    'first_seen': window[0].timestamp.isoformat(),
                    'last_seen': event.timestamp.isoformat(),
                    'explanation': rule.explanation,
                    # islice avoids copying a potentially large window just to
                    # retain three examples. Count still covers the full window.
                    'evidence': [entry.to_dict() for entry in islice(window, 3)],
                }
        findings.extend(best.values())
    return findings
