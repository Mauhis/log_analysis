"""Descriptive statistics for retained events, independent of alert thresholds.

All totals describe normalized journal records, not unique incidents, users, or
connection attempts. No extra commands or lookups are needed to build summaries.
"""
from collections import Counter, defaultdict
from datetime import timezone


PRIORITY_NAMES = ('emergency', 'alert', 'critical', 'error', 'warning',
                  'notice', 'info', 'debug')
AUTH_FAILURE_TERMS = ('failed password', 'authentication failure', 'invalid user',
                      'incorrect password')


def auth_activity(event):
    """Return failure/success flags using common English SSH/sudo messages.

    A record matching several failure phrases is counted once. Success markers
    are SSH accepted credentials and sudo PAM session-open records; they do not
    establish unique logins or successful privileged commands.
    """
    if event.source not in ('ssh', 'sudo'):
        return False, False
    message = event.message.casefold()
    failure = any(term in message for term in AUTH_FAILURE_TERMS)
    success = ((event.source == 'ssh' and any(term in message for term in (
        'accepted password', 'accepted publickey', 'accepted keyboard-interactive')))
        or (event.source == 'sudo' and 'session opened for user' in message))
    return failure, success


def ranked(counter, limit=10):
    """Return bounded counts with deterministic alphabetical ties for reports."""
    return [{'name': name, 'count': count}
            for name, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def summarize(events):
    """Aggregate metadata, volume, IP repetition, and authentication indicators.

    Rankings retain ten entries; unique counts and aggregate totals remain exact
    for the analyzed sample. Empty timestamps and missing fields are explicit
    rather than inferred from the requested collection interval.
    """
    sources = Counter({source: 0 for source in ('ssh', 'sudo', 'firewall', 'kernel', 'systemd', 'other')})
    priorities = Counter({name: 0 for name in (*PRIORITY_NAMES, 'unknown')})
    hosts, units, identifiers, hours = Counter(), Counter(), Counter(), Counter()
    missing = Counter({name: 0 for name in ('host', 'unit', 'identifier', 'message', 'priority')})
    authentication = {source: {'failure_records': 0, 'success_records': 0}
                      for source in ('ssh', 'sudo')}
    # Keep hosts separate: a shared source address need not represent one actor.
    addresses = defaultdict(lambda: {'event_count': 0, 'failure_records': 0,
                                    'firewall_block_records': 0, 'sources': Counter()})
    message_bytes = 0
    first = last = None
    firewall_blocks = 0
    for event in events:
        sources[event.source] += 1
        priority = PRIORITY_NAMES[event.priority] if event.priority is not None else 'unknown'
        priorities[priority] += 1
        for field, counter in (('host', hosts), ('unit', units), ('identifier', identifiers)):
            value = getattr(event, field)
            if value:
                counter[value] += 1
            else:
                missing[field] += 1
        missing['message'] += not bool(event.message)
        missing['priority'] += event.priority is None
        message_bytes += len(event.message.encode('utf-8'))
        first = min(first, event.timestamp) if first else event.timestamp
        last = max(last, event.timestamp) if last else event.timestamp
        hour = event.timestamp.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
        hours[hour] += 1
        failure, success = auth_activity(event)
        if event.source in authentication:
            authentication[event.source]['failure_records'] += failure
            authentication[event.source]['success_records'] += success
        blocked = event.source == 'firewall' and any(term in event.message.casefold()
                                                    for term in ('[ufw block]', '[ufw reject]'))
        firewall_blocks += blocked
        if event.source_ip:
            address = addresses[(event.host, event.source_ip)]
            address['event_count'] += 1
            address['failure_records'] += failure
            address['firewall_block_records'] += blocked
            address['sources'][event.source] += 1
    # Restrict output size without hiding the number of distinct addresses/groups.
    ordered_ips = sorted(addresses.items(), key=lambda item: (-item[1]['event_count'], item[0]))
    return {
        'scope': 'Analyzed records only; omitted, unreadable, or discarded entries are not summarized.',
        'first_event': first.isoformat() if first else None,
        'last_event': last.isoformat() if last else None,
        'observed_span_seconds': (last - first).total_seconds() if first else 0,
        'message_text_bytes': message_bytes,
        'by_source': dict(sources), 'by_journal_priority': dict(priorities),
        'unique_hosts': len(hosts), 'unique_units': len(units),
        'unique_identifiers': len(identifiers),
        'top_hosts': ranked(hosts), 'top_units': ranked(units),
        'top_identifiers': ranked(identifiers),
        'missing_metadata': dict(missing),
        'hourly_volume': [{'hour_utc': hour, 'count': count} for hour, count in sorted(hours.items())],
        'authentication': authentication,
        'firewall_block_records': firewall_blocks,
        'events_with_source_ip': sum(item['event_count'] for item in addresses.values()),
        'unique_source_ips': len({ip for host, ip in addresses}),
        'source_ip_host_groups': len(addresses),
        'repeated_source_ip_host_groups': sum(item['event_count'] > 1 for item in addresses.values()),
        'top_source_ips': [dict(host=host, source_ip=ip, **values)
                           for (host, ip), values in ordered_ips[:10]],
        'ranking_limit': 10,
        'notes': [
            'Counts represent journal records, not unique incidents or authentication attempts.',
            'Authentication and firewall indicators use common English message substrings; other formats may be missed.',
            'Journal priorities describe the emitting application; they are separate from finding severity.',
            'Hourly buckets include observed hours only; missing buckets do not prove missing logs. Boundary hours may be partial.',
            'Message text bytes measure normalized UTF-8 message content only, not journal size or disk usage.',
            'Source addresses come from message text and may be spoofed; repetition alone is not evidence of an attack.',
        ],
    }
