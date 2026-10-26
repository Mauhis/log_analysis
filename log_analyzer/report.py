"""Build a shared report model and render it as readable plain text.

JSON serialization lives in the CLI; both formats use the same findings and
coverage values so their counts and investigation explanations stay consistent.
"""
from datetime import datetime, timezone
import json
from collections import Counter
from .rules import DEFAULT_RULES, detect
from .summary import summarize


def build_report(events, warnings, rules=None, coverage=None):
    """Analyze normalized events and return schema-version-3 report data.

    events_analyzed counts every supplied event, including unmatched sources.
    warnings is copied; coverage is the collector's metadata or None for callers
    that only have synthetic/pre-normalized input. Rule findings are separate
    from collection completeness: partial collection may still produce alerts.
    """
    active_rules = DEFAULT_RULES if rules is None else rules
    findings = detect(events, active_rules)
    finding_counts = Counter(finding['rule_id'] for finding in findings)
    severity_counts = Counter(finding['severity'] for finding in findings)
    statistics = summarize(events)
    configured_sources = {source for rule in active_rules for source in rule.sources}
    # Eligibility is a source-category check only, not a claim that a record
    # matched a rule's message predicate, grouping field, or threshold.
    eligible = sum(count for source, count in statistics['by_source'].items() if source in configured_sources)
    available = coverage.get('events_available') if coverage else None
    return {
        'schema_version': 3,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'events_analyzed': len(events),
        'collection': coverage,
        'warnings': list(warnings),
        'summary': statistics,
        'analysis': {
            'enabled_rules': len(active_rules),
            'events_in_rule_source_categories': eligible,
            'events_outside_rule_source_categories': len(events) - eligible,
            'analyzed_percent_of_available': round(100 * len(events) / available, 2) if available else None,
            'findings_by_severity': {level: severity_counts[level] for level in ('high', 'medium', 'low')},
            'rules': [{'id': rule.id, 'sources': list(rule.sources),
                       'contains': list(rule.contains), 'threshold': rule.threshold,
                       'window_seconds': rule.window_seconds, 'group_by': rule.group_by,
                       'severity': rule.severity, 'explanation': rule.explanation,
                       'findings': finding_counts[rule.id]} for rule in active_rules],
        },
        'findings': findings,
        'interpretation': 'Findings are rule matches requiring investigation, not proof of compromise. No findings does not establish that the system is secure.',
    }


def render_text(report):
    """Return a newline-terminated text report from build_report output.

    Include accounting, warnings, findings, explanations, and evidence. Optional
    collection metadata is omitted for callers without it. Escape untrusted
    fields so messages cannot inject terminal escapes or new report lines.
    """
    def safe(value):
        """Use JSON string escaping without its surrounding quotation marks."""
        return json.dumps(str(value), ensure_ascii=True)[1:-1]

    lines = ['Security analysis report',
             f"Generated (UTC): {report['generated_at']}",
             f"Events analyzed: {report['events_analyzed']}",
             f"Findings: {len(report['findings'])}"]
    coverage = report.get('collection')  # May be None for direct library callers.
    if coverage:
        def state(value):
            """Keep an unknown partial-scan result distinct from a confirmed no."""
            return 'unknown' if value is None else ('yes' if value else 'no')
        available = coverage['events_available']
        lines.extend([
            f"Requested interval: {safe(coverage['since'])} through {safe(coverage['until'])}",
            f"Available entries (readable): {available if available is not None else 'unknown'}",
            f"Observed entries: {coverage['events_observed']}",
            f"Collected entries (retained): {coverage['events_collected']}",
            f"Discarded entries (parsing/normalization): {coverage['events_discarded']}",
            f"Entries omitted by limit: {coverage['events_omitted_by_limit']}",
            f"Collection limit: {coverage['limit']}",
            f"Collection completed: {state(coverage['collection_completed'])}",
            f"Collection truncated: {state(coverage['truncated'])}",
            f"Complete readable coverage: {state(coverage['coverage_complete'])}",
            f"Permissions: {safe(coverage['permission_status'])}",
            safe(coverage['scope']),
        ])
    lines.extend(['', 'Collection warnings:'])
    lines.extend(f'- {safe(warning)}' for warning in report['warnings'])
    if not report['warnings']:
        lines.append('- None reported.')
    if report.get('summary'):
        lines.extend(_summary_lines(report, safe))
    lines.extend(['', 'Detected findings:'])
    if not report['findings']:
        lines.append('No configured rules matched the collected events.')
    # Evidence contains only the small sample chosen by detection, not all events.
    for number, finding in enumerate(report['findings'], 1):
        lines.extend([
            '', f"{number}. [{safe(finding['severity']).upper()}] {safe(finding['rule_id'])}",
            f"Host: {safe(finding['host'])}",
            f"Group ({safe(finding['group_by'])}): {safe(finding['group'])}",
            f"Count: {finding['count']} within {finding['window_seconds']} seconds",
            f"First seen: {safe(finding['first_seen'])}",
            f"Last seen: {safe(finding['last_seen'])}",
            f"Why investigate: {safe(finding['explanation'])}",
            'Sample evidence:',
        ])
        for event in finding['evidence']:
            lines.append(f"- {safe(event['timestamp'])} [{safe(event['source'])}] {safe(event['message'])}")
    lines.extend(['', report['interpretation']])
    return '\n'.join(lines) + '\n'


def _summary_lines(report, safe):
    """Render descriptive statistics; escape all log-derived labels via safe.

    Rankings show at most ten groups. Hourly text is capped at the 24 busiest
    observed hours while JSON retains every observed hourly bucket.
    """
    summary, analysis = report['summary'], report['analysis']
    percentage = analysis['analyzed_percent_of_available']
    lines = ['', 'Gathered data overview:', summary['scope'],
             f"First analyzed event (UTC): {summary['first_event'] or 'none'}",
             f"Last analyzed event (UTC): {summary['last_event'] or 'none'}",
             f"Observed event span: {summary['observed_span_seconds']} seconds",
             f"Analyzed share of readable entries: {str(percentage) + '%' if percentage is not None else 'unknown / not applicable'}",
             f"Normalized message text: {summary['message_text_bytes']} UTF-8 bytes (not journal disk usage)",
             f"Distinct hosts: {summary['unique_hosts']}; emitting units: {summary['unique_units']}; identifiers: {summary['unique_identifiers']}",
             '', 'Records by source:']
    total = report['events_analyzed']
    for source, count in summary['by_source'].items():
        percent = 100 * count / total if total else 0
        lines.append(f'- {safe(source)}: {count} ({percent:.1f}%)')
    lines.extend(['', 'Journal priorities (independent of finding severity):'])
    lines.extend(f'- {safe(priority)}: {count}' for priority, count in summary['by_journal_priority'].items())
    for title, key in (('Top hosts', 'top_hosts'), ('Top emitting units', 'top_units'),
                       ('Top identifiers', 'top_identifiers')):
        lines.extend(['', f'{title} (up to 10):'])
        lines.extend(f"- {safe(item['name'])}: {item['count']}" for item in summary[key])
        if not summary[key]:
            lines.append('- No populated metadata.')
    lines.extend(['', 'Metadata quality (missing or empty after normalization):'])
    lines.extend(f'- {safe(field)}: {count}' for field, count in summary['missing_metadata'].items())
    lines.extend(['', 'Authentication and network activity (record counts):'])
    for source, counts in summary['authentication'].items():
        lines.append(f"- {safe(source)}: {counts['failure_records']} failure indicators; {counts['success_records']} success/session-open indicators")
    lines.extend([
        f"- UFW block/reject indicators: {summary['firewall_block_records']}",
        f"- Records with an extracted source IP: {summary['events_with_source_ip']}",
        f"- Distinct source IPs: {summary['unique_source_ips']}",
        f"- Source-IP/host groups: {summary['source_ip_host_groups']} (repeated: {summary['repeated_source_ip_host_groups']})",
        '', 'Top source IPs by volume (up to 10, separated by host):',
    ])
    for item in summary['top_source_ips']:
        lines.append(f"- {safe(item['source_ip'])} on {safe(item['host']) or '(unknown host)'}: {item['event_count']} records; {item['failure_records']} auth failure indicators; {item['firewall_block_records']} firewall block indicators")
    if not summary['top_source_ips']:
        lines.append('- No source addresses extracted; this does not establish absence of network activity.')
    hours = summary['hourly_volume']
    lines.extend(['', f'Hourly volume (UTC; {len(hours)} observed buckets):'])
    if len(hours) > 24:
        hours = sorted(sorted(hours, key=lambda item: (-item['count'], item['hour_utc']))[:24], key=lambda item: item['hour_utc'])
        lines.append('Showing the 24 busiest observed hours; JSON contains all buckets.')
    lines.extend(f"- {item['hour_utc']}: {item['count']}" for item in hours)
    if not hours:
        lines.append('- No analyzed events.')
    lines.extend(['', 'Detection coverage and configuration:',
                  f"Enabled rules: {analysis['enabled_rules']}",
                  f"Records in configured rule source categories: {analysis['events_in_rule_source_categories']}",
                  f"Records outside configured rule source categories: {analysis['events_outside_rule_source_categories']}",
                  'Category eligibility does not mean a record matched a message predicate or alert threshold.',
                  'Findings by severity: ' + ', '.join(f'{level}={count}' for level, count in analysis['findings_by_severity'].items())])
    for rule in analysis['rules']:
        lines.append(f"- {safe(rule['id'])}: {rule['findings']} findings; {rule['threshold']} records / {rule['window_seconds']} seconds; group={safe(rule['group_by'])}; severity={safe(rule['severity'])}; sources={safe(', '.join(rule['sources']))}")
        lines.append('  Message matches (any): ' + (safe(', '.join(rule['contains'])) if rule['contains'] else 'all messages in the selected sources'))
    if not analysis['rules']:
        lines.append('- Detection is disabled: no rules configured.')
    lines.extend(['', 'How to interpret these statistics:'])
    lines.extend(f'- {note}' for note in summary['notes'])
    return lines
