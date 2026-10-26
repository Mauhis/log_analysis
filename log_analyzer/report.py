"""Build a shared report model and render it as readable plain text.

JSON serialization lives in the CLI; both formats use the same findings and
coverage values so their counts and investigation explanations stay consistent.
"""
from datetime import datetime, timezone
import json
from .rules import detect


def build_report(events, warnings, rules=None, coverage=None):
    """Analyze normalized events and return schema-version-2 report data.

    events_analyzed counts every supplied event, including unmatched sources.
    warnings is copied; coverage is the collector's metadata or None for callers
    that only have synthetic/pre-normalized input. Rule findings are separate
    from collection completeness: partial collection may still produce alerts.
    """
    return {
        'schema_version': 2,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'events_analyzed': len(events),
        'collection': coverage,
        'warnings': list(warnings),
        'findings': detect(events, rules),
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
