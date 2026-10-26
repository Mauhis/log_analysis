"""Synthetic report regressions for exact totals, bounded output, and safe text."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest

from log_analyzer.normalize import Event
from log_analyzer.report import build_report, render_text
from log_analyzer.rules import Rule
from log_analyzer.summary import summarize


def event(source='ssh', message='Failed password from 192.0.2.1', **overrides):
    """Create an immutable normalized fixture without accessing real journals."""
    base = Event(datetime(2026, 1, 1, tzinfo=timezone.utc), source, message,
                 'host-a', 'ssh.service', 'sshd', 4, '192.0.2.1')
    return replace(base, **overrides)


class SummaryTests(unittest.TestCase):
    def test_mixed_sources_exact_totals_and_time_span(self):
        events = [
            event(message='Failed password; authentication failure from 192.0.2.1'),
            event(message='Accepted publickey from 192.0.2.1'),
            event('sudo', 'session opened for user root', source_ip=None),
            event('sudo', 'authentication failure', source_ip=None),
            event('firewall', '[UFW BLOCK] SRC=192.0.2.1'),
            event('kernel', 'segfault', source_ip=None, priority=3),
            event('systemd', 'Started worker', source_ip=None, priority=6),
            event('other', '', host='', unit='', identifier='', priority=None,
                  source_ip=None, timestamp=datetime(2026, 1, 1, 2, tzinfo=timezone.utc)),
        ]
        report = build_report(list(reversed(events)), [])
        summary = report['summary']
        self.assertEqual(sum(summary['by_source'].values()), 8)
        self.assertEqual(sum(summary['by_journal_priority'].values()), 8)
        self.assertEqual(summary['by_source']['ssh'], 2)
        self.assertEqual(summary['authentication']['ssh'], {'failure_records': 1, 'success_records': 1})
        self.assertEqual(summary['authentication']['sudo'], {'failure_records': 1, 'success_records': 1})
        self.assertEqual(summary['firewall_block_records'], 1)
        self.assertEqual(summary['events_with_source_ip'], 3)
        self.assertEqual(summary['unique_source_ips'], 1)
        self.assertEqual(summary['top_source_ips'][0]['failure_records'], 1)
        self.assertEqual(summary['top_source_ips'][0]['firewall_block_records'], 1)
        self.assertEqual(summary['missing_metadata'], dict.fromkeys(('host', 'unit', 'identifier', 'message', 'priority'), 1))
        self.assertEqual(summary['observed_span_seconds'], 7200)
        self.assertEqual([bucket['count'] for bucket in summary['hourly_volume']], [7, 1])
        self.assertEqual(summary['first_event'], '2026-01-01T00:00:00+00:00')
        self.assertEqual(summary['last_event'], '2026-01-01T02:00:00+00:00')
        self.assertEqual(report['analysis']['events_in_rule_source_categories'], 7)
        self.assertEqual(report['analysis']['events_outside_rule_source_categories'], 1)

    def test_ip_rankings_are_bounded_and_hosts_stay_separate(self):
        events = [event(source_ip=f'192.0.2.{i}') for i in range(1, 13)]
        events.extend([event(), event(host='host-b')])
        summary = summarize(events)
        self.assertEqual(summary['unique_source_ips'], 12)
        self.assertEqual(summary['source_ip_host_groups'], 13)
        self.assertEqual(summary['repeated_source_ip_host_groups'], 1)
        self.assertEqual(len(summary['top_source_ips']), 10)
        self.assertEqual(summary['top_source_ips'][0]['event_count'], 2)
        self.assertEqual(len(summary['top_source_ips'][0]['sources']), 1)
        self.assertEqual(summary['top_source_ips'][0]['host'], 'host-a')

    def test_empty_and_single_event_reports(self):
        empty = build_report([], [])
        self.assertIsNone(empty['summary']['first_event'])
        self.assertIsNone(empty['summary']['last_event'])
        self.assertIsNone(empty['analysis']['analyzed_percent_of_available'])
        self.assertEqual(empty['summary']['message_text_bytes'], 0)
        self.assertEqual(empty['summary']['hourly_volume'], [])
        self.assertIn('No analyzed events.', render_text(empty))
        self.assertEqual(summarize([event()])['observed_span_seconds'], 0)

    def test_custom_and_disabled_rule_coverage(self):
        rule = Rule('custom', ('other',), (), 1, 60, 'host', 'low', 'Review this record.')
        events = [event('other'), event()]
        report = build_report(events, [], [rule], coverage={'events_available': 4})
        self.assertEqual(report['analysis']['analyzed_percent_of_available'], 50.0)
        self.assertEqual(report['analysis']['enabled_rules'], 1)
        self.assertEqual(report['analysis']['events_in_rule_source_categories'], 1)
        self.assertEqual(report['analysis']['rules'][0]['findings'], 1)
        self.assertEqual(report['analysis']['findings_by_severity'], {'high': 0, 'medium': 0, 'low': 1})
        disabled = build_report(events, [], [])
        self.assertEqual(disabled['findings'], [])
        self.assertEqual(disabled['analysis']['events_in_rule_source_categories'], 0)
        self.assertIn('Detection is disabled', render_text(disabled))

    def test_normalized_byte_count_and_authentication_scope(self):
        summary = summarize([event('other', 'Failed password é'), event('ssh', 'normal activity')])
        self.assertEqual(summary['message_text_bytes'], len('Failed password énormal activity'.encode('utf-8')))
        self.assertEqual(summary['authentication']['ssh']['failure_records'], 0)

    def test_json_and_text_include_statistics_and_escape_metadata(self):
        report = build_report([event(host='host\nforged', identifier='\x1b[31m')], [])
        decoded = json.loads(json.dumps(report))
        self.assertEqual(decoded['summary']['by_source']['ssh'], 1)
        text = render_text(report)
        for expected in ('Gathered data overview:', 'Records by source:', 'Journal priorities',
                         'Top hosts', 'Metadata quality', 'Authentication and network activity',
                         'Hourly volume', 'Detection coverage and configuration', 'Message matches (any):'):
            self.assertIn(expected, text)
        self.assertNotIn('\x1b', text)
        self.assertNotIn('host\nforged', text)
        self.assertIn(r'host\nforged', text)
        self.assertIn(r'\u001b[31m', text)

    def test_many_hours_are_preserved_in_json_but_bounded_in_text(self):
        base = event()
        events = [replace(base, timestamp=base.timestamp + timedelta(hours=i)) for i in range(30)]
        report = build_report(events, [])
        self.assertEqual(len(report['summary']['hourly_volume']), 30)
        self.assertEqual(sum(bucket['count'] for bucket in report['summary']['hourly_volume']), 30)
        self.assertIn('Showing the 24 busiest observed hours', render_text(report))


if __name__ == '__main__':
    unittest.main()
