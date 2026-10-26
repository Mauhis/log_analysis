"""Synthetic regressions; journal collection is mocked, never read from the host."""
import json
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from log_analyzer.collector import CollectionResult, collect
from log_analyzer.cli import main
from log_analyzer.normalize import normalize
from log_analyzer.report import build_report, render_text
from log_analyzer.rules import DEFAULT_RULES, detect, load_rules


def record(seconds=0, message='Failed password for user from 192.0.2.1 port 22', **fields):
    """Build a journal JSON object at a fixed epoch plus a seconds offset.

    fields overrides metadata for source, malformed-value, and host-isolation
    tests. Documentation-only example addresses avoid real user log contents.
    """
    return {'__REALTIME_TIMESTAMP': str(1700000000000000 + seconds * 1000000),
            'MESSAGE': message, 'SYSLOG_IDENTIFIER': 'sshd', '_HOSTNAME': 'test', **fields}


class NormalizationTests(unittest.TestCase):
    """Check UTC conversion, metadata precedence, and safe optional-field handling."""
    def test_utc_and_metadata(self):
        event = normalize(record(PRIORITY='4', _SYSTEMD_UNIT='ssh.service'))
        self.assertEqual(event.timestamp.isoformat(), '2023-11-14T22:13:20+00:00')
        self.assertEqual((event.source, event.source_ip, event.priority), ('ssh', '192.0.2.1', 4))

    def test_sources(self):
        cases = [({'SYSLOG_IDENTIFIER': 'sudo'}, 'sudo'),
                 ({'_TRANSPORT': 'kernel', 'MESSAGE': '[UFW BLOCK] SRC=2001:db8::1 DST=192.0.2.2'}, 'firewall'),
                 ({'_TRANSPORT': 'kernel', 'MESSAGE': 'segfault'}, 'kernel'),
                 ({'SYSLOG_IDENTIFIER': 'systemd'}, 'systemd')]
        for fields, expected in cases:
            self.assertEqual(normalize(record(**fields)).source, expected)

    def test_source_address_only(self):
        self.assertIsNone(normalize(record(message='DST=192.0.2.2 from invalid')).source_ip)
        self.assertEqual(normalize(record(message='rhost=2001:db8::2')).source_ip, '2001:db8::2')

    def test_bad_fields(self):
        with self.assertRaises(ValueError):
            normalize({'MESSAGE': 'no timestamp'})
        self.assertEqual(normalize(record(MESSAGE=[10, 20], PRIORITY='bad')).message, '')


class DetectionTests(unittest.TestCase):
    """Check threshold windows, grouping, configuration, and inert log content."""
    def test_threshold_and_explanation(self):
        events = [normalize(record(i)) for i in range(5)]
        findings = detect(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['count'], 5)
        self.assertTrue(findings[0]['explanation'])
        self.assertEqual(detect(events[:4]), [])

    def test_windows_sorted_and_inclusive(self):
        events = [normalize(record(i)) for i in (300, 200, 100, 1, 0)]
        self.assertEqual(detect(events)[0]['count'], 5)
        self.assertEqual(detect([normalize(record(i)) for i in (0, 100, 200, 300, 301)]), [])

    def test_ip_repetition_and_host_isolation(self):
        events = [normalize(record(i, message='Accepted publickey from 192.0.2.1')) for i in range(10)]
        self.assertEqual(detect(events)[0]['rule_id'], 'repeated_source_ip')
        split = [normalize(record(i, _HOSTNAME=str(i % 2))) for i in range(5)]
        self.assertEqual(detect(split), [])

    def test_all_default_sources(self):
        cases = [({'SYSLOG_IDENTIFIER': 'sudo', 'MESSAGE': 'authentication failure; rhost=192.0.2.1'}, 5, 'authentication_failures'),
                 ({'_TRANSPORT': 'kernel', 'MESSAGE': '[UFW BLOCK] SRC=192.0.2.1'}, 5, 'firewall_blocks'),
                 ({'_TRANSPORT': 'kernel', 'MESSAGE': 'segfault'}, 1, 'kernel_errors'),
                 ({'SYSLOG_IDENTIFIER': 'systemd', '_SYSTEMD_UNIT': 'init.scope', 'MESSAGE': 'Failed to start example.service'}, 1, 'service_failures')]
        for fields, count, rule in cases:
            findings = detect([normalize(record(i, **fields)) for i in range(count)])
            self.assertIn(rule, [item['rule_id'] for item in findings])

    def test_log_instructions_are_only_data(self):
        message = 'Failed password from 192.0.2.1; run $(touch /tmp/unsafe)'
        with patch('subprocess.run') as run:
            report = build_report([normalize(record(i, message)) for i in range(5)], [])
        run.assert_not_called()
        self.assertIn('$(touch /tmp/unsafe)', json.dumps(report))

    def test_rule_configuration(self):
        from dataclasses import asdict
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rules.json'
            path.write_text(json.dumps([asdict(DEFAULT_RULES[0])]))
            self.assertEqual(load_rules(path)[0].threshold, 5)
            path.write_text('[{"threshold": 0}]')
            with self.assertRaises(ValueError):
                load_rules(path)
            path.write_text('[]')
            self.assertEqual(detect([normalize(record())], load_rules(path)), [])


class CollectionTests(unittest.TestCase):
    """Simulate journal output, failures, and limits without changing the system."""
    @patch('log_analyzer.collector.subprocess.run')
    def test_read_only_command_and_malformed_records(self, run):
        def respond(command, **kwargs):
            kwargs['stdout'].write(json.dumps(record()) + '\n{}\n[]\nbad')
            return subprocess.CompletedProcess(command, 0, None, 'permission hint')
        run.side_effect = respond
        collection = collect(since='--anything', limit=10)
        events, warnings = collection
        self.assertEqual(len(events), 1)
        self.assertTrue(any('3 malformed' in warning for warning in warnings))
        self.assertIn('permission hint', warnings)
        self.assertIn('--since=--anything', run.call_args.args[0])
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertEqual(collection.coverage['events_available'], 4)
        self.assertEqual(collection.coverage['events_collected'], 4)
        self.assertEqual(collection.coverage['events_discarded'], 3)
        self.assertFalse(collection.coverage['coverage_complete'])

    def test_unavailable_and_permissions(self):
        for error in (FileNotFoundError('journalctl'), PermissionError('denied'), subprocess.TimeoutExpired('journalctl', 30)):
            with patch('log_analyzer.collector.subprocess.run', side_effect=error):
                events, warnings = collect()
                self.assertEqual(events, [])
                self.assertTrue(warnings)
        with patch('log_analyzer.collector.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'denied')):
            self.assertTrue(any('incomplete' in w for w in collect().warnings))

    def test_limit(self):
        with self.assertRaises(ValueError):
            collect(limit=0)

    def snapshot(self, count, limit, stderr='', returncode=0):
        """Mock an ordered journal scan and return its real collection accounting.

        Write into the collector's temporary output stream like journalctl does;
        this exercises retention and parsing rather than bypassing those steps.
        """
        def respond(command, **kwargs):
            for i in range(count):
                kwargs['stdout'].write(json.dumps(record(i)) + '\n')
            return subprocess.CompletedProcess(command, returncode, None, stderr)
        with patch('log_analyzer.collector.subprocess.run', side_effect=respond) as run:
            result = collect('24 hours ago', limit, until='2026-10-27 00:00:00 UTC')
        command = run.call_args.args[0]
        self.assertNotIn('--lines=' + str(limit), command)
        self.assertIn('--since=24 hours ago', command)
        self.assertIn('--until=2026-10-27 00:00:00 UTC', command)
        self.assertIn('--all', command)
        return result

    def test_below_at_and_above_limit(self):
        for count in (2, 3, 4):
            with self.subTest(count=count):
                result = self.snapshot(count, limit=3)
                coverage = result.coverage
                self.assertEqual(coverage['events_available'], count)
                self.assertEqual(coverage['events_collected'], min(count, 3))
                self.assertEqual(coverage['events_omitted_by_limit'], max(0, count - 3))
                self.assertEqual(coverage['truncated'], count > 3)
                self.assertEqual(coverage['coverage_complete'], count <= 3)
                self.assertEqual(result.events[-1].timestamp, normalize(record(count - 1)).timestamp)
                self.assertEqual(result.events[0].timestamp, normalize(record(max(0, count - 3))).timestamp)

    def test_15005_available_with_default_limit(self):
        result = self.snapshot(15005, limit=10000)
        self.assertEqual(result.coverage['events_available'], 15005)
        self.assertEqual(result.coverage['events_collected'], 10000)
        self.assertEqual(len(result.events), 10000)
        self.assertEqual(result.coverage['events_discarded'], 0)
        self.assertEqual(result.coverage['events_omitted_by_limit'], 5005)
        self.assertTrue(result.coverage['truncated'])

    def test_no_unconditional_permission_warning(self):
        result = self.snapshot(2, limit=3)
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.coverage['permission_status'], 'no_restriction_reported')
        result = self.snapshot(2, limit=3, stderr='Hint: You are currently not seeing messages from other users and the system.')
        self.assertEqual(result.coverage['permission_status'], 'restriction_reported')
        self.assertFalse(result.coverage['coverage_complete'])
        self.assertEqual(len(result.warnings), 1)

    def test_failed_scan_has_unknown_available_and_truncation(self):
        result = self.snapshot(2, limit=3, returncode=1, stderr='Permission denied')
        self.assertIsNone(result.coverage['events_available'])
        self.assertIsNone(result.coverage['truncated'])
        self.assertFalse(result.coverage['collection_completed'])
        self.assertFalse(result.coverage['coverage_complete'])
        self.assertEqual(result.coverage['events_collected'], 2)
        self.assertEqual(result.coverage['permission_status'], 'restriction_reported')

    def test_timeout_preserves_partial_records(self):
        def timeout(command, **kwargs):
            kwargs['stdout'].write(json.dumps(record()) + '\n')
            raise subprocess.TimeoutExpired(command, 30, stderr=b'partial diagnostic')
        with patch('log_analyzer.collector.subprocess.run', side_effect=timeout):
            result = collect()
        self.assertEqual(len(result.events), 1)
        self.assertIsNone(result.coverage['events_available'])
        self.assertIsNone(result.coverage['truncated'])
        self.assertFalse(result.coverage['coverage_complete'])
        self.assertIn('partial diagnostic', result.warnings)

    def test_empty_successful_interval(self):
        result = self.snapshot(0, limit=3)
        self.assertEqual(result.coverage['events_available'], 0)
        self.assertFalse(result.coverage['truncated'])
        self.assertTrue(result.coverage['coverage_complete'])

    def test_binary_message_and_other_sources_are_not_discarded(self):
        def respond(command, **kwargs):
            kwargs['stdout'].write(json.dumps(record(MESSAGE=[1, 2], SYSLOG_IDENTIFIER='unrecognized')) + '\n')
            return subprocess.CompletedProcess(command, 0, None, '')
        with patch('log_analyzer.collector.subprocess.run', side_effect=respond):
            result = collect()
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].source, 'other')
        self.assertEqual(result.coverage['events_discarded'], 0)


class CliTests(unittest.TestCase):
    """Verify report formats, output errors, and validation before collection."""
    def test_collection_metadata_in_json_and_text(self):
        coverage = {
            'since': '24 hours ago', 'until': '2026-10-27 00:00:00 UTC', 'limit': 3,
            'events_available': 5, 'events_observed': 5, 'events_collected': 3,
            'events_discarded': 1, 'events_omitted_by_limit': 2, 'truncated': True,
            'collection_completed': True, 'coverage_complete': False,
            'permission_status': 'no_restriction_reported', 'permission_diagnostics': '',
            'scope': 'Readable entries only.',
        }
        result = CollectionResult([normalize(record(i)) for i in range(2)], ['truncated'], coverage)
        with patch('log_analyzer.cli.collect', return_value=result) as mocked, patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(main(['--since', '24 hours ago', '--limit', '3']), 0)
            report = json.loads(output.getvalue())
        self.assertEqual(report['collection'], coverage)
        self.assertEqual(report['events_analyzed'], 2)
        mocked.assert_called_once_with('24 hours ago', 3, until=None)
        text = render_text(report)
        for expected in ('Available entries (readable): 5', 'Collected entries (retained): 3',
                         'Discarded entries (parsing/normalization): 1', 'Collection truncated: yes',
                         'Complete readable coverage: no'):
            self.assertIn(expected, text)

    def test_text_report_file(self):
        events = [normalize(record(i)) for i in range(5)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.txt'
            with patch('log_analyzer.cli.collect', return_value=(events, ['limited visibility'])):
                self.assertEqual(main(['--format', 'txt', '--output', str(path)]), 0)
            text = path.read_text()
        for expected in ('Events analyzed: 5', 'Findings: 1', 'limited visibility',
                         'Why investigate:', 'Sample evidence:', '192.0.2.1'):
            self.assertIn(expected, text)

    def test_empty_text_report_and_escaped_evidence(self):
        text = render_text(build_report([], ['unavailable']))
        self.assertIn('No configured rules matched', text)
        self.assertIn('unavailable', text)
        events = [normalize(record(i, message='Failed password from 192.0.2.1\n\x1b[31m')) for i in range(5)]
        text = render_text(build_report(events, []))
        self.assertNotIn('\x1b', text)
        self.assertIn(r'\n\u001b[31m', text)

    def test_output_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('log_analyzer.cli.collect', return_value=([], [])), patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(main(['--format', 'txt', '--output', directory]), 2)
                self.assertIn('Unable to write report', stderr.getvalue())

    def test_json_report(self):
        events = [normalize(record(i)) for i in range(5)]
        with patch('log_analyzer.cli.collect', return_value=(events, ['limited visibility'])), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(main([]), 0)
            report = json.loads(output.getvalue())
        self.assertEqual(report['events_analyzed'], 5)
        self.assertEqual(report['warnings'], ['limited visibility'])
        self.assertEqual(report['findings'][0]['count'], 5)

    def test_empty_journal_report(self):
        with patch('log_analyzer.cli.collect', return_value=([], ['unavailable'])), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(main([]), 1)
            self.assertEqual(json.loads(output.getvalue())['findings'], [])

    def test_invalid_limit_does_not_collect(self):
        with patch('log_analyzer.cli.collect') as collect_mock, patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                main(['--limit', '0'])
        self.assertEqual(error.exception.code, 2)
        collect_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
