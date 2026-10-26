"""Command-line orchestration: validate, collect, analyze, and write a report."""
import argparse
import json
import sys
from .collector import collect
from .report import build_report, render_text
from .rules import load_rules


def main(argv=None):
    """Run one snapshot analysis, accepting an optional argument list for tests.

    None lets argparse read the process arguments. Return 0 when at least one
    event was analyzed, 1 for no analyzable events, or 2 for output failure.
    argparse raises SystemExit(2) for invalid arguments/rule configuration.
    Collection warnings and findings do not independently change the exit code.
    """
    parser = argparse.ArgumentParser(description='Read-only journald security report')
    parser.add_argument('--since', default='1 hour ago', help='Start of interval (default: 1 hour ago)')
    parser.add_argument('--until', help='End of interval (default: collection start time)')
    parser.add_argument('--limit', type=int, default=10000, help='Newest entries to retain for analysis (default: 10000; maximum: 100000)')
    parser.add_argument('--rules', help='JSON rule configuration')
    parser.add_argument('--format', choices=('json', 'txt'), default='json', help='Report format (default: json)')
    parser.add_argument('--output', help='Write report to this file instead of stdout (overwrites existing file)')
    args = parser.parse_args(argv)
    # Validate configuration before reading logs, so invalid rules do not trigger
    # an unnecessary journal scan. None means defaults; [] means no detectors.
    try:
        if not 1 <= args.limit <= 100000:
            raise ValueError('limit must be between 1 and 100000')
        rules = load_rules(args.rules) if args.rules else None
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    collection = collect(args.since, args.limit, until=args.until)
    events, warnings = collection
    # Legacy callers/tests may supply only an (events, warnings) pair. Real
    # CollectionResult objects also carry detailed coverage for both formats.
    report = build_report(events, warnings, rules, coverage=getattr(collection, 'coverage', None))
    content = render_text(report) if args.format == 'txt' else json.dumps(report, indent=2, ensure_ascii=True) + '\n'
    try:
        if args.output:
            # User-selected report files are the persistent write performed by
            # the application. Relative paths follow the caller's working dir.
            with open(args.output, 'w', encoding='utf-8') as stream:
                stream.write(content)
        else:
            sys.stdout.write(content)
    except OSError as exc:
        print(f'Unable to write report: {exc}', file=sys.stderr)
        return 2
    # Success describes processed input, not security state or complete coverage.
    return 0 if events else 1
