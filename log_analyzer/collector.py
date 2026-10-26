"""Read-only snapshot collection with explicit coverage accounting."""
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import subprocess
import tempfile
from .normalize import normalize


@dataclass
class CollectionResult:
    """Keep normalized input, user-facing diagnostics, and coverage together.

    events contains only records accepted by normalize(); warnings explains
    collection or parsing problems. coverage contains raw-record accounting and
    tri-state truncation information for the report, independent of rule matches.
    """
    events: list
    warnings: list
    coverage: dict

    def __iter__(self):
        """Preserve the original events, warnings unpacking interface."""
        yield self.events
        yield self.warnings


def collect(since='1 hour ago', limit=10000, timeout=30, until=None):
    """Collect a journal interval as the current user, retaining its newest records.

    since/until are journalctl date expressions; an omitted until is fixed at
    collection start. limit caps retained records, not the number scanned, so a
    successful scan can report exact readable availability. timeout bounds the
    journalctl subprocess in seconds, not normalization or rule evaluation.

    Return a CollectionResult, preserving captured records after command failure
    or timeout. Invalid limits raise ValueError; command and record errors become
    warnings. Availability never includes journals inaccessible to this user.
    """
    # bool is an int subclass, but is not a meaningful record limit.
    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError('limit must be between 1 and 100000')
    until = until or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    # Argument-list execution avoids a shell. Date expressions remain argument
    # values, and --all preserves large fields. No source or priority filter is
    # applied: classification and rule matching happen after collection.
    command = ['journalctl', '--no-pager', '--all', '--output=json',
               '--since=' + since, '--until=' + until]
    warnings = []
    selected = deque(maxlen=limit)  # Newest raw lines; oldest drop automatically.
    read_count = 0  # All nonempty output lines, including those omitted by limit.
    completed = False  # Only a zero journalctl exit confirms a finished scan.
    diagnostics = ''  # Preserve stderr instead of guessing access from groups.
    # Scan once to count the readable interval. Spool to a temporary file rather
    # than keeping an unbounded response in RAM; retain only the newest N.
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8', errors='replace') as output:
        try:
            result = subprocess.run(command, stdout=output, stderr=subprocess.PIPE,
                                    text=True, encoding='utf-8', errors='replace',
                                    timeout=timeout, check=False)
            diagnostics = result.stderr.strip()
            completed = result.returncode == 0
            if not completed:
                warnings.append(f'journalctl exited with status {result.returncode}; coverage is incomplete.')
        except subprocess.TimeoutExpired as exc:
            # subprocess.run stops the child on timeout. Its temporary-file
            # output remains readable, and captured stderr may still be bytes.
            diagnostics = exc.stderr or ''
            if isinstance(diagnostics, bytes):
                diagnostics = diagnostics.decode('utf-8', errors='replace')
            warnings.append('Journal collection timed out; available count is unknown and coverage is incomplete.')
        except OSError as exc:
            warnings.append(f'Journal collection unavailable: {exc}')
        if diagnostics:
            warnings.append(diagnostics)
        output.seek(0)
        for line in output:
            if line.strip():
                read_count += 1
                selected.append(line)
    events = []  # Successfully normalized retained records, including 'other'.
    malformed = 0  # Rejections in the retained sample, not in omitted older data.
    for line in selected:
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError('Expected object')
            events.append(normalize(record))
        except (ValueError, TypeError, OverflowError, OSError):
            malformed += 1
    if malformed:
        warnings.append(f'Skipped {malformed} malformed journal records.')
    # Exactly hitting the cap does not prove truncation. On a failed scan, fewer
    # observed records cannot establish whether more entries were available.
    truncated = read_count > limit if completed else (True if read_count > limit else None)
    if truncated:
        warnings.append(f'Collection truncated: retained the newest {limit} of {read_count} observed entries.')
    if not events:
        warnings.append('No analyzable journal events in the requested interval.')
    # Recognize common English journal diagnostics, preserving the original text
    # for other/localized messages. Absence of a match does not prove full access.
    restricted = any(term in diagnostics.casefold() for term in (
        'permission denied', 'insufficient permissions', 'not seeing messages',
        'access denied', 'not permitted'))
    # Accounting: collected = len(events) + discarded; observed = collected +
    # omitted_by_limit. Complete coverage refers only to this readable interval.
    return CollectionResult(events, warnings, {
        'since': since, 'until': until, 'limit': limit,
        'events_available': read_count if completed else None,
        'events_observed': read_count,
        'events_collected': len(selected),
        'events_discarded': malformed,
        'events_omitted_by_limit': read_count - len(selected),
        'truncated': truncated,
        'collection_completed': completed,
        'coverage_complete': completed and not truncated and not malformed and not restricted,
        'permission_status': ('restriction_reported' if restricted else
                              'no_restriction_reported' if completed else 'unknown'),
        'permission_diagnostics': diagnostics,
        'scope': 'Entries readable by the current user; access to all system journals is not verified.',
    })
