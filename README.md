# Linux log analyzer

A Python 3.10+ standard-library-only journal analyzer intended for Ubuntu 24.04.
It reads SSH, sudo, kernel, UFW firewall, and systemd messages visible to the
current user. It never elevates privileges, changes services or firewall rules,
or executes log content. Its only system command is read-only `journalctl`.

## Quick start

Requires Python 3.10+ and an available `journalctl` command. Python 3.12 on Ubuntu
24.04 meets the Python requirement. Runtime and test code use only the standard
library; running from the project directory needs no package installation.

Clone the repository and run from its directory:

```sh
git clone https://github.com/Mauhis/log_analysis.git
cd log_analysis
```

Create a report:

```sh
python3 -m log_analyzer --since '1 hour ago' --limit 10000 > report.json
python3 -m log_analyzer --since '1 hour ago' --format txt --output report.txt
python3 -m log_analyzer --since '24 hours ago' --limit 100000 --format txt --output report-24h.txt
```

The default command `python3 -m log_analyzer` analyzes **one hour**, retaining up
to **10,000 entries**. For a 24-hour report, specify both the interval and a limit
large enough for your journal, as in the third example above.

## Command-line reference

| Option | Default | Purpose |
| --- | --- | --- |
| `--since DATE` | `1 hour ago` | Beginning of the requested journal interval. |
| `--until DATE` | Collection start time in UTC | Fixed end of the requested interval. |
| `--limit N` | `10000` | Retain the newest N records; allowed range is 1–100000. The interval is still scanned to count availability. |
| `--rules PATH` | Built-in rules | Replace all default rules with a validated JSON rule list. |
| `--format json\|txt` | `json` | Select machine-readable JSON or readable text. |
| `--output PATH` | Standard output | Write to a UTF-8 file, overwriting any existing file at that path. |
| `--help` | — | Show command usage without collecting logs. |

Date values are interpreted by journalctl; include an explicit timezone for
repeatable comparisons. For example, these commands request the same interval:

```sh
python3 -m log_analyzer --since '2026-10-25 00:00:00 UTC' --until '2026-10-26 00:00:00 UTC' --limit 100000
journalctl --no-pager --all --output=json --since='2026-10-25 00:00:00 UTC' --until='2026-10-26 00:00:00 UTC'
```

Count JSON records when comparing; ordinary journal output can contain headings
or multiline messages that make a plain line count misleading.

JSON goes to stdout by default. Use `--format txt` for a readable text report with
counts, warnings, findings, investigation explanations, and sample evidence.
`--output PATH` writes either format to a UTF-8 file, overwriting it if it exists;
relative paths use your current directory. If you have configured the
`log-analyzer` shell alias, it accepts the same options from any directory.
Control characters in text evidence and metadata are escaped to keep log content
inert. Generated `report*.txt`, `report*.json`, and files inside `reports/` are
excluded from Git by the project's `.gitignore`.
Exit status 1 means no usable events were collected; 2 means invalid
arguments/configuration or an output error; 0 means events were analyzed,
including when findings exist. A partial scan with usable events also returns 0:
inspect collection coverage and warnings instead of using exit status as a
completeness or security verdict. Journal errors and observed permission
diagnostics are included in report warnings. Root is not required;
the application does not change permissions. A normal account may have little
or no access to system logs. Empty results do not establish absence of threats.

## Detailed report contents

Both JSON and text reports include a collection overview, descriptive statistics,
detection configuration, and findings with investigation explanations. Generate
a detailed 24-hour report:

```sh
python3 -m log_analyzer --since '24 hours ago' --limit 100000 --format txt --output report-detailed-24h.txt
```

| Report area | Included information |
| --- | --- |
| Collection coverage | Requested interval, available/observed/retained/analyzed counts, parsing discards, limit omissions, completion, truncation, permission diagnostics. |
| Actual data range | Earliest and latest analyzed timestamps, observed span, and analyzed percentage of readable availability when known. |
| Volume and sources | Record counts and text-report percentages for SSH, sudo, firewall, kernel, systemd, and other records. |
| Journal priorities | Emergency through debug counts plus unknown priority; these are distinct from detector finding severities. |
| Hosts and emitters | Distinct populated hosts, units, and identifiers, plus the ten most frequent values for each. |
| Metadata quality | Missing/empty host, unit, identifier, message, and priority counts after normalization. |
| Authentication indicators | SSH and sudo failure records, SSH accepted-credential records, and sudo session-open records. |
| Network indicators | UFW block/reject records, extracted source-IP counts, distinct IPs, repeated IP/host groups, and the ten busiest groups with source categories and failure/block counts in JSON. |
| Hourly volume | Observed UTC hourly buckets. Text shows at most the 24 busiest hours; JSON keeps every observed bucket. |
| Detection scope | Enabled rule definitions, per-rule finding totals, findings by severity, and records inside/outside configured source categories. |
| Text size | UTF-8 bytes in normalized message text, excluding journal metadata and storage overhead. |

Statistics describe **analyzed records only**. A truncated sample can look quite
different from the full requested interval. Rankings are ordered by count with
deterministic ties; totals and distinct counts include entries outside the top
ten. Missing metadata is counted separately from populated-value rankings.
The observed timestamp span is not a measure of continuous coverage or uptime.
Unobserved hourly buckets are omitted, and boundary hours can be partial.

Authentication indicators use English substring heuristics and count records,
not unique attempts, accounts, or sessions. Several failure phrases in one record
count once. Success/session-open indicators do not prove a privileged command
succeeded. Repeated addresses are grouped separately per host and can represent
normal activity, shared addresses, or spoofed log text. No DNS lookups are made.

JSON reports use **schema version 3**, with `collection`, `summary`, `analysis`,
`findings`, and `warnings` fields alongside report timestamps, analyzed-event
counts, and interpretation guidance. `summary` contains descriptive statistics;
`analysis` contains rule configuration and detector coverage.
`analyzed_percent_of_available` is null when availability is unknown or zero.
Source-category eligibility does not imply a message matched a predicate,
grouping field, or alert threshold. Finding totals are not unique event totals:
rules may overlap. An empty rule list explicitly reports disabled detection.

## Detection and configuration

| Rule ID | Sources | Threshold in 300 seconds | Grouping |
| --- | --- | --- | --- |
| `authentication_failures` | SSH and sudo | 5 matching records | Host |
| `repeated_source_ip` | SSH, sudo, firewall | 10 records, including successful activity | Source IP within host |
| `firewall_blocks` | Firewall | 5 UFW block/reject records | Source IP within host |
| `kernel_errors` | Kernel | 1 fault/resource-exhaustion record | Host |
| `service_failures` | systemd | 1 service-failure record | Emitting unit within host |

Thresholds are configurable heuristics, not statistical baselines.
Findings include explanations and up to three normalized
evidence entries. Protect reports because log messages may contain private data.

Override the full rule list using `--rules rules.json`. An empty list disables
detection. Each rule uses literal, case-insensitive substring matching (any listed
substring matches); an empty `contains` array matches every event in its sources.
No expressions, scripts, plugins, or commands are accepted in rules.

```json
[
  {
    "id": "ssh_failures",
    "sources": ["ssh"],
    "contains": ["failed password", "authentication failure", "invalid user"],
    "threshold": 5,
    "window_seconds": 300,
    "group_by": "source_ip",
    "severity": "high",
    "explanation": "Repeated SSH failures may indicate password guessing. Check whether the source and account are expected."
  }
]
```

Sources: `ssh`, `sudo`, `firewall`, `kernel`, `systemd`, `other`.
Grouping: `host`, `source_ip`, `unit`. Severity: `low`, `medium`, `high`.
Threshold and window must be positive integers; IDs must be unique.
Groups always stay separate across hosts. Missing group fields are skipped.
Events are sorted in UTC; windows include both endpoints. Each rule/group emits
one finding for its highest-count window, rather than flooding the report with
overlapping alerts. Counts describe journal records, which may include multiple
records for a single authentication attempt. Equal-count windows keep the earlier
finding. Evidence shows up to the first three matching records in the chosen
window, so it is a sample rather than a complete event export.

## Scope and limitations

This is a snapshot tool, not a continuous daemon. The default interval is **one
hour**, not 24 hours. It retains the latest 10,000 records by default (maximum
100,000) with a 30-second collection timeout. `--until` can specify a fixed end;
otherwise the collector fixes the end at collection start. Use identical absolute
`--since` and `--until` values when comparing with a manual journal count.

The collector scans the requested readable interval once, spooling JSON to a
private temporary file, and retains the newest `--limit` records for normalization
and analysis. This provides exact availability counts after successful collection
without loading the full interval into RAM. The temporary file is removed on
close. Very large intervals can consume temporary disk space and time; retained
large messages can still consume significant memory. `--all` prevents journalctl
from eliding long field values. No service, priority, or source filters are applied.

The JSON `collection` object and text report display the same coverage
information:

- `events_available`: raw readable entries in the requested interval, or `null`
  when the scan failed or timed out. This is not a count of inaccessible logs.
- `events_observed`: entries actually returned, including during a partial scan.
- `events_collected`: entries retained after applying the limit.
- `events_discarded`: retained entries rejected during JSON parsing/normalization.
- `events_omitted_by_limit`: observed entries not retained because of the cap.
- Top-level `events_analyzed`: successfully normalized entries passed to analysis,
  including source `other`, regardless of whether any detection rule matches.
- `truncated`: true only when observed entries exceed the limit; false for a
  successful scan at or below the limit; null if incomplete and not proven.
- `coverage_complete`: true only for a successful scan with no truncation,
  rejected records, or reported permission restriction, within the readable scope.

The counts obey `events_collected = events_analyzed + events_discarded`. Malformed
records outside the retained sample are omitted by the limit, not counted as
parsing discards. On failure, any captured partial records are still analyzed,
but the available count and complete interval remain unknown.

There is no unconditional permission warning and group membership is not used
to infer full access. Actual journal diagnostics are preserved. The permission
status distinguishes a reported restriction, no reported restriction, and an
unknown result after collection failure. No reported restriction does not prove
access to every system journal. Journald rotation, permissions, and disabled
logging can hide events. No permission or system configuration changes are made.
Restriction recognition currently uses common English stderr phrases; localized
or unfamiliar diagnostics are preserved but may not be classified as permission
restrictions. `permission_diagnostics` contains all stderr, not only access errors.

Classification uses journal metadata and common English messages. Firewall
support currently recognizes kernel UFW/IN=/SRC= messages; other firewall formats
need tailored normalization. IP extraction uses source-labelled literal IPv4 or
IPv6 addresses, without DNS lookup. Arbitrary log text can spoof those fields;
findings warrant investigation and do not establish attribution or compromise.
Systemd grouping uses the emitting journal unit, which may be `init.scope`, rather
than the failed service named in the message. No machine learning or AI services
are used.

Non-string journal text fields, including binary/array-valued `MESSAGE`, normalize
to empty strings. Those entries still count as analyzed, but their omitted text
cannot match substring rules. Missing or invalid timestamps reject a retained
record. Collection timeout applies to the journal command, not the later parsing
and detection steps. No automatic scheduling or continuous alert delivery is
implemented.

## Code structure and data flow

| File | Responsibility and main interfaces |
| --- | --- |
| `log_analyzer/__main__.py` | Module entry point; passes the CLI result to the process exit status. |
| `log_analyzer/cli.py` | `main(argv=None)` validates options/rules, coordinates one scan, and writes the chosen format. |
| `log_analyzer/collector.py` | `collect(...)` runs journalctl, retains a bounded sample, and returns a `CollectionResult` with events, warnings, and coverage. |
| `log_analyzer/normalize.py` | `normalize(record)` converts a decoded journal object into immutable `Event` metadata; `Event.to_dict()` prepares JSON-compatible output. |
| `log_analyzer/rules.py` | `Rule` describes a detector; `load_rules(path)` validates configuration; `detect(events, rules=None)` applies sliding windows. |
| `log_analyzer/summary.py` | `summarize(events)` computes descriptive totals, metadata quality, hourly volume, and bounded rankings without reading additional logs. |
| `log_analyzer/report.py` | `build_report(...)` creates the shared report dictionary; `render_text(report)` formats that dictionary for people. |
| `tests/test_analyzer.py` | Synthetic fixtures and mocked journal processes cover collection, normalization, rules, reports, and CLI errors. |
| `tests/test_reports.py` | Mixed-source fixtures verify summary totals, authentication indicators, bounded rankings, empty input, custom rules, and safe text rendering. |
| `INVESTIGATION.md` | Documents the original one-hour versus 24-hour count discrepancy and verification results. |

The processing sequence is:

1. Validate command-line arguments and the complete rule configuration.
2. Scan the readable interval into a temporary file and count observed records.
3. Retain the newest N raw records and normalize them, counting rejected records.
4. Sort accepted events by UTC timestamp and evaluate matching rules per group.
5. Summarize analyzed metadata, build a schema-version-3 report, and serialize it
   as JSON or text.

`CollectionResult` supports `events, warnings = collect(...)` for compatibility;
use its `.coverage` attribute for accounting. `build_report` accepts optional
coverage for callers working with synthetic input; its `collection` field is
`null` when metadata is absent. Passing `None` for rules uses defaults, while
passing `[]` disables detection. Neither detection nor rendering runs commands.

## Development and tests

```sh
python3 -m unittest discover -s tests -v
```

Tests use documentation IP addresses, fixed synthetic timestamps, temporary report
files, and mocked subprocess output. They do not require journal access, root,
network access, or changes to services. Coverage includes inclusive window
boundaries, host isolation, limits below/at/above capacity, 15,005 available
entries, malformed JSON/metadata, permission diagnostics, partial timeouts, inert
log text, and both output formats.

To extend support, add journal-field handling in `normalize.py`, then add synthetic
fixtures that exercise the format. Add configurable literal-match rules through
JSON, or update `DEFAULT_RULES` when a new built-in heuristic is warranted.
Changes to coverage or summary fields should update both renderers' expectations,
this README, and accounting tests. Keep user-supplied messages and rules as data;
do not add shell execution or automatic system remediation.
