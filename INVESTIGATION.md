# Event-count discrepancy

The original CLI and collector both defaulted to `--since '1 hour ago'`. Comparing
that report with a manual 24-hour count compares different intervals. The original
collector also passed `--lines=10000`, silently excluding older entries except for
a generic limit warning. It applied no source, unit, priority, or boot filters.

Before modifying code, a read-only check under the current user used a shared
upper bound of `2026-10-26 22:05:22 UTC` and found:

| Requested interval | Raw entries | Successfully normalized | Parsing errors |
| --- | ---: | ---: | ---: |
| One hour | 132 | 132 | 0 |
| 24 hours | 15,858 | 15,858 | 0 |

Neither command emitted stderr or failed. The current user's groups included
`adm`. This supports the one-hour default as the explanation for the earlier
270-entry report. The exact earlier interval cannot be reconstructed from that
number alone. These current counts naturally differ from earlier manual counts
as the journal and rolling interval change. The supplied normal-versus-sudo
counts differ by only two entries; they do not explain a gap of roughly 14,700.
No privileged comparison was run during this investigation.

All 15,858 readable records passed the original normalizer. Unknown source types
are retained as `other`; detection rules do not remove them from the analyzed
count. Missing/invalid timestamps and invalid JSON can discard records, but no
such failures occurred in this check. A 24-hour run with the old default cap
would analyze at most 10,000 entries even with full readable access.

The old warning about current-user visibility was appended unconditionally;
it was not the result of a permission check. The revised collector preserves
journal diagnostics, reports the interval and separate counts, distinguishes
limit omissions from parsing discards, and marks incomplete collection explicitly.
Availability always means entries readable by the current user, not inaccessible
system logs. The one-hour default is retained and is now explicit in CLI help
and both report formats.

Post-change verification used the fixed UTC interval `2026-10-25 22:08:42` through
`2026-10-26 22:08:42`. Manual journal output contained 15,883 records. Both CLI
runs reported exactly that availability:

| Limit | Collected | Analyzed | Parsing discards | Limit omissions | Truncated |
| ---: | ---: | ---: | ---: | ---: | --- |
| 10,000 | 10,000 | 10,000 | 0 | 5,883 | yes |
| 100,000 | 15,883 | 15,883 | 0 | 0 | no |

Neither run reported permission restrictions. The full run produced
`report-24h.txt`. All 27 automated tests passed, including exact-limit boundaries,
malformed records, 15,005-entry availability, permission diagnostics, partial
timeouts, and JSON/text coverage reporting.
