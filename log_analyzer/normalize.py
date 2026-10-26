"""Normalize journal JSON; log content is always treated as data."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import re


@dataclass(frozen=True)
class Event:
    """Immutable input shared by detection and reporting.

    timestamp is an aware UTC datetime. source is the analyzer's category;
    identifier/unit/host preserve journal metadata as strings. priority is a
    syslog level (0..7) or None. source_ip is a canonical literal address, never
    a DNS resolution or independently verified attribution.
    """
    timestamp: datetime
    source: str
    message: str
    host: str
    unit: str
    identifier: str
    priority: int | None
    source_ip: str | None

    def to_dict(self):
        """Return JSON-ready metadata, converting the datetime to ISO 8601."""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


def normalize(record):
    """Convert one decoded journal object into an Event without executing text.

    A valid __REALTIME_TIMESTAMP is required. Missing/non-string text fields
    become empty strings; unknown sources remain analyzable as 'other'. Invalid
    timestamps raise conversion errors for the collector to count as discards.
    """
    stamp = record.get('__REALTIME_TIMESTAMP')
    if not isinstance(stamp, str) or not stamp.isdecimal():
        raise ValueError('Missing or invalid journal timestamp')
    # Journal realtime timestamps are integer microseconds since the Unix epoch.
    # Integer splitting preserves subsecond precision without a float round-trip.
    seconds, micros = divmod(int(stamp), 1_000_000)
    timestamp = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=micros)
    def field(name):
        """Read string fields; journal JSON can also contain arrays/binary data.

        Such values are not decoded here. The record itself is still retained,
        but a non-string MESSAGE contributes no text to substring matching.
        """
        value = record.get(name, '')
        return value if isinstance(value, str) else ''
    message = field('MESSAGE')
    identifier = field('SYSLOG_IDENTIFIER')
    unit = field('_SYSTEMD_UNIT')
    # Kernel transport takes precedence over identifiers; firewall messages are
    # a subset of kernel events identified by common packet-log markers.
    if record.get('_TRANSPORT') == 'kernel':
        source = 'firewall' if re.search(r'\b(?:UFW|IN=|SRC=)', message) else 'kernel'
    elif identifier in ('sshd', 'sshd-session') or unit in ('ssh.service', 'sshd.service'):
        source = 'ssh'
    elif identifier == 'sudo':
        source = 'sudo'
    elif identifier == 'systemd':
        source = 'systemd'
    else:
        source = 'other'
    source_ip = None  # Missing or invalid labelled addresses do not form IP groups.
    # Only source-labelled fields: do not confuse a destination with an attacker.
    for match in re.finditer(r'(?:\bSRC=|\bfrom\s+|\brhost=)([^\s]+)', message):
        try:
            source_ip = str(ipaddress.ip_address(match[1].strip('[],')))
            break
        except ValueError:
            # A hostname or malformed candidate may precede a usable address.
            continue
    priority = field('PRIORITY')  # Preserve only the defined syslog levels 0..7.
    return Event(timestamp, source, message, field('_HOSTNAME'), unit, identifier,
                 int(priority) if priority in tuple(str(n) for n in range(8)) else None,
                 source_ip)
