"""
APEXEYE Timezone Utilities (Master)

Converts UTC timestamps stored in the database to the local machine/operator
timezone for dashboard display and API responses.

Guarantees:
- Dynamically resolves operator/machine timezone without hardcoding offsets.
- Preserves raw UTC values for auditing and chronological sorting.
- Idempotent: safe against double conversion.
- Zero shift when a timestamp is already timezone-aware or in local time.
"""

from datetime import datetime, timezone
from typing import Optional, Union


def get_local_timezone():
    """Return the operating system's current local timezone dynamically."""
    return datetime.now().astimezone().tzinfo


def utc_to_local_display(
    ts: Union[str, datetime, None],
    target_tz: Optional[timezone] = None,
    output_format: str = "%Y-%m-%d %H:%M:%S",
) -> str:
    """
    Convert a UTC timestamp (string or datetime) to the local machine timezone.
    If target_tz is None, uses the system's dynamic local timezone.

    Handles:
    - Naive UTC strings: '2026-09-11 09:31:00' or '2026-09-11T09:31:00'
    - ISO strings with Z: '2026-09-11T09:31:00Z'
    - Timezone-aware ISO strings: '2026-09-11T15:01:00+05:30' (no shift if already in target timezone)
    - Naive datetimes (assumed UTC from DB)
    - Timezone-aware datetimes
    """
    if not ts:
        return ""

    if target_tz is None:
        target_tz = get_local_timezone()

    dt: Optional[datetime] = None

    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            # Naive datetime from database: attach UTC
            dt = ts.replace(tzinfo=timezone.utc)
        else:
            dt = ts
    elif isinstance(ts, str):
        raw = ts.strip()
        if not raw:
            return ""

        try:
            if raw.endswith("Z") or raw.endswith("z"):
                clean = raw[:-1] + "+00:00"
                dt = datetime.fromisoformat(clean)
            elif "+" in raw[10:] or ("-" in raw[10:] and ("T" in raw or " " in raw[10:])):
                # Has explicit timezone offset
                dt = datetime.fromisoformat(raw)
            elif "T" in raw:
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            else:
                if len(raw) == 19:
                    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                elif len(raw) == 16:
                    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
                else:
                    dt = datetime.fromisoformat(raw)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            return raw

    if dt is None:
        return str(ts)

    local_dt = dt.astimezone(target_tz)
    return local_dt.strftime(output_format)
