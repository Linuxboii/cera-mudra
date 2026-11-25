"""Human-friendly rendering of JWT NumericDate claims and duration parsing."""

from __future__ import annotations

import datetime as _dt
import re
import time

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> int:
    """'90' -> 90, '15m' -> 900, '2h' -> 7200, '7d', '1w'. Compound '1h30m' works too."""
    text = str(text).strip().lower()
    if text.isdigit():
        return int(text)
    parts = re.findall(r"(\d+)\s*([smhdw])", text)
    if not parts or "".join(n + u for n, u in parts) != re.sub(r"\s+", "", text):
        raise ValueError(f"invalid duration {text!r} (examples: 3600, 30m, 12h, 7d)")
    return sum(int(n) * _UNITS[u] for n, u in parts)


def humanize_seconds(seconds: float) -> str:
    seconds = int(abs(seconds))
    for unit, size in (("year", 31536000), ("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = seconds // size
            return f"{n} {unit}{'' if n == 1 else 's'}"
    return f"{seconds} second{'' if seconds == 1 else 's'}"


def format_utc(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def describe_timestamp(ts, now: float | None = None) -> str:
    now = time.time() if now is None else now
    try:
        ts = float(ts)
        absolute = format_utc(ts)
    except (TypeError, ValueError, OverflowError, OSError):
        return f"{ts!r} (not a valid NumericDate)"
    delta = ts - now
    if abs(delta) < 1:
        rel = "now"
    elif delta > 0:
        rel = f"in {humanize_seconds(delta)}"
    else:
        rel = f"{humanize_seconds(delta)} ago"
    return f"{absolute} ({rel})"
