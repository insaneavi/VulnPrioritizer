from datetime import datetime
from zoneinfo import ZoneInfo
import os

LOCAL_TZ = os.environ.get("TZ", "America/New_York")

def display_time(value):
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(ZoneInfo(LOCAL_TZ)).strftime("%b %d, %Y %I:%M:%S %p %Z")
    except Exception:
        return str(value)
