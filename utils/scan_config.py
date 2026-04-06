# -*- coding: utf-8 -*-
"""スキャン環境変数（イベントログ件数・時間窓など）。"""
import os

_EVENTLOG_MAX_DEFAULT = 50
_EVENTLOG_SYSMON_MAX_DEFAULT = 40


def get_eventlog_max_events(default=None):
    """SACABAM_EVENTLOG_MAX: 既定ログ用の MaxEvents（5〜500）。"""
    d = default if default is not None else _EVENTLOG_MAX_DEFAULT
    try:
        v = int(os.environ.get("SACABAM_EVENTLOG_MAX", str(d)))
        return max(5, min(500, v))
    except ValueError:
        return d


def get_eventlog_sysmon_max_events():
    """SACABAM_EVENTLOG_SYSMON_MAX: Sysmon 専用（省略時 40）。"""
    try:
        v = int(os.environ.get("SACABAM_EVENTLOG_SYSMON_MAX", str(_EVENTLOG_SYSMON_MAX_DEFAULT)))
        return max(5, min(500, v))
    except ValueError:
        return _EVENTLOG_SYSMON_MAX_DEFAULT


def get_eventlog_hours_window():
    """
    SACABAM_EVENTLOG_HOURS: 直近 N 時間のみ取得（省略で全期間から MaxEvents 件）。
    正の数のみ（最大 720 = 30 日）。
    """
    raw = os.environ.get("SACABAM_EVENTLOG_HOURS", "").strip()
    if not raw:
        return None
    try:
        h = float(raw)
        if h <= 0:
            return None
        return min(h, 24 * 30)
    except ValueError:
        return None
