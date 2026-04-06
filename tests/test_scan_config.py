# -*- coding: utf-8 -*-
from utils.scan_config import (
    get_eventlog_hours_window,
    get_eventlog_max_events,
    get_eventlog_sysmon_max_events,
)


def test_eventlog_max_defaults():
    assert 5 <= get_eventlog_max_events(50) <= 500
    assert 5 <= get_eventlog_sysmon_max_events() <= 500


def test_eventlog_hours(monkeypatch):
    monkeypatch.setenv("SACABAM_EVENTLOG_HOURS", "24")
    assert get_eventlog_hours_window() == 24.0
