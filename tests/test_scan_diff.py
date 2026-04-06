# -*- coding: utf-8 -*-
"""utils/scan_diff: スキャン JSON 差分"""
from utils.scan_diff import diff_scans


def _proc(path, name="x.exe", pid=1):
    return {"path": path, "name": name, "pid": pid, "status": "WARNING"}


def test_diff_processes_added_removed():
    old = {"processes": [_proc(r"C:\a\old.exe")], "system": {"scan_time": "t0", "hostname": "h"}}
    new = {"processes": [_proc(r"C:\b\new.exe")], "system": {"scan_time": "t1", "hostname": "h"}}
    d = diff_scans(old, new)
    assert len(d["added"]["processes"]) == 1
    assert r"C:\b\new.exe" in d["added"]["processes"][0]["path"]
    assert len(d["removed"]["processes"]) == 1
    assert d["stats"]["processes"]["added"] == 1
    assert d["stats"]["processes"]["removed"] == 1


def test_diff_empty_baseline():
    new = {"processes": [_proc(r"C:\x\p.exe")], "system": {}}
    d = diff_scans(None, new)
    assert len(d["added"]["processes"]) == 1
    assert d["meta"]["baseline_scan_time"] is None


def test_diff_meta_times():
    a = {"system": {"scan_time": "A", "hostname": "ha"}}
    b = {"system": {"scan_time": "B", "hostname": "hb"}}
    d = diff_scans(a, b)
    assert d["meta"]["baseline_scan_time"] == "A"
    assert d["meta"]["current_scan_time"] == "B"
