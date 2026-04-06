# -*- coding: utf-8 -*-
from web import app as app_module


def test_safe_history_rejects_traversal():
    assert app_module._safe_history_path(r"..\scan_x.json") is None
    assert app_module._safe_history_path("scan_1.json/../x") is None


def test_safe_history_accepts_scan_json():
    p = app_module._safe_history_path("scan_20250101_120000.json")
    assert p is not None
    assert p.replace("\\", "/").endswith("scan_20250101_120000.json")


def test_safe_history_rejects_non_scan_pattern():
    assert app_module._safe_history_path("evil.json") is None
    assert app_module._safe_history_path("scan.json") is None
