# -*- coding: utf-8 -*-
"""web.app._safe_history_path: 履歴ファイルパス検証"""
import os

import web.app as app


def test_safe_history_basename_only(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr(app, "LOG_DIR", str(log_dir))
    fn = "scan_20240101_120000.json"
    resolved = app._safe_history_path(fn)
    assert resolved is not None
    assert os.path.basename(resolved) == fn


def test_safe_history_rejects_traversal(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr(app, "LOG_DIR", str(log_dir))
    assert app._safe_history_path("../scan_x.json") is None
    assert app._safe_history_path("a/b.json") is None
    assert app._safe_history_path("..") is None
