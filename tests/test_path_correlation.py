# -*- coding: utf-8 -*-
from utils.path_correlation import find_path_correlations


def test_find_path_correlations_same_exe_two_categories():
    scan = {
        "processes": [
            {"path": r"C:\Temp\evil.exe", "status": "WARNING", "is_self": False},
        ],
        "evidence": [
            {"artifact": r"c:\temp\evil.exe", "status": "DANGER", "is_self": False},
        ],
        "pca": [],
        "cam": [],
        "persistence": [],
        "binrename": [],
        "ads": [],
        "lnk": [],
    }
    out = find_path_correlations(scan)
    assert len(out) >= 1
    assert "processes" in out[0]["categories"]
    assert "evidence" in out[0]["categories"]


def test_find_path_correlations_self_excluded():
    scan = {
        "processes": [
            {"path": r"C:\Tools\app.exe", "status": "DANGER", "is_self": True},
        ],
        "evidence": [
            {"artifact": r"C:\Tools\app.exe", "status": "DANGER", "is_self": False},
        ],
    }
    out = find_path_correlations(scan)
    assert out == []
