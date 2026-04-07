# -*- coding: utf-8 -*-
from unittest.mock import patch

import pytest


@pytest.fixture
def no_path_corr():
    with patch("web.app.find_path_correlations", return_value=[]), patch(
        "web.app.find_path_correlations_info_tier", return_value=[]
    ):
        yield


def _cat(name, danger=0, warning=0, info=0, safe=1):
    items = []
    for _ in range(danger):
        items.append({"status": "DANGER", "is_self": False})
    for _ in range(warning):
        items.append({"status": "WARNING", "is_self": False})
    for _ in range(info):
        items.append({"status": "INFO", "is_self": False})
    for _ in range(safe):
        items.append({"status": "SAFE", "is_self": False})
    return {name: items}


def test_clean_empty_scan(no_path_corr):
    from web.app import calculate_threat_score

    r = calculate_threat_score({})
    assert r["level"] == "CLEAN"
    assert r["danger_category_count"] == 0


def test_medium_one_danger_category(no_path_corr):
    from web.app import calculate_threat_score

    data = _cat("processes", danger=1, safe=0)
    r = calculate_threat_score(data)
    assert r["level"] == "MEDIUM"
    assert r["danger_category_count"] == 1


def test_high_three_categories(no_path_corr):
    from web.app import calculate_threat_score

    data = {}
    data.update(_cat("processes", danger=1, safe=0))
    data.update(_cat("networks", danger=1, safe=0))
    data.update(_cat("memory", danger=1, safe=0))
    r = calculate_threat_score(data)
    assert r["level"] == "HIGH"
    assert r["danger_category_count"] == 3


def test_critical_five_categories(no_path_corr):
    from web.app import calculate_threat_score

    data = {}
    for c in ("processes", "networks", "memory", "persistence", "evidence"):
        data.update(_cat(c, danger=1, safe=0))
    r = calculate_threat_score(data)
    assert r["level"] == "CRITICAL"


def test_process_network_correlation(no_path_corr):
    from web.app import calculate_threat_score

    data = {}
    data.update(_cat("processes", danger=1, safe=0))
    data.update(_cat("networks", danger=1, safe=0))
    r = calculate_threat_score(data)
    assert any("C2通信" in x for x in r["correlation_reasons"])


def test_self_excluded_from_danger_count(no_path_corr):
    from web.app import calculate_threat_score

    data = {
        "processes": [{"status": "DANGER", "is_self": True}],
    }
    r = calculate_threat_score(data)
    assert r["danger_category_count"] == 0
    assert r["level"] == "CLEAN"
