# -*- coding: utf-8 -*-
"""スキャン結果 JSON（2件）の差分。一覧系キーごとに安定キーで突き合わせ。"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple


def _key_process(x: Dict[str, Any]) -> str:
    p = (x.get("path") or "").strip().lower()
    if p:
        return "p:" + p
    return "n:" + str(x.get("name", "")).lower() + "|" + str(x.get("pid", ""))


def _key_memory(x: Dict[str, Any]) -> str:
    return "m:" + str(x.get("pid", "")) + "|" + (x.get("reason", "") or "")[:120]


def _key_persist(x: Dict[str, Any]) -> str:
    return "r:" + (x.get("artifact", "") or x.get("key", "") or x.get("path", "")).strip().lower()


def _key_network(x: Dict[str, Any]) -> str:
    return "n:" + str(x.get("remote", "")) + "|" + str(x.get("local", "")) + "|" + str(x.get("pid", ""))


def _key_evidence(x: Dict[str, Any]) -> str:
    return "e:" + (x.get("artifact", "") or "").strip().lower() + "|" + str(x.get("source", ""))


def _key_eventlog(x: Dict[str, Any]) -> str:
    msg = (x.get("message", "") or "")[:200]
    return "l:" + str(x.get("id", "")) + "|" + str(x.get("time", "")) + "|" + msg


def _key_generic(x: Dict[str, Any], *fields: str) -> str:
    parts = []
    for f in fields:
        parts.append(str(x.get(f, "")).strip().lower())
    return "g:" + "|".join(parts)


LIST_SPECS: List[Tuple[str, Callable[[Dict[str, Any]], str]]] = [
    ("processes", _key_process),
    ("memory", _key_memory),
    ("persistence", _key_persist),
    ("networks", _key_network),
    ("evidence", _key_evidence),
    ("eventlogs", _key_eventlog),
    ("pca", lambda x: _key_generic(x, "exe_name", "artifact", "timestamp")),
    ("ads", lambda x: _key_generic(x, "artifact", "timestamp")),
    ("wsl", lambda x: _key_generic(x, "artifact")),
    ("cam", lambda x: _key_generic(x, "exe_path", "program_name")),
    ("srum", lambda x: _key_generic(x, "app_name", "timestamp")),
    ("recall", lambda x: _key_generic(x, "artifact")),
    ("binrename", lambda x: _key_generic(x, "exe_path", "exe_name")),
    ("lnk", lambda x: _key_generic(x, "lnk_path", "target_path")),
    ("mutant", lambda x: _key_generic(x, "artifact")),
]


def diff_scans(baseline: Optional[Dict[str, Any]], current: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    baseline / current は scan_results 形式。
    返却: added / removed / stats（カテゴリごとの件数）
    """
    baseline = baseline or {}
    current = current or {}

    out_added: Dict[str, List[Any]] = {}
    out_removed: Dict[str, List[Any]] = {}
    stats: Dict[str, Any] = {}

    for key, key_fn in LIST_SPECS:
        old_list = baseline.get(key)
        new_list = current.get(key)
        if not isinstance(old_list, list):
            old_list = []
        if not isinstance(new_list, list):
            new_list = []

        old_map: Dict[str, Any] = {}
        for item in old_list:
            if isinstance(item, dict):
                try:
                    old_map[key_fn(item)] = item
                except Exception:
                    continue

        new_map: Dict[str, Any] = {}
        for item in new_list:
            if isinstance(item, dict):
                try:
                    new_map[key_fn(item)] = item
                except Exception:
                    continue

        ok, nk = set(old_map.keys()), set(new_map.keys())
        added_k = nk - ok
        removed_k = ok - nk

        out_added[key] = [new_map[k] for k in sorted(added_k)]
        out_removed[key] = [old_map[k] for k in sorted(removed_k)]
        stats[key] = {
            "baseline_count": len(old_list),
            "current_count": len(new_list),
            "added": len(added_k),
            "removed": len(removed_k),
        }

    meta = {
        "baseline_scan_time": (baseline.get("system") or {}).get("scan_time"),
        "baseline_hostname": (baseline.get("system") or {}).get("hostname"),
        "current_scan_time": (current.get("system") or {}).get("scan_time"),
        "current_hostname": (current.get("system") or {}).get("hostname"),
    }

    return {
        "added": out_added,
        "removed": out_removed,
        "stats": stats,
        "meta": meta,
    }


def load_scan_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
