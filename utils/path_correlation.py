# -*- coding: utf-8 -*-
"""
スキャン結果横断で同一ファイルパスが複数カテゴリに現れた場合の相関。
"""
import os
import re
from collections import defaultdict

# 引用符・末尾の句読点を除いた Windows パス（ローカルドライブ・UNC）
_WIN_PATH_RE = re.compile(
    r'(?i)(?:"(?P<q>[a-z]:\\[^"]+)"|\'(?P<s>[a-z]:\\[^\']+)\'|(?P<u>\\\\[^\s"|<>*]+)|(?P<p>[a-z]:\\[^\s"|<>*]+))'
)

_STATUS_RANK = {"DANGER": 4, "WARNING": 3, "INFO": 2, "SAFE": 1, "": 0}


def _norm_path(p):
    if not p or not isinstance(p, str):
        return ""
    p = p.strip().strip('"').strip("'")
    p = re.sub(r'[.,;:)]+$', "", p)
    if len(p) < 4:
        return ""
    low = p.lower().replace("/", "\\")
    if ":\\" not in low and not (low.startswith("\\\\") and len(low) > 3):
        return ""
    try:
        if low.startswith("\\\\"):
            # UNC: 正規化で重複を減らす（共有名まで）
            parts = [x for x in low.split("\\") if x]
            if len(parts) >= 2:
                return "\\\\" + "\\".join(parts[: min(len(parts), 8)])
        return os.path.normpath(low)
    except (OSError, TypeError, ValueError):
        return low


def _paths_from_command(cmd):
    if not cmd or not isinstance(cmd, str):
        return []
    out = []
    for m in _WIN_PATH_RE.finditer(cmd):
        raw = m.group("q") or m.group("s") or m.group("u") or m.group("p") or ""
        n = _norm_path(raw)
        if n and len(n) >= 8:
            out.append(n)
    return out


def _iter_artifact_paths(category, item):
    """(category, normalized_path, status, is_self) を yield"""
    if not isinstance(item, dict):
        return
    is_self = bool(item.get("is_self"))
    status = item.get("status") or ""

    keys_by_cat = {
        "processes": ("path",),
        "evidence": ("artifact",),
        "pca": ("artifact",),
        "cam": ("exe_path",),
        "binrename": ("exe_path", "artifact"),
        "ads": ("filepath",),
        "lnk": ("target_path",),
    }
    for key in keys_by_cat.get(category, ()):
        raw = item.get(key)
        if not raw or raw == "-":
            continue
        n = _norm_path(raw)
        if n and len(n) >= 8:
            yield (category, n, status, is_self)

    if category == "persistence":
        for n in _paths_from_command(item.get("command") or ""):
            yield (category, n, status, is_self)


def _collect_clusters(scan_data):
    by_path = defaultdict(lambda: {"categories": set(), "max_rank": 0})

    for category in (
        "processes",
        "evidence",
        "pca",
        "cam",
        "persistence",
        "binrename",
        "ads",
        "lnk",
    ):
        items = scan_data.get(category)
        if not isinstance(items, list):
            continue
        for item in items:
            for cat, norm, status, is_self in _iter_artifact_paths(category, item):
                if is_self:
                    continue
                rec = by_path[norm]
                rec["categories"].add(cat)
                r = _STATUS_RANK.get(status, 0)
                if r > rec["max_rank"]:
                    rec["max_rank"] = r

    return by_path


def find_path_correlations(scan_data, min_rank=3, min_categories=2):
    """
    min_rank: 3=WARNING以上, 2=INFOも含める（同一パスが複数カテゴリのとき）
    """
    by_path = _collect_clusters(scan_data)
    out = []
    for path, rec in by_path.items():
        cats = rec["categories"]
        if len(cats) < min_categories:
            continue
        if rec["max_rank"] < min_rank:
            continue
        out.append(
            {
                "path": path,
                "categories": sorted(cats),
                "category_count": len(cats),
                "max_severity_rank": rec["max_rank"],
            }
        )

    out.sort(key=lambda x: (-x["category_count"], -x["max_severity_rank"], x["path"]))
    return out[:80]


def find_path_correlations_info_tier(scan_data, min_categories=2):
    """最大深刻度が INFO のみ（複数カテゴリ）の相関。誤報の可能性あり参考用。"""
    by_path = _collect_clusters(scan_data)
    out = []
    for path, rec in by_path.items():
        cats = rec["categories"]
        if len(cats) < min_categories:
            continue
        if rec["max_rank"] != _STATUS_RANK["INFO"]:
            continue
        out.append(
            {
                "path": path,
                "categories": sorted(cats),
                "category_count": len(cats),
                "max_severity_rank": rec["max_rank"],
            }
        )
    out.sort(key=lambda x: (-x["category_count"], x["path"]))
    return out[:40]
