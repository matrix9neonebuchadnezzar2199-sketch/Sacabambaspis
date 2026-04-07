# -*- coding: utf-8 -*-
# collectors/sigma_engine.py - P39: Sigma ルール統合エンジン
"""
SigmaHQ の YAML ルールを読み込み、イベントログに対してマッチングを行う。
sigma-rule-matcher (pySigma ベース) を使用。
"""

import glob
import os
import threading

from utils.app_logging import get_logger

try:
    from sigma.rule import SigmaRule
    from sigma_rule_matcher import RuleMatcher
    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False

_logger = get_logger(__name__)

# ルールキャッシュ（モジュールレベルで保持・並行ロード防止）
_rule_cache = None
_rule_load_errors = 0
_rule_lock = threading.Lock()


def _get_rules_dir():
    """Sigma ルールディレクトリのパスを返す"""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "rules", "sigma", "rules", "windows"),
        os.path.join(base, "rules", "sigma", "rules-emerging-threats"),
    ]
    return [c for c in candidates if os.path.isdir(c)]


def _load_rules(directories=None, categories=None):
    """
    Sigma ルールを一括読み込みしてキャッシュする。
    categories: 読み込むサブフォルダ名のリスト（None=全部）
      例: ["security", "powershell_script", "service_control_manager"]
    """
    global _rule_cache, _rule_load_errors

    if _rule_cache is not None:
        return _rule_cache

    with _rule_lock:
        if _rule_cache is not None:
            return _rule_cache

        if not SIGMA_AVAILABLE:
            _logger.warning("sigma-rule-matcher が未インストールです。pip install sigma-rule-matcher")
            _rule_cache = []
            return _rule_cache

        rules = []
        errors = 0
        dirs = directories or _get_rules_dir()

        # Sacabambaspis が扱うログソースに関連するカテゴリ
        relevant_categories = categories or [
            "security",
            "service_control_manager",
            "powershell_script",
            "powershell_module",
            "powershell_classic",
            "application",
            "system",
            "process_creation",
            "registry_set",
            "registry_event",
            "file_event",
            "image_load",
            "network_connection",
            "dns_query",
        ]

        for base_dir in dirs:
            # 直下の YAML も読む
            for yml_path in glob.glob(os.path.join(base_dir, "**", "*.yml"), recursive=True):
                # カテゴリフィルタ
                parent_folder = os.path.basename(os.path.dirname(yml_path))
                if relevant_categories and parent_folder not in relevant_categories:
                    # emerging-threats 等はフォルダ構造が異なるのでスキップしない
                    if "rules-emerging" in yml_path or "rules-threat" in yml_path:
                        pass
                    else:
                        continue

                try:
                    with open(yml_path, "r", encoding="utf-8") as f:
                        raw = f.read()

                    sigma_rule = SigmaRule.from_yaml(raw)
                    matcher = RuleMatcher(sigma_rule)

                    rules.append({
                        "matcher": matcher,
                        "title": sigma_rule.title or os.path.basename(yml_path),
                        "level": str(sigma_rule.level) if sigma_rule.level else "medium",
                        "description": sigma_rule.description or "",
                        "tags": [str(t) for t in (sigma_rule.tags or [])],
                        "id": str(sigma_rule.id) if sigma_rule.id else "",
                        "file": os.path.basename(yml_path),
                    })
                except Exception:
                    errors += 1

        _rule_load_errors = errors
        _rule_cache = rules
        _logger.info("Sigma: %d ルール読み込み完了 (エラー: %d)", len(rules), errors)
        return _rule_cache


def get_rule_count():
    """読み込み済みルール数を返す"""
    rules = _load_rules()
    return len(rules)


def get_load_errors():
    """読み込みエラー数を返す"""
    return _rule_load_errors


def _level_to_status(level):
    """Sigma の level を Sacabambaspis の status に変換"""
    level_lower = str(level).lower()
    if level_lower in ("critical", "high"):
        return "DANGER"
    elif level_lower in ("medium",):
        return "WARNING"
    else:
        return "INFO"


def _tags_to_mitre(tags):
    """Sigma の tags から MITRE ATT&CK ID を抽出"""
    mitre_ids = []
    for tag in tags:
        tag_str = str(tag)
        # attack.t1059.001 -> T1059.001
        if "attack.t" in tag_str.lower():
            tid = tag_str.split("attack.")[-1].upper()
            mitre_ids.append(tid)
    return mitre_ids


def match_event(event_data):
    """
    イベントデータを全 Sigma ルールに対してマッチングする。
    
    Args:
        event_data: dict - イベントログの辞書データ
            例: {"EventID": "4688", "CommandLine": "powershell -enc ...", ...}
    
    Returns:
        list of dict - マッチしたルールのリスト
            [{
                "title": "Suspicious PowerShell Download",
                "level": "high",
                "status": "DANGER",
                "description": "...",
                "tags": ["attack.execution", "attack.t1059.001"],
                "mitre_ids": ["T1059.001"],
                "rule_id": "...",
                "file": "...",
            }, ...]
    """
    rules = _load_rules()
    if not rules:
        return []

    matches = []
    for rule_info in rules:
        try:
            if rule_info["matcher"].match(event_data):
                matches.append({
                    "title": rule_info["title"],
                    "level": rule_info["level"],
                    "status": _level_to_status(rule_info["level"]),
                    "description": rule_info["description"],
                    "tags": rule_info["tags"],
                    "mitre_ids": _tags_to_mitre(rule_info["tags"]),
                    "rule_id": rule_info["id"],
                    "file": rule_info["file"],
                })
        except Exception:
            pass

    # 重要度順にソート (critical > high > medium > low)
    level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    matches.sort(key=lambda m: level_order.get(m["level"].lower(), 5))

    return matches


def match_event_summary(event_data):
    """
    マッチ結果をサマリー形式で返す（eventlog.py 統合用）。
    最も重要度の高いマッチだけを返す。
    
    Returns:
        dict or None
        {
            "status": "DANGER",
            "reason": "Sigma: Suspicious PowerShell Download (high)",
            "sigma_title": "...",
            "sigma_level": "high",
            "sigma_description": "...",
            "sigma_mitre": ["T1059.001"],
            "sigma_tags": [...],
            "sigma_rule_count": 3,  # 合計マッチ数
        }
    """
    matches = match_event(event_data)
    if not matches:
        return None

    best = matches[0]  # 最重要
    return {
        "status": best["status"],
        "reason": f"Sigma検知: {best['title']} ({best['level']})",
        "sigma_title": best["title"],
        "sigma_level": best["level"],
        "sigma_description": best["description"],
        "sigma_mitre": best["mitre_ids"],
        "sigma_tags": best["tags"],
        "sigma_rule_count": len(matches),
    }


def build_sigma_tutor(match_result):
    """
    Sigma マッチ結果から解説テキストを生成する。
    
    Args:
        match_result: match_event_summary() の戻り値
    
    Returns:
        dict: {"beginner": "...", "intermediate": "...", "advanced": "..."}
    """
    if not match_result:
        return {}

    title = match_result.get("sigma_title", "")
    desc = match_result.get("sigma_description", "")
    level = match_result.get("sigma_level", "")
    mitre = match_result.get("sigma_mitre", [])
    count = match_result.get("sigma_rule_count", 1)
    mitre_str = ", ".join(mitre) if mitre else "N/A"

    beginner = (
        f"セキュリティルール「{title}」に一致しました（危険度: {level}）。"
        f"これは世界中のセキュリティ専門家が作成した検知ルール（Sigma）によるもので、"
        f"不審な動作パターンが検出されたことを意味します。"
    )
    if desc:
        beginner += f" 詳細: {desc[:150]}"

    intermediate = (
        f"Sigma ルール「{title}」(level: {level}) がマッチしました。"
        f"合計 {count} 件のルールがヒットしています。"
        f"MITRE ATT&CK: {mitre_str}。"
        f"Sigma は SIEM 向け汎用検知フォーマットで、SigmaHQ コミュニティが管理する "
        f"3000+ ルールから検知されています。"
    )
    if desc:
        intermediate += f" ルール説明: {desc[:200]}"

    advanced = (
        f"Sigma Rule: {title} | ID: {match_result.get('rule_id', 'N/A')} | "
        f"Level: {level} | MITRE: {mitre_str} | "
        f"Total hits: {count} | "
        f"Tags: {', '.join(match_result.get('sigma_tags', [])[:5])}。"
        f"SigmaHQ (DRL 1.1 License) のルールセットによる検知。"
        f"偽陽性の可能性もあるため、コンテキストを確認してください。"
    )
    if desc:
        advanced += f" Description: {desc}"

    return {
        "beginner": beginner,
        "intermediate": intermediate,
        "advanced": advanced,
    }
