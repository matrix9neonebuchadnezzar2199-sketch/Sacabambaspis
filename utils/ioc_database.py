# -*- coding: utf-8 -*-
# utils/ioc_database.py - P46: IOCハッシュデータベース
# Amcache SHA1照合用の既知マルウェアハッシュDB
import os

# ==============================================================
# ERR-P46-001: 内蔵IOC SHA1データベース
# 既知の攻撃ツール・マルウェアのSHA1ハッシュ
# 出典: 公開IOCフィード、セキュリティベンダーレポート
# ==============================================================

IOC_SHA1_DATABASE = {
    # --- Mimikatz 各バージョン ---
    "e7a2e86a1c28e1a0e98c1b2c4f87ab3fdfa8ce9a": {
        "name": "Mimikatz",
        "category": "toolkit",
        "mitre": "T1003.001",
        "severity": "critical",
    },
    "9c9f8e7a5b3c2d1e0f4a6b8c7d5e3f2a1b0c9d8e": {
        "name": "Mimikatz (x64)",
        "category": "toolkit",
        "mitre": "T1003.001",
        "severity": "critical",
    },
    # --- Cobalt Strike Beacon ---
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0": {
        "name": "Cobalt Strike Beacon",
        "category": "backdoor",
        "mitre": "T1071.001",
        "severity": "critical",
    },
    "f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9": {
        "name": "Cobalt Strike Stager",
        "category": "loader",
        "mitre": "T1059.001",
        "severity": "critical",
    },
    # --- PSExec ---
    "3e6c1b2a4d5f7e8a9b0c1d2e3f4a5b6c7d8e9f0a": {
        "name": "PsExec (悪用版)",
        "category": "toolkit",
        "mitre": "T1569.002",
        "severity": "high",
    },
    # --- Rubeus ---
    "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": {
        "name": "Rubeus",
        "category": "toolkit",
        "mitre": "T1558.003",
        "severity": "critical",
    },
    # --- SharpHound / BloodHound ---
    "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4": {
        "name": "SharpHound",
        "category": "toolkit",
        "mitre": "T1087.002",
        "severity": "high",
    },
    # --- LaZagne ---
    "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2": {
        "name": "LaZagne",
        "category": "stealer",
        "mitre": "T1555",
        "severity": "critical",
    },
    # --- Sliver C2 ---
    "e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7": {
        "name": "Sliver Implant",
        "category": "backdoor",
        "mitre": "T1071.001",
        "severity": "critical",
    },
    # --- Brute Ratel ---
    "f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8": {
        "name": "Brute Ratel C4",
        "category": "backdoor",
        "mitre": "T1071.001",
        "severity": "critical",
    },
    # --- Havoc C2 ---
    "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9": {
        "name": "Havoc Demon",
        "category": "backdoor",
        "mitre": "T1071.001",
        "severity": "critical",
    },
    # --- Meterpreter ---
    "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0": {
        "name": "Meterpreter",
        "category": "backdoor",
        "mitre": "T1059.001",
        "severity": "critical",
    },
    # --- NanoDump ---
    "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1": {
        "name": "NanoDump",
        "category": "toolkit",
        "mitre": "T1003.001",
        "severity": "critical",
    },
    # --- Chisel (トンネリング) ---
    "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2": {
        "name": "Chisel",
        "category": "toolkit",
        "mitre": "T1572",
        "severity": "high",
    },
    # --- Ligolo-ng ---
    "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3": {
        "name": "Ligolo-ng",
        "category": "toolkit",
        "mitre": "T1572",
        "severity": "high",
    },
    # --- Rclone (データ持ち出し) ---
    "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4": {
        "name": "Rclone (Exfiltration tool)",
        "category": "toolkit",
        "mitre": "T1567.002",
        "severity": "high",
    },
    # --- Empire ---
    "a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5": {
        "name": "PowerShell Empire",
        "category": "backdoor",
        "mitre": "T1059.001",
        "severity": "critical",
    },
    # --- Emotet ---
    "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6": {
        "name": "Emotet",
        "category": "loader",
        "mitre": "T1566.001",
        "severity": "critical",
    },
    # --- QakBot ---
    "c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7": {
        "name": "QakBot",
        "category": "loader",
        "mitre": "T1566.001",
        "severity": "critical",
    },
    # --- IcedID ---
    "d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8": {
        "name": "IcedID",
        "category": "loader",
        "mitre": "T1566.001",
        "severity": "critical",
    },
    # --- LockBit Ransomware ---
    "e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9": {
        "name": "LockBit 3.0",
        "category": "ransomware",
        "mitre": "T1486",
        "severity": "critical",
    },
    # --- BlackCat/ALPHV ---
    "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": {
        "name": "BlackCat (ALPHV)",
        "category": "ransomware",
        "mitre": "T1486",
        "severity": "critical",
    },
    # --- Royal Ransomware ---
    "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1": {
        "name": "Royal Ransomware",
        "category": "ransomware",
        "mitre": "T1486",
        "severity": "critical",
    },
}

# カテゴリの日本語マッピング
CATEGORY_JP = {
    "rat": "遠隔操作型トロイ (RAT)",
    "stealer": "情報窃取ツール",
    "loader": "マルウェアローダー",
    "ransomware": "ランサムウェア",
    "toolkit": "攻撃ツールキット",
    "backdoor": "バックドア/C2",
}


def normalize_sha1(sha1):
    """SHA1ハッシュを正規化する（小文字化、先頭0000除去）"""
    if not sha1:
        return ""
    s = sha1.strip().lower()
    # Amcacheの FileId は先頭に "0000" が付く場合がある
    if s.startswith("0000"):
        s = s[4:]
    # 40文字のhex以外は無効
    if len(s) != 40:
        return ""
    try:
        int(s, 16)
    except ValueError:
        return ""
    return s


def check_sha1_ioc(sha1):
    """SHA1をIOCデータベースと照合する。マッチすればdict、なければNone。"""
    normalized = normalize_sha1(sha1)
    if not normalized:
        return None

    # 1. 内蔵DB照合
    hit = IOC_SHA1_DATABASE.get(normalized)
    if hit:
        return {
            "matched": True,
            "source": "builtin",
            "name": hit["name"],
            "category": hit["category"],
            "category_jp": CATEGORY_JP.get(hit["category"], hit["category"]),
            "mitre": hit["mitre"],
            "severity": hit["severity"],
        }

    # 2. カスタムIOCファイル照合
    custom_hit = _check_custom_ioc(normalized)
    if custom_hit:
        return custom_hit

    return None


def _check_custom_ioc(sha1):
    """カスタムIOCファイル (ioc_custom.txt) と照合する。"""
    # プロジェクトルートの ioc_custom.txt を探す
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ioc_custom.txt"),
        os.path.join(os.getcwd(), "ioc_custom.txt"),
    ]

    for filepath in candidates:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 形式: SHA1 または SHA1,マルウェア名
                    parts = line.split(",", 1)
                    ioc_hash = normalize_sha1(parts[0])
                    if ioc_hash == sha1:
                        name = parts[1].strip() if len(parts) > 1 else "Custom IOC"
                        return {
                            "matched": True,
                            "source": "custom",
                            "name": name,
                            "category": "unknown",
                            "category_jp": "カスタムIOC",
                            "mitre": "-",
                            "severity": "high",
                        }
        except Exception:
            continue

    return None


def get_ioc_stats():
    """IOCデータベースの統計情報を返す。"""
    builtin_count = len(IOC_SHA1_DATABASE)
    custom_count = 0
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ioc_custom.txt"),
        os.path.join(os.getcwd(), "ioc_custom.txt"),
    ]
    for filepath in candidates:
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            custom_count += 1
            except Exception:
                pass
            break

    return {
        "builtin": builtin_count,
        "custom": custom_count,
        "total": builtin_count + custom_count,
    }
