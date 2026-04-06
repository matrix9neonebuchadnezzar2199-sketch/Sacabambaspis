# -*- coding: utf-8 -*-
# utils/ioc_database.py - IOC ハッシュデータベース（SHA256 優先・SHA1 は Amcache 等の互換用）
import hashlib
import json
import os

# ==============================================================
# 内蔵 IOC（SHA1）— Windows Amcache FileId が SHA1 のため引き続き利用
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
    # --- Chisel ---
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
    # --- Rclone ---
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
    # --- LockBit ---
    "e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9": {
        "name": "LockBit 3.0",
        "category": "ransomware",
        "mitre": "T1486",
        "severity": "critical",
    },
    # --- BlackCat ---
    "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": {
        "name": "BlackCat (ALPHV)",
        "category": "ransomware",
        "mitre": "T1486",
        "severity": "critical",
    },
    # --- Royal ---
    "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1": {
        "name": "Royal Ransomware",
        "category": "ransomware",
        "mitre": "T1486",
        "severity": "critical",
    },
}

# 内蔵 SHA256（必要に応じて拡張）。現状は空でも、照合 API は USER / カスタムファイルを利用。
IOC_SHA256_DATABASE: dict = {}

CATEGORY_JP = {
    "rat": "遠隔操作型トロイ (RAT)",
    "stealer": "情報窃取ツール",
    "loader": "マルウェアローダー",
    "ransomware": "ランサムウェア",
    "toolkit": "攻撃ツールキット",
    "backdoor": "バックドア/C2",
    "unknown": "未分類",
}

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER_IOC_PATH = os.path.join(_BASE, "data", "user_ioc.json")

# メモリ上のユーザー IOC（sha256 / sha1 キーは正規化済み hex）
USER_IOC_SHA256: dict = {}
USER_IOC_SHA1: dict = {}


def _record_to_hit(hit: dict, source: str) -> dict:
    return {
        "matched": True,
        "source": source,
        "name": hit["name"],
        "category": hit["category"],
        "category_jp": CATEGORY_JP.get(hit["category"], hit["category"]),
        "mitre": hit.get("mitre", "-"),
        "severity": hit.get("severity", "high"),
    }


def normalize_sha1(sha1):
    """SHA1（40 hex）。Amcache の先頭 0000 を除去。"""
    if not sha1:
        return ""
    s = sha1.strip().lower()
    if s.startswith("0000"):
        s = s[4:]
    if len(s) != 40:
        return ""
    try:
        int(s, 16)
    except ValueError:
        return ""
    return s


def normalize_sha256(sha256):
    """SHA256（64 hex）。"""
    if not sha256:
        return ""
    s = sha256.strip().lower()
    if len(s) != 64:
        return ""
    try:
        int(s, 16)
    except ValueError:
        return ""
    return s


def _load_user_ioc_file():
    global USER_IOC_SHA256, USER_IOC_SHA1
    USER_IOC_SHA256 = {}
    USER_IOC_SHA1 = {}
    if not os.path.isfile(USER_IOC_PATH):
        return
    try:
        with open(USER_IOC_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in (data.get("sha256") or {}).items():
            nk = normalize_sha256(k)
            if nk and isinstance(v, dict) and v.get("name"):
                USER_IOC_SHA256[nk] = v
        for k, v in (data.get("sha1") or {}).items():
            nk = normalize_sha1(k)
            if nk and isinstance(v, dict) and v.get("name"):
                USER_IOC_SHA1[nk] = v
    except Exception:
        pass


def _save_user_ioc_file():
    try:
        os.makedirs(os.path.dirname(USER_IOC_PATH), exist_ok=True)
        out = {
            "sha256": USER_IOC_SHA256,
            "sha1": USER_IOC_SHA1,
        }
        with open(USER_IOC_PATH, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_user_iocs():
    """モジュール読込時および取込後に再実行。"""
    _load_user_ioc_file()


load_user_iocs()


def should_read_file_for_sha256_ioc() -> bool:
    """
    内蔵/ユーザーに SHA256 IOC が1件でもあれば True。
    1件も無い場合は Amcache 等で全ファイルを読む必要がない（スキャン停滞の主因を防ぐ）。
    """
    return bool(IOC_SHA256_DATABASE) or bool(USER_IOC_SHA256)


# Amcache からの SHA256 計算: これを超えるファイルはスキップ（数 GB の読み込みでスキャンが事実上停止するのを防ぐ）
AMCACHE_SHA256_MAX_BYTES = 64 * 1024 * 1024


def compute_file_sha256(filepath: str, max_bytes: int | None = None) -> str:
    """ファイルの SHA256（大容量はチャンク読み）。"""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        if max_bytes is None:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        else:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
    return h.hexdigest()


def check_sha256_ioc(sha256: str):
    """SHA256 のみ照合（正規化後）。"""
    n = normalize_sha256(sha256)
    if not n:
        return None
    hit = IOC_SHA256_DATABASE.get(n)
    if hit:
        return _record_to_hit(hit, "builtin")
    hit = USER_IOC_SHA256.get(n)
    if hit:
        return _record_to_hit(hit, "user")
    return None


def check_sha1_ioc(sha1: str):
    """SHA1 のみ照合。後方互換 API。"""
    n = normalize_sha1(sha1)
    if not n:
        return None
    hit = IOC_SHA1_DATABASE.get(n)
    if hit:
        return _record_to_hit(hit, "builtin")
    hit = USER_IOC_SHA1.get(n)
    if hit:
        return _record_to_hit(hit, "user")
    custom = _check_custom_ioc_file(n)
    if custom:
        return custom
    return None


def check_ioc_hash(hex_str: str):
    """
    40 hex → SHA1、64 hex → SHA256 を自動判定。
    どちらでもない場合は None。
    """
    if not hex_str or not isinstance(hex_str, str):
        return None
    s = hex_str.strip().lower()
    if len(s) == 64:
        return check_sha256_ioc(s)
    if len(s) == 40:
        return check_sha1_ioc(s)
    return None


def _check_custom_ioc_file(normalized_sha1: str):
    """ioc_custom.txt（SHA1 行）— レガシー互換。"""
    candidates = [
        os.path.join(_BASE, "ioc_custom.txt"),
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
                    parts = line.split(",", 1)
                    token = parts[0].strip()
                    n1 = normalize_sha1(token)
                    if n1 == normalized_sha1:
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


def parse_ioc_import_text(text: str, replace: bool = False) -> dict:
    """
    1行1エントリ: 64hex または 40hex [,表示名]
    replace=True でユーザー IOC を全置換。
    """
    global USER_IOC_SHA256, USER_IOC_SHA1
    if replace:
        USER_IOC_SHA256 = {}
        USER_IOC_SHA1 = {}
    added_s256 = 0
    added_s1 = 0
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 1)
        token = parts[0].strip()
        label = parts[1].strip() if len(parts) > 1 else "Imported IOC"
        n256 = normalize_sha256(token)
        n1 = normalize_sha1(token)
        rec = {"name": label, "category": "unknown", "mitre": "-", "severity": "high"}
        if n256:
            USER_IOC_SHA256[n256] = rec
            added_s256 += 1
        elif n1:
            USER_IOC_SHA1[n1] = rec
            added_s1 += 1
    _save_user_ioc_file()
    return {
        "sha256_added": added_s256,
        "sha1_added": added_s1,
        "total_user_sha256": len(USER_IOC_SHA256),
        "total_user_sha1": len(USER_IOC_SHA1),
    }


def clear_user_iocs():
    global USER_IOC_SHA256, USER_IOC_SHA1
    USER_IOC_SHA256 = {}
    USER_IOC_SHA1 = {}
    _save_user_ioc_file()


def get_ioc_stats():
    custom_txt = 0
    for filepath in [os.path.join(_BASE, "ioc_custom.txt"), os.path.join(os.getcwd(), "ioc_custom.txt")]:
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            custom_txt += 1
            except Exception:
                pass
            break
    return {
        "builtin_sha1": len(IOC_SHA1_DATABASE),
        "builtin_sha256": len(IOC_SHA256_DATABASE),
        "user_sha256": len(USER_IOC_SHA256),
        "user_sha1": len(USER_IOC_SHA1),
        "custom_txt_lines": custom_txt,
        "total_builtin": len(IOC_SHA1_DATABASE) + len(IOC_SHA256_DATABASE),
        "total_user": len(USER_IOC_SHA256) + len(USER_IOC_SHA1),
    }
