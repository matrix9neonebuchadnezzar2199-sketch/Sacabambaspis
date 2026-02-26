# -*- coding: utf-8 -*-
# utils/signature.py - P41: Authenticode署名検証モジュール
import subprocess
import os
import logging

logger = logging.getLogger(__name__)

_cache = {}

TRUSTED_SIGNERS = [
    'microsoft', 'mcafee', 'google', 'adobe', 'intel', 'nvidia',
    'apple', 'mozilla', 'cisco', 'oracle', 'vmware', 'symantec',
    'norton', 'eset', 'kaspersky', 'trend micro', 'sophos',
    'crowdstrike', 'sentinelone', 'palo alto', 'avast', 'avg',
    'malwarebytes', 'bitdefender', 'f-secure', 'comodo',
    'dell', 'hp', 'lenovo', 'asus', 'acer', 'samsung', 'logitech',
    'realtek', 'qualcomm', 'broadcom', 'amd',
    'python software foundation', 'git', 'github',
    'slack', 'zoom', 'discord', 'valve', 'steam',
]

HARDCORE_TOOLS = [
    'mimikatz', 'cobalt', 'beacon', 'rubeus', 'seatbelt',
    'sharphound', 'bloodhound', 'lazagne', 'procdump', 'nanodump',
    'safetykatz', 'covenant', 'sliver', 'hashcat', 'john',
    'hydra', 'empire', 'meterpreter', 'havoc', 'bruteratel',
]


def verify_signature(file_path):
    """Authenticode署名を検証し (status, signer) を返す"""
    if not file_path or not os.path.isfile(file_path):
        return ('NotFound', '')

    normalized = os.path.normpath(file_path).lower()
    if normalized in _cache:
        return _cache[normalized]

    try:
        cmd = (
            f'powershell -NoProfile -Command "'
            f"$s = Get-AuthenticodeSignature '{file_path}';"
            f"$s.Status.ToString() + '|' + "
            f"($s.SignerCertificate.Subject -replace ',',';')"
            f'"'
        )
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, shell=True, encoding='utf-8', errors='replace'
        )
        out = r.stdout.strip()
        if '|' in out:
            parts = out.split('|', 1)
            status = parts[0].strip()
            signer = parts[1].strip()
        else:
            status = out if out else 'Unknown'
            signer = ''
    except subprocess.TimeoutExpired:
        status, signer = 'Timeout', ''
    except Exception as e:
        logger.debug(f"署名検証エラー: {e}")
        status, signer = 'Error', ''

    result = (status, signer)
    _cache[normalized] = result
    return result


def is_trusted_signer(signer):
    """署名者が信頼リストに含まれるか判定"""
    if not signer:
        return False
    s_lower = signer.lower()
    return any(t in s_lower for t in TRUSTED_SIGNERS)


def is_hardcore_tool(basename):
    """署名があってもDANGER維持すべきツールか判定"""
    b = basename.lower().replace('.exe', '')
    return any(t in b for t in HARDCORE_TOOLS)


def extract_signer_name(signer_subject):
    """CN=... から組織名を抽出"""
    if not signer_subject:
        return ''
    for part in signer_subject.split(';'):
        part = part.strip()
        if part.upper().startswith('O='):
            return part[2:].strip().strip('"')
    for part in signer_subject.split(';'):
        part = part.strip()
        if part.upper().startswith('CN='):
            return part[3:].strip().strip('"')
    return signer_subject[:60]


def clear_cache():
    """キャッシュをクリア（スキャン毎にリセット用）"""
    _cache.clear()
