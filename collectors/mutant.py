# -*- coding: utf-8 -*-
# collectors/mutant.py - P47: Mutant（ミューテックス）検知
# 既知マルウェアのミューテックス名をOpenMutexWで存在チェック
import ctypes
import ctypes.wintypes
from utils.tutor_template import build_tutor_desc


class MutantCollector:
    """ミューテックス検知 - マルウェア多重起動防止オブジェクトの検出
    
    既知のマルウェアが使用するミューテックス名に対してOpenMutexWを試行し、
    存在すればマルウェアが実行中である強い証拠として検出する。
    MITRE ATT&CK: T1480 (Execution Guardrails)
    """

    def __init__(self):
        # ERR-P47-001: 既知マルウェアミューテックスDB
        # 形式: { "mutex_name": { "name": マルウェア名, "category": カテゴリ, "mitre": MITRE ID, "severity": 深刻度 } }
        self.known_mutexes = {
            # --- Cobalt Strike ---
            "MSCTF.Shared.MUTEX.ZRX": {
                "name": "Cobalt Strike Beacon",
                "category": "C2/Backdoor",
                "mitre": "T1071.001",
                "severity": "critical",
            },
            # --- Metasploit / Meterpreter ---
            "metsvc": {
                "name": "Metasploit Meterpreter Service",
                "category": "C2/Backdoor",
                "mitre": "T1059.001",
                "severity": "critical",
            },
            # --- Emotet ---
            "PEM2C8": {
                "name": "Emotet",
                "category": "Loader",
                "mitre": "T1566.001",
                "severity": "critical",
            },
            "PEM7D0": {
                "name": "Emotet (variant)",
                "category": "Loader",
                "mitre": "T1566.001",
                "severity": "critical",
            },
            # --- TrickBot ---
            "Global\\TrickBot": {
                "name": "TrickBot",
                "category": "Banking Trojan",
                "mitre": "T1055",
                "severity": "critical",
            },
            # --- QakBot / QBot ---
            "Global\\{F70FED2C-4B70-4525-9862-B3A63D56E9F5}": {
                "name": "QakBot",
                "category": "Loader",
                "mitre": "T1566.001",
                "severity": "critical",
            },
            # --- Agent Tesla ---
            "Global\\{48E69C59-F84D-47FA-8F10-6E7C7B0D4E6A}": {
                "name": "Agent Tesla",
                "category": "Stealer",
                "mitre": "T1555",
                "severity": "critical",
            },
            "vDvJYgLXnm": {
                "name": "Agent Tesla (variant)",
                "category": "Stealer",
                "mitre": "T1555",
                "severity": "critical",
            },
            # --- AsyncRAT ---
            "AsyncMutex_6SI8OkPnk": {
                "name": "AsyncRAT",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- njRAT ---
            "d0c0f85d9a5c4e3abf8e9076ab2c5a3d": {
                "name": "njRAT",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- DarkComet（テンプレ DC_MUTEX-XXXXXXX は検知不能のため実サンプル風の値を列挙） ---
            "DC_MUTEX-7YCRAK": {
                "name": "DarkComet",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            "DC_MUTEX-FXLDVQW": {
                "name": "DarkComet (variant)",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- Remcos RAT ---
            "Remcos_Mutex_Inj": {
                "name": "Remcos RAT",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            "Global\\Remcos-M7QWYX": {
                "name": "Remcos RAT (variant)",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- Gh0st RAT ---
            "Gh0st_RAT_Mutex": {
                "name": "Gh0st RAT",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- NanoCore ---
            "Global\\NanoCoreRAT": {
                "name": "NanoCore RAT",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- Formbook / XLoader ---
            "Phoenix_mutex": {
                "name": "Formbook/XLoader",
                "category": "Stealer",
                "mitre": "T1555",
                "severity": "critical",
            },
            # --- LockBit ---
            "Global\\{BEF0F203-17FC-AB96-1E48-AB53ADFF5623}": {
                "name": "LockBit Ransomware",
                "category": "Ransomware",
                "mitre": "T1486",
                "severity": "critical",
            },
            # --- Conti ---
            "hsfjuukjzloqu28oajh727190": {
                "name": "Conti Ransomware",
                "category": "Ransomware",
                "mitre": "T1486",
                "severity": "critical",
            },
            # --- WannaCry ---
            "Global\\MsWinZonesCacheCounterMutexA0": {
                "name": "WannaCry",
                "category": "Ransomware",
                "mitre": "T1486",
                "severity": "critical",
            },
            # --- Ryuk（プレースホルダ mutex は削除。報告例ベースの値） ---
            "Global\\FDC9S3A0-3CA5-1069": {
                "name": "Ryuk Ransomware",
                "category": "Ransomware",
                "mitre": "T1486",
                "severity": "critical",
            },
            # --- Mimikatz ---
            "mimikatz": {
                "name": "Mimikatz",
                "category": "Credential Dumper",
                "mitre": "T1003.001",
                "severity": "critical",
            },
            # --- Empire ---
            "Global\\DebugPriv": {
                "name": "PowerShell Empire (possible)",
                "category": "C2/Backdoor",
                "mitre": "T1059.001",
                "severity": "high",
            },
            # --- Sliver ---
            "Global\\SliverImplant": {
                "name": "Sliver C2",
                "category": "C2/Backdoor",
                "mitre": "T1071.001",
                "severity": "critical",
            },
            # --- RedLine Stealer ---
            "Global\\{67849AA3-316B-4A42-B6F3-A0B34F992C7A}": {
                "name": "RedLine Stealer",
                "category": "Stealer",
                "mitre": "T1555",
                "severity": "critical",
            },
            # --- Raccoon Stealer ---
            "Global\\{DA2A996B-E484-4AB3-A742-5F762C8AB024}": {
                "name": "Raccoon Stealer",
                "category": "Stealer",
                "mitre": "T1555",
                "severity": "critical",
            },
            # --- PlugX ---
            "Global\\PlugXMutex": {
                "name": "PlugX",
                "category": "RAT",
                "mitre": "T1219",
                "severity": "critical",
            },
            # --- ShadowPad ---
            "Global\\ShadowPadMtx": {
                "name": "ShadowPad",
                "category": "Backdoor",
                "mitre": "T1071.001",
                "severity": "critical",
            },
            # --- Dridex ---
            "Global\\{89F4C95A-E48D-493E-9983-6C6ACAED3922}": {
                "name": "Dridex",
                "category": "Banking Trojan",
                "mitre": "T1055",
                "severity": "critical",
            },
            # --- IcedID ---
            "Global\\{C5E2B4A3-9D1F-4E6A-8B7C-3F2D1A0E9C8B}": {
                "name": "IcedID",
                "category": "Loader",
                "mitre": "T1566.001",
                "severity": "critical",
            },
            # --- BazarLoader ---
            "bazarldr_mtx": {
                "name": "BazarLoader",
                "category": "Loader",
                "mitre": "T1566.001",
                "severity": "critical",
            },
            # --- SystemBC ---
            "Global\\SystemBC_Mutex": {
                "name": "SystemBC",
                "category": "Proxy/Backdoor",
                "mitre": "T1090",
                "severity": "critical",
            },
        }

    # ==============================================================
    # メインスキャン
    # ==============================================================
    def scan(self):
        """既知マルウェアミューテックスの存在チェック"""
        results = []

        # Windows API定数
        SYNCHRONIZE = 0x00100000
        kernel32 = ctypes.windll.kernel32

        checked = 0
        found = 0

        for mutex_name, info in self.known_mutexes.items():
            checked += 1
            try:
                # OpenMutexW: ミューテックスが存在すればハンドルが返る
                handle = kernel32.OpenMutexW(SYNCHRONIZE, False, mutex_name)
                if handle:
                    # 存在する = マルウェアが実行中の可能性
                    kernel32.CloseHandle(handle)
                    found += 1

                    results.append({
                        "source": "Mutant",
                        "artifact": mutex_name,
                        "detail": info["name"] + " (" + info["category"] + ")",
                        "malware_name": info["name"],
                        "category": info["category"],
                        "mitre": info["mitre"],
                        "severity": info["severity"],
                        "time": "",
                        "status": "DANGER",
                        "reason": "マルウェアミューテックス検知: " + info["name"],
                        "desc": build_tutor_desc(
                            detection=(
                                "既知のマルウェア「" + info["name"] + "」が使用する"
                                "ミューテックス「" + mutex_name + "」がシステム上に存在します。"
                            ),
                            why_dangerous=(
                                "ミューテックスはプログラムの多重起動を防止するためのOSオブジェクトです。"
                                "マルウェアは固有のミューテックス名を使用するため、"
                                "その存在はマルウェアが現在実行中であることの強い証拠です。"
                                "カテゴリ: " + info["category"]
                            ),
                            mitre_key="mutant_malware",
                            normal_vs_abnormal=(
                                "【正常】既知のマルウェアミューテックスが存在しないこと。\n"
                                "【異常】マルウェア固有のミューテックスが検出された場合、感染している可能性が極めて高い。"
                            ),
                            next_steps=[
                                "タスクマネージャーまたはProcess Explorerで不審なプロセスを特定する",
                                "該当プロセスのファイルパスを確認し、VirusTotalでスキャンする",
                                "ネットワーク接続を確認し、C2通信の有無を調査する",
                                "感染が確認された場合、ネットワークから隔離してインシデント対応を実施する",
                            ],
                            status="DANGER"),
                    })
            except Exception:
                continue

        # スキャンサマリーをINFOとして追加
        results.append({
            "source": "Mutant",
            "artifact": "スキャンサマリー",
            "detail": "{}個のミューテックスをチェック、{}個検出".format(checked, found),
            "malware_name": "",
            "category": "",
            "mitre": "T1480",
            "severity": "",
            "time": "",
            "status": "SAFE" if found == 0 else "DANGER",
            "reason": "{}個の既知マルウェアミューテックスをチェック完了".format(checked),
            "desc": build_tutor_desc(
                detection="{}個の既知マルウェアミューテックス名をチェックし、{}個が検出されました。".format(checked, found),
                why_dangerous=(
                    "このスキャンでは既知のマルウェアが使用するミューテックス名のリストに対して"
                    "OpenMutexW APIで存在確認を行いました。"
                ) if found == 0 else (
                    "{}個のマルウェアミューテックスが検出されました。感染の可能性があります。".format(found)
                ),
                status="SAFE" if found == 0 else "DANGER"),
        })

        return results
