# -*- coding: utf-8 -*-
# collectors/pe_sieve.py - P40: PE-sieve / HollowsHunter 統合ラッパー
"""
PE-sieve (hasherezade) をサブプロセスで呼び出し、
プロセスインジェクション・hollowing・シェルコードを検出する。
"""

import os
import json
import shutil
import subprocess
import tempfile

try:
    from utils.tutor_template import build_tutor_desc
except ImportError:
    try:
        from tutor_template import build_tutor_desc
    except ImportError:
        def build_tutor_desc(**kwargs):
            return kwargs.get("detection", "")


def _find_tool(name):
    """tools/ ディレクトリから EXE を探す"""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "tools", name),
        os.path.join(base, name),
        name,
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


PE_SIEVE_PATH = _find_tool("pe-sieve64.exe")
HOLLOWS_HUNTER_PATH = _find_tool("hollows_hunter64.exe")

DOTNET_FP_INDICATORS = [
    "clr.dll", "clrjit.dll", "mscorlib", "coreclr",
    ".ni.dll", "mscoreei.dll", "mscorwks.dll",
]

FP_PROCESS_NAMES = [
    "powershell.exe", "pwsh.exe", "code.exe", "devenv.exe",
    "java.exe", "javaw.exe", "node.exe", "python.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
]


def is_available():
    """PE-sieve が利用可能か"""
    return PE_SIEVE_PATH is not None and os.path.isfile(PE_SIEVE_PATH)


def scan_process(pid, process_name="", process_path=""):
    """
    単一プロセスを PE-sieve でスキャンする。
    Returns: dict or None
    """
    if not is_available():
        return None

    work_dir = tempfile.mkdtemp(prefix="pesieve_")

    try:
        cmd = [
            PE_SIEVE_PATH,
            "/pid", str(pid),
            "/shellc", "A",
            "/json",
            "/quiet",
            "/dir", work_dir,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            creationflags=0x08000000,
        )

        output = result.stdout
        if not output.strip():
            return None

        json_start = output.find("{")
        if json_start < 0:
            return None

        report = json.loads(output[json_start:])
        scan_report = report.get("scan_report", {})
        scanned = scan_report.get("scanned", {})
        modified = scanned.get("modified", {})

        is_managed = scan_report.get("is_managed", 0) == 1
        replaced = modified.get("replaced", 0)
        patched = modified.get("patched", 0)
        implanted_pe = modified.get("implanted_pe", 0)
        implanted_shc = modified.get("implanted_shc", 0)
        iat_hooked = modified.get("iat_hooked", 0)
        unreachable = modified.get("unreachable_file", 0)
        other_mod = modified.get("other", 0)

        # --- 偽陽性フィルタリング ---
        adjusted_shc = implanted_shc
        adjusted_patched = patched

        if is_managed:
            scans = scan_report.get("scans", [])
            fp_shc = 0
            fp_patch = 0
            for scan in scans:
                if "workingset_scan" in scan:
                    ws = scan["workingset_scan"]
                    if ws.get("has_shellcode", 0) == 1:
                        if ws.get("mapping_type") == "MEM_PRIVATE":
                            fp_shc += 1
                if "code_scan" in scan:
                    cs = scan["code_scan"]
                    mf = cs.get("module_file", "").lower()
                    if any(fp in mf for fp in DOTNET_FP_INDICATORS):
                        fp_patch += 1
            adjusted_shc = max(0, implanted_shc - fp_shc)
            adjusted_patched = max(0, patched - fp_patch)

        proc_lower = process_name.lower()
        if proc_lower in FP_PROCESS_NAMES and adjusted_shc > 0 and replaced == 0 and implanted_pe == 0:
            adjusted_shc = 0

        # --- 判定 ---
        status = "SAFE"
        reasons = []
        details = []

        if replaced > 0:
            status = "DANGER"
            reasons.append(f"プロセスハロウイング検出 ({replaced}モジュール置換)")
            details.append({"type": "replaced", "count": replaced})

        if implanted_pe > 0:
            status = "DANGER"
            reasons.append(f"不正PE注入検出 ({implanted_pe}モジュール)")
            details.append({"type": "implanted_pe", "count": implanted_pe})

        if adjusted_shc > 0:
            status = "DANGER"
            reasons.append(f"シェルコード検出 ({adjusted_shc}領域)")
            details.append({"type": "shellcode", "count": adjusted_shc, "raw": implanted_shc})

        if iat_hooked > 0:
            if status != "DANGER":
                status = "WARNING"
            reasons.append(f"IAT フック検出 ({iat_hooked})")
            details.append({"type": "iat_hook", "count": iat_hooked})

        if adjusted_patched > 0:
            if status != "DANGER":
                status = "WARNING"
            reasons.append(f"コードパッチ検出 ({adjusted_patched}モジュール)")
            details.append({"type": "patched", "count": adjusted_patched, "raw": patched})

        if unreachable > 0:
            if status == "SAFE":
                status = "WARNING"
            reasons.append(f"ファイル不達モジュール ({unreachable})")
            details.append({"type": "unreachable", "count": unreachable})

        reason = "; ".join(reasons) if reasons else "PE-sieve: 異常なし"
        desc = _build_desc(status, reason, details, is_managed, process_name)

        return {
            "pid": pid,
            "process_name": process_name,
            "total_scanned": scanned.get("total", 0),
            "replaced": replaced,
            "patched": patched,
            "adjusted_patched": adjusted_patched,
            "implanted_pe": implanted_pe,
            "implanted_shc": implanted_shc,
            "adjusted_shc": adjusted_shc,
            "iat_hooked": iat_hooked,
            "unreachable_file": unreachable,
            "is_managed": is_managed,
            "status": status,
            "reason": reason,
            "details": details,
            "desc": desc,
        }

    except subprocess.TimeoutExpired:
        return {"pid": pid, "status": "ERROR", "reason": "PE-sieve タイムアウト (30秒)"}
    except json.JSONDecodeError:
        return {"pid": pid, "status": "ERROR", "reason": "PE-sieve JSON パースエラー"}
    except Exception as e:
        return {"pid": pid, "status": "ERROR", "reason": f"PE-sieve エラー: {str(e)[:100]}"}
    finally:
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


def scan_suspicious_processes(process_list):
    """
    process.py の scan() 結果から WARNING/DANGER のプロセスだけを
    PE-sieve でスキャンする。
    """
    if not is_available():
        return []

    results = []
    scanned_pids = set()

    for proc in process_list:
        pid = proc.get("pid")
        if not pid or pid in scanned_pids:
            continue
        proc_status = proc.get("status", "SAFE")
        if proc_status not in ("DANGER", "WARNING"):
            continue

        scanned_pids.add(pid)
        result = scan_process(
            pid,
            process_name=proc.get("name", ""),
            process_path=proc.get("path", ""),
        )
        if result and result.get("status") not in ("SAFE", "ERROR"):
            results.append(result)

    return results


def _build_desc(status, reason, details, is_managed, process_name):
    """PE-sieve 結果から解説テキストを生成"""
    if status == "SAFE":
        return build_tutor_desc(
            detection="PE-sieveスキャンで異常は検出されませんでした。",
            why_dangerous="",
            mitre_key=None,
            status="SAFE",
        )

    detection_parts = []
    risk_parts = []

    for d in details:
        dtype = d["type"]
        if dtype == "replaced":
            detection_parts.append(
                f"プロセスのメモリ上のPEが{d['count']}個、ディスク上のファイルと一致しません。"
            )
            risk_parts.append(
                "プロセスハロウイング（Process Hollowing）の可能性が高いです。"
                "攻撃者が正規プロセスの中身をマルウェアに置き換えている状態です。"
            )
        elif dtype == "implanted_pe":
            detection_parts.append(
                f"不正なPEが{d['count']}個メモリ上に存在します。"
            )
            risk_parts.append(
                "DLLインジェクションまたはReflective DLL Loadingの可能性があります。"
            )
        elif dtype == "shellcode":
            detection_parts.append(
                f"シェルコードが{d['count']}領域で検出されました。"
            )
            risk_parts.append(
                "シェルコードインジェクションの可能性があります。"
                "攻撃者がプロセスメモリに直接攻撃コードを書き込んでいます。"
            )
        elif dtype == "iat_hook":
            detection_parts.append(
                f"IAT フックが{d['count']}件検出されました。"
            )
            risk_parts.append(
                "API呼び出しが横取りされている可能性があります。"
            )
        elif dtype == "patched":
            detection_parts.append(
                f"コードパッチが{d['count']}件検出されました。"
            )
            risk_parts.append(
                "インラインフックの可能性があります。セキュリティ製品による正規フックの場合も。"
            )
        elif dtype == "unreachable":
            detection_parts.append(
                f"対応ファイルが{d['count']}件見つかりません。"
            )
            risk_parts.append(
                "ファイルレスマルウェアまたは削除済みファイルの可能性があります。"
            )

    detection = " ".join(detection_parts)
    risk = " ".join(risk_parts)

    return build_tutor_desc(
        detection=f"PE-sieve検出: {detection}",
        why_dangerous=risk,
        mitre_key="proc_injection",
        status=status,
    )
