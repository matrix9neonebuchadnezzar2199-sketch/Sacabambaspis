# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import glob
import json
import os
import re
import socket
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from urllib.parse import urlparse

from flask import Flask, render_template, jsonify, request

from utils.app_logging import configure_logging, get_logger
from utils.path_helper import resource_path
from utils.threat_thresholds import (
    THREAT_CORR_MULTI_MODERATE_MIN,
    THREAT_CORR_MULTI_SEVERE_MIN,
    THREAT_DC_CRITICAL_MIN,
    THREAT_DC_HIGH_MIN,
)

# Collectors Import
from collectors.process import ProcessCollector
from collectors.registry import RegistryCollector
from collectors.network import NetworkCollector
from collectors.memory import MemoryCollector
from collectors.persistence import PersistenceCollector
from collectors.evidence import EvidenceCollector
from collectors.dna import DNACollector
from collectors.eventlog import EventLogCollector
from collectors.pca import PCACollector
from collectors.ads import ADSCollector
from collectors.wsl import WSLCollector
from collectors.cam import CAMCollector
from collectors.srum import SRUMCollector
from collectors.recall import RecallCollector
from collectors.binary_rename import BinaryRenameCollector
from collectors.lnk_forensics import LnkForensicsCollector
from collectors.mutant import MutantCollector
from collectors.security_surface import SecuritySurfaceCollector
from collectors.memdump import MemoryDumper
from collectors.file_inspector import FileInspector
from utils.yara_manager import YaraManager
from utils.ioc_database import (
    check_sha256_ioc,
    clear_user_iocs,
    get_ioc_stats,
    parse_ioc_import_text,
)
from utils.scan_diff import diff_scans, load_scan_json
from utils.path_correlation import find_path_correlations, find_path_correlations_info_tier
from utils.scan_capabilities import build_scan_capability_report

configure_logging()
logger = get_logger(__name__)

# --- 設定 ---
template_dir = resource_path(os.path.join('web', 'templates'))
static_dir = resource_path(os.path.join('web', 'static'))

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

_memdumper = MemoryDumper()
_file_inspector = FileInspector()
_yara_manager = YaraManager()


def _request_origin_is_localhost() -> bool:
    """Origin 未送信（curl 等）または 127.0.0.1 / localhost のみ許可。"""
    origin = (request.headers.get("Origin") or "").strip()
    if not origin:
        return True
    try:
        host = urlparse(origin).hostname
        if host is None:
            return False
        return host.lower() in ("127.0.0.1", "localhost")
    except (TypeError, ValueError):
        return False


@app.before_request
def _guard_mutating_requests_origin():
    """POST/PUT/DELETE/PATCH を同一オリジン（ローカル UI）に寄せ、外部サイト経由の CSRF を緩和。"""
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return None
    if _request_origin_is_localhost():
        return None
    return jsonify({"status": "error", "message": "Origin not allowed"}), 403


# ================================================================
# P15: 統合脅威スコアリングエンジン
# ================================================================
def calculate_threat_score(scan_data: dict[str, Any]) -> dict[str, Any]:
    """
    全コレクター結果の件数サマリーとカテゴリ別内訳を算出。
    スコアは使わず、DANGER/WARNING/INFO/SAFE の件数で判断する。
    脅威レベルは DANGER が検出されたカテゴリ数で決定。
    """
    details = {}

    categories = {
        'processes':   'プロセス解析',
        'memory':      'メモリ領域解析',
        'persistence': '永続化',
        'networks':    'ネットワーク深層解析',
        'eventlogs':   'イベントログ',
        'evidence':    '実行痕跡',
        'pca':         'PCA実行履歴',
        'ads':         'ADS',
        'wsl':         'WSL環境',
        'cam':         'CAM DB',
        'srum':        'SRUM',
        'recall':      'Windows Recall',
        'binrename':   'バイナリリネーム',
        'lnk':         'LNKフォレンジック',
        'mutant':      'ミューテックス',
    }

    total_danger = 0
    total_warning = 0
    total_info = 0
    total_safe = 0
    danger_categories = []

    for cat, label in categories.items():
        items = scan_data.get(cat, [])
        if not isinstance(items, list):
            continue

        d = sum(1 for x in items if x.get('status') == 'DANGER' and not x.get('is_self'))
        w = sum(1 for x in items if x.get('status') == 'WARNING' and not x.get('is_self'))
        info = sum(1 for x in items if x.get('status') == 'INFO')
        safe = sum(1 for x in items if x.get('status') == 'SAFE')

        total_danger += d
        total_warning += w
        total_info += info
        total_safe += safe

        if d > 0:
            danger_categories.append(cat)

        details[cat] = {
            'label': label,
            'danger': d,
            'warning': w,
            'info': info,
            'safe': safe,
            'total': len(items)
        }

    # --- クロスモジュール相関検知 ---
    correlation_reasons = []

    if 'processes' in danger_categories and 'networks' in danger_categories:
        correlation_reasons.append('プロセス＋ネットワーク同時DANGER → C2通信の可能性')

    if 'persistence' in danger_categories and 'evidence' in danger_categories:
        correlation_reasons.append('永続化＋実行痕跡同時DANGER → マルウェア定着の可能性')

    if 'eventlogs' in danger_categories and 'ads' in danger_categories:
        correlation_reasons.append('イベントログ＋ADS同時DANGER → 高度な隠蔽攻撃の可能性')

    if 'memory' in danger_categories and 'processes' in danger_categories:
        correlation_reasons.append('メモリ注入＋不審プロセス → プロセスインジェクション攻撃の可能性')

    if 'binrename' in danger_categories and 'processes' in danger_categories:
        correlation_reasons.append('バイナリリネーム＋不審プロセス → マスカレードの可能性')

    if len(danger_categories) >= THREAT_CORR_MULTI_SEVERE_MIN:
        correlation_reasons.append(f'{len(danger_categories)}カテゴリでDANGER検知 → 深刻な侵害の可能性')
    elif len(danger_categories) >= THREAT_CORR_MULTI_MODERATE_MIN:
        correlation_reasons.append(f'{len(danger_categories)}カテゴリでDANGER検知 → APT活動の兆候')

    path_correlations = find_path_correlations(scan_data, min_rank=3)
    path_correlations_info = find_path_correlations_info_tier(scan_data)
    for pc in path_correlations[:15]:
        pshort = pc["path"][:140] + ("…" if len(pc["path"]) > 140 else "")
        correlation_reasons.append(
            "同一パスが複数ソースで検出: "
            + pshort
            + " → "
            + ", ".join(pc["categories"])
        )
    for pc in path_correlations_info[:5]:
        pshort = pc["path"][:120] + ("…" if len(pc["path"]) > 120 else "")
        correlation_reasons.append(
            "[参考・INFOのみ] 同一パス複数ソース: "
            + pshort
            + " → "
            + ", ".join(pc["categories"])
        )

    # 脅威レベル: DANGERカテゴリ数で判定
    dc = len(danger_categories)
    if dc >= THREAT_DC_CRITICAL_MIN:
        level = 'CRITICAL'
        level_ja = '🔴 深刻'
        verdict = f'{dc}カテゴリでDANGER検知。即座にインシデント対応を開始してください。'
    elif dc >= THREAT_DC_HIGH_MIN:
        level = 'HIGH'
        level_ja = '🟠 高'
        verdict = f'{dc}カテゴリでDANGER検知。詳細調査を早急に実施してください。'
    elif dc >= 1:
        level = 'MEDIUM'
        level_ja = '🟡 中'
        verdict = f'{dc}カテゴリでDANGER検知。各DANGERアーティファクトの詳細を確認してください。'
    elif total_warning > 0:
        level = 'LOW'
        level_ja = '🟢 低'
        verdict = f'DANGERなし。WARNING {total_warning}件を念のため確認してください。'
    else:
        level = 'CLEAN'
        level_ja = '⚪ クリーン'
        verdict = '脅威は検出されませんでした。'

    return {
        'score': total_danger,
        'level': level,
        'level_ja': level_ja,
        'verdict': verdict,
        'total_danger': total_danger,
        'total_warning': total_warning,
        'total_info': total_info,
        'total_safe': total_safe,
        'total_items': total_danger + total_warning + total_info + total_safe,
        'danger_categories': danger_categories,
        'danger_category_count': dc,
        'correlation_reasons': correlation_reasons,
        'path_correlations': path_correlations,
        'path_correlations_info': path_correlations_info,
        'category_details': details
    }


def find_free_port(start=5000, end=5010):
    """空きポートを自動探索（UFED等との競合回避）。範囲内に空きがなければ OS に任せる。"""
    for port in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', port))
            s.close()
            return port
        except OSError:
            continue
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

# ベースディレクトリの決定（プロジェクトルートを基準にする）
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # web/app.py から1階層上がプロジェクトルート
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_DIR = os.path.join(BASE_DIR, "logs")

# 履歴 API: scan_*.json のみ（許可リスト）
_SCAN_JSON_NAME = re.compile(r"^scan_[A-Za-z0-9._-]+\.json$")
_state_lock = threading.RLock()


def _safe_history_path(filename):
    """LOG_DIR 直下の scan_*.json のみ許可（パストラバーサル・大小文字差を吸収）。"""
    if not filename or filename != os.path.basename(filename):
        return None
    if filename in ('.', '..'):
        return None
    if not _SCAN_JSON_NAME.match(filename):
        return None
    log_root = Path(LOG_DIR).resolve()
    try:
        target = (log_root / filename).resolve()
    except (OSError, ValueError):
        return None
    try:
        target.relative_to(log_root)
    except ValueError:
        return None
    return str(target)


scan_results = {}

# --- ルーティング ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    with _state_lock:
        return jsonify(copy.deepcopy(scan_results))

# --- 履歴管理API ---
@app.route('/api/history/list')
def list_history():
    if not os.path.exists(LOG_DIR):
        return jsonify([])
    files = glob.glob(os.path.join(LOG_DIR, "scan_*.json"))
    history = []
    for f in files:
        try:
            fname = os.path.basename(f)
            with open(f, 'r', encoding='utf-8') as jf:
                d = json.load(jf)
                s = d.get('system', {})
                history.append({
                    "filename": fname,
                    "hostname": s.get('hostname', 'Unknown'),
                    "scan_time": s.get('scan_time', 'Unknown'),
                    "red_flags": s.get('red_flags', 0)
                })
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            logger.debug("履歴エントリをスキップ", exc_info=True)
            continue
    return jsonify(sorted(history, key=lambda x: x['scan_time'], reverse=True))

@app.route('/api/history/load/<filename>')
def load_history(filename):
    global scan_results
    fp = _safe_history_path(filename)
    if not fp:
        return jsonify({"status": "error", "message": "Invalid filename"})
    if os.path.exists(fp):
        with open(fp, 'r', encoding='utf-8') as f:
            data = json.load(f)
        with _state_lock:
            scan_results = data
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "File not found"})

# 【追加】削除機能
@app.route('/api/history/delete/<filename>', methods=['DELETE'])
def delete_history(filename):
    fp = _safe_history_path(filename)
    if not fp:
        return jsonify({"status": "error", "message": "Invalid filename"})
    if os.path.exists(fp):
        try:
            os.remove(fp)
            return jsonify({"status": "ok"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "error", "message": "File not found"})


@app.route('/api/analysis/diff', methods=['POST'])
def api_analysis_diff():
    """履歴 JSON（baseline）と現在の scan_results を比較。"""
    data = request.get_json() or {}
    baseline_file = data.get('baseline_file')
    if not baseline_file:
        return jsonify({"status": "error", "message": "baseline_file が必要です"})
    fp = _safe_history_path(baseline_file)
    if not fp or not os.path.isfile(fp):
        return jsonify({"status": "error", "message": "ベースラインが見つかりません"})
    try:
        baseline = load_scan_json(fp)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    with _state_lock:
        current = copy.deepcopy(scan_results)
    d = diff_scans(baseline, current)
    return jsonify({"status": "ok", **d})


@app.route('/api/ioc/status')
def api_ioc_status():
    try:
        return jsonify({"status": "ok", **get_ioc_stats()})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/ioc/import', methods=['POST'])
def api_ioc_import():
    data = request.get_json() or {}
    text = data.get('text', '')
    replace = bool(data.get('replace'))
    try:
        r = parse_ioc_import_text(text, replace=replace)
        return jsonify({"status": "ok", **r})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/ioc/clear', methods=['POST'])
def api_ioc_clear():
    try:
        clear_user_iocs()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ============================================
# P26: Memory Dump & Analysis API
# ============================================

@app.route('/api/memdump/list')
def memdump_list():
    try:
        procs = _memdumper.list_processes()
        return jsonify({"status": "ok", "processes": procs})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/dump', methods=['POST'])
def memdump_dump():
    data = request.get_json()
    pid = data.get('pid')
    output_dir = data.get('output_dir') or None
    if not pid:
        return jsonify({"status": "error", "message": "pid is required"})
    try:
        result = _memdumper.dump_process(int(pid), output_dir)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/strings', methods=['POST'])
def memdump_strings():
    data = request.get_json()
    pid = data.get('pid')
    min_len = data.get('min_len', 4)
    max_results = data.get('max_results', 5000)
    if not pid:
        return jsonify({"status": "error", "message": "pid is required"})
    try:
        result = _memdumper.extract_strings(int(pid), int(min_len), int(max_results))
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/dlls/<int:pid>')
def memdump_dlls(pid):
    try:
        result = _memdumper.list_dlls(pid)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/memmap/<int:pid>')
def memdump_memmap(pid):
    try:
        result = _memdumper.memory_map(pid)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/pe/scan/<int:pid>')
def memdump_pe_scan(pid):
    try:
        result = _memdumper.scan_pe_headers(pid)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/pe/export', methods=['POST'])
def memdump_pe_export():
    data = request.get_json()
    pid = data.get('pid')
    address = data.get('address')
    output_dir = data.get('output_dir') or None
    if not pid or not address:
        return jsonify({"status": "error", "message": "pid and address required"})
    try:
        result = _memdumper.export_pe(int(pid), address, output_dir)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/hex', methods=['POST'])
def memdump_hex():
    data = request.get_json()
    pid = data.get('pid')
    address = data.get('address')
    size = data.get('size', 256)
    if not pid or not address:
        return jsonify({"status": "error", "message": "pid and address required"})
    try:
        result = _memdumper.read_hex(int(pid), address, int(size))
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ============================================
# P26-ext: Memory Dump Extended API
# ============================================

@app.route('/api/memdump/outputdir', methods=['GET'])
def memdump_get_outputdir():
    return jsonify({"status": "ok", "output_dir": _memdumper.get_output_dir()})

@app.route('/api/memdump/outputdir', methods=['POST'])
def memdump_set_outputdir():
    data = request.get_json()
    new_dir = data.get('output_dir', '')
    if not new_dir:
        return jsonify({"status": "error", "message": "output_dir is required"})
    try:
        result = _memdumper.set_output_dir(new_dir)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/outputdir/browse')
def memdump_browse_outputdir():
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    folder = filedialog.askdirectory(title="出力先フォルダを選択")
    root.destroy()
    if folder:
        _memdumper.set_output_dir(folder)
        return jsonify({"status": "ok", "path": folder})
    return jsonify({"status": "cancelled"})

@app.route('/api/memdump/sysinfo')
def memdump_sysinfo():
    try:
        info = _memdumper.get_system_memory_info()
        return jsonify({"status": "ok", **info})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/dump/all', methods=['POST'])
def memdump_dump_all():
    data = request.get_json() or {}
    output_dir = data.get('output_dir') or None
    try:
        result = _memdumper.dump_all_processes(output_dir)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/dump/selective', methods=['POST'])
def memdump_dump_selective():
    data = request.get_json()
    pid = data.get('pid')
    if not pid:
        return jsonify({"status": "error", "message": "pid is required"})
    try:
        result = _memdumper.dump_process_selective(
            int(pid),
            output_dir=data.get('output_dir') or None,
            include_heap=data.get('include_heap', True),
            include_stack=data.get('include_stack', True),
            include_executable=data.get('include_executable', True),
            include_mapped=data.get('include_mapped', False),
            include_all=data.get('include_all', False)
        )
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/dump/full', methods=['POST'])
def memdump_dump_full():
    data = request.get_json() or {}
    output_dir = data.get('output_dir') or None
    try:
        result = _memdumper.dump_full_memory(output_dir)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/dumpfiles')
def memdump_list_dumpfiles():
    directory = request.args.get('dir', None)
    try:
        result = _memdumper.list_dump_files(directory)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/memdump/analyze', methods=['POST'])
def memdump_analyze_dump():
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    analysis_type = data.get('type', 'strings')
    try:
        result = _memdumper.analyze_dump_file(
            filepath,
            analysis_type=analysis_type,
            min_len=int(data.get('min_len', 4)),
            max_results=int(data.get('max_results', 5000)),
            hex_offset=int(data.get('hex_offset', 0)),
            hex_size=int(data.get('hex_size', 1024))
        )
        if result.get('error'):
            return jsonify({"status": "error", "message": result['error']})
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ============================================
# P27: File Inspector API
# ============================================

@app.route('/api/fileinspect/list', methods=['POST'])
def fileinspect_list():
    data = request.get_json()
    folder = data.get('folder', '')
    include_sub = data.get('include_subfolders', False)
    if not folder:
        return jsonify({"status": "error", "message": "folder is required"})
    try:
        result = _file_inspector.list_folder(folder, include_sub)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fileinspect/hashes', methods=['POST'])
def fileinspect_hashes():
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    try:
        hashes = _file_inspector.get_file_hashes(filepath)
        return jsonify({"status": "ok", **hashes})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fileinspect/browse')
def fileinspect_browse():
    """Open native folder selection dialog."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        folder = filedialog.askdirectory(title='検査対象フォルダを選択')
        root.destroy()
        if folder:
            return jsonify({"status": "ok", "folder": folder})
        return jsonify({"status": "cancelled"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fileinspect/analyze', methods=['POST'])
def fileinspect_analyze():
    """Deep analysis of a single file (OLE/OOXML/PDF)."""
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    try:
        result = _file_inspector.analyze_file_deep(filepath)
        if result.get('error'):
            return jsonify({"status": "error", "message": result['error']})
        return jsonify({"status": "ok", "analysis": result['analysis']})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fileinspect/inspect', methods=['POST'])
def fileinspect_inspect():
    """Quick inspect: basic analysis + deep analysis combined."""
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    try:
        # Basic analysis (already in P27-A)
        basic = _file_inspector.analyze_file(filepath)
        # Hash calculation
        hashes = _file_inspector.get_file_hashes(filepath)
        if hashes:
            basic['md5'] = hashes.get('md5', '')
            basic['sha256'] = hashes.get('sha256', '')
        # Deep analysis (P27-B)
        deep = _file_inspector.analyze_file_deep(filepath)
        # Merge deep findings into basic
        if deep.get('analysis'):
            da = deep['analysis']
            basic['deep_analysis'] = da
            # Upgrade status if deep found worse
            priority = {'DANGER': 3, 'WARNING': 2, 'INFO': 1, 'SAFE': 0}
            if priority.get(da.get('status', ''), 0) > priority.get(basic.get('status', ''), 0):
                basic['status'] = da['status']
            # Merge MITRE (deduplicated)
            existing = set(basic.get('mitre', []))
            for m in da.get('mitre', []):
                if m not in existing:
                    basic.setdefault('mitre', []).append(m)
                    existing.add(m)
            # Merge findings
            for f in da.get('findings', []):
                basic.setdefault('findings', []).append(f)
        return jsonify({"status": "ok", "result": basic})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})





# P27-D: YARA Manager API

@app.route('/api/yara/status')
def yara_status():
    try:
        return jsonify({"status": "ok", **_yara_manager.get_status()})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/rules')
def yara_rules():
    try:
        rules = _yara_manager.list_rules()
        return jsonify({"status": "ok", "rules": rules})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/compile', methods=['POST'])
def yara_compile():
    try:
        result = _yara_manager.compile_rules()
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/scan', methods=['POST'])
def yara_scan():
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    try:
        result = _yara_manager.scan_file(filepath)
        if result.get('error'):
            return jsonify({"status": "error", "message": result['error'], "matches": result.get('matches', [])})
        return jsonify({"status": "ok", "matches": result['matches']})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/import', methods=['POST'])
def yara_import():
    data = request.get_json()
    source = data.get('source', '')
    category = data.get('category', 'imported')
    if not source:
        return jsonify({"status": "error", "message": "source path is required"})
    try:
        result = _yara_manager.import_rules(source, category)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/download', methods=['POST'])
def yara_download():
    data = request.get_json()
    url = data.get('url', '')
    name = data.get('name', 'downloaded')
    if not url:
        return jsonify({"status": "error", "message": "url is required"})
    try:
        result = _yara_manager.download_ruleset(url, name)
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/delete', methods=['POST'])
def yara_delete():
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    try:
        result = _yara_manager.delete_rule(filepath)
        return jsonify({"status": "ok" if result['success'] else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/browse')
def yara_browse():
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        path = filedialog.askdirectory(title='YARAルールフォルダを選択')
        root.destroy()
        if path:
            return jsonify({"status": "ok", "folder": path})
        return jsonify({"status": "cancelled"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ================================================================
# P28-A: YARA管理・検査タブ用 API
# ================================================================

@app.route('/api/yara/tree')
def yara_tree():
    try:
        tree = _yara_manager.get_rule_tree()
        return jsonify({"status": "ok", "tree": tree})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/rule/content', methods=['POST'])
def yara_rule_content():
    data = request.get_json()
    filepath = data.get('filepath', '')
    if not filepath:
        return jsonify({"status": "error", "message": "filepath is required"})
    try:
        result = _yara_manager.get_rule_content(filepath)
        return jsonify({"status": "ok" if result.get('success') else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/rule/save', methods=['POST'])
def yara_rule_save():
    data = request.get_json()
    filepath = data.get('filepath', '')
    content = data.get('content', '')
    if not filepath or not content:
        return jsonify({"status": "error", "message": "filepath and content are required"})
    try:
        result = _yara_manager.save_rule_content(filepath, content)
        return jsonify({"status": "ok" if result.get('success') else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/rule/create', methods=['POST'])
def yara_rule_create():
    data = request.get_json()
    category = data.get('category', 'custom')
    name = data.get('name', '')
    content = data.get('content', None)
    if not name:
        return jsonify({"status": "error", "message": "name is required"})
    try:
        result = _yara_manager.create_rule(category, name, content)
        return jsonify({"status": "ok" if result.get('success') else "error", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/search', methods=['POST'])
def yara_search():
    data = request.get_json()
    query = data.get('query', '')
    if not query:
        return jsonify({"status": "ok", "results": []})
    try:
        results = _yara_manager.search_rules(query)
        return jsonify({"status": "ok", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/scan/manual', methods=['POST'])
def yara_scan_manual():
    data = request.get_json()
    target = data.get('target', '')
    if not target:
        return jsonify({"status": "error", "message": "target is required"})
    try:
        if os.path.isdir(target):
            result = _yara_manager.scan_directory(target)
        elif os.path.isfile(target):
            scan = _yara_manager.scan_file(target)
            result = {"scanned": 1, "matched": 1 if scan.get("matches") else 0, "errors": 0, "results": [{"filepath": target, "filename": os.path.basename(target), "matches": scan.get("matches", [])}] if scan.get("matches") else []}
        else:
            return jsonify({"status": "error", "message": "対象が見つかりません"})
        return jsonify({"status": "ok", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/yara/presets')
def yara_presets():
    try:
        presets = _yara_manager.get_presets()
        return jsonify({"status": "ok", "presets": presets})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# --- メインロジック ---
def save_report(data):
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
        except OSError:
            pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"scan_{ts}.json"
    fpath = os.path.join(LOG_DIR, fname)

    try:
        with open(fpath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.info("レポート保存完了: %s", fpath)
    except OSError as e:
        logger.error("レポート保存エラー: %s", e)

# ============================================
# Scan API (background thread)
# ============================================
_scan_status = {
    "running": False,
    "progress": 0,
    "step": "",
    "detail": "",
    "done": False,
    "error": None,
}

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    global _scan_status
    with _state_lock:
        if _scan_status["running"]:
            return jsonify({"status": "error", "message": "Scan already running"})
        _scan_status = {
            "running": True,
            "progress": 0,
            "step": "Starting...",
            "detail": "",
            "done": False,
            "error": None,
        }
    t = threading.Thread(target=_run_scan, daemon=True)
    t.start()
    return jsonify({"status": "ok", "message": "Scan started"})

@app.route('/api/scan/status')
def api_scan_status():
    with _state_lock:
        return jsonify(dict(_scan_status))


def assign_uids(items):
    """全アーティファクトに一意の _uid を付与"""
    for item in items:
        if '_uid' not in item:
            item['_uid'] = uuid.uuid4().hex[:12]
    return items

def _run_scan():
    global scan_results, _scan_status
    try:
        self_pid = os.getpid()
        self_ppid = os.getppid()
        scan_start_time = datetime.now()

        def update(step, progress):
            with _state_lock:
                _scan_status["step"] = step
                _scan_status["progress"] = progress
                _scan_status["detail"] = ""

        def set_scan_detail(text):
            """サブスキャン内の細かい進捗（ファイル名など）。進捗バー%は update のまま。"""
            with _state_lock:
                if text:
                    _scan_status["detail"] = str(text)[:420]
                else:
                    _scan_status["detail"] = ""

        # 1. Process & DNA & PE-sieve
        update("プロセス & DNA & メモリインジェクション解析中...", 5)
        proc_c = ProcessCollector()
        procs = proc_c.scan()
        dna_c = DNACollector()
        for p in procs:
            if p['status'] != 'SAFE' and os.path.exists(p['path']):
                set_scan_detail("DNA · " + os.path.basename(p["path"]))
                res = dna_c.analyze_file(p['path'])
                if res:
                    p['dna'] = res
                    if res.get('sha256'):
                        try:
                            hit = check_sha256_ioc(res['sha256'])
                            if hit:
                                p['ioc_match'] = hit['name']
                                p['ioc_category'] = hit['category_jp']
                                p['ioc_mitre'] = hit['mitre']
                                p['ioc_severity'] = hit['severity']
                                p['reason'] = (p.get('reason') or '') + ' [IOC:' + hit['name'] + ']'
                        except (OSError, ValueError, TypeError, KeyError) as exc:
                            logger.debug("IOC 照会をスキップ: %s", exc)
                    if res['entropy'] > 7.2:
                        p['reason'] += " [高エントロピー]"
                        p['status'] = "DANGER"

        # 2. Memory
        update("メモリ解析中...", 15)
        mem_c = MemoryCollector()
        injections = mem_c.scan(on_detail=set_scan_detail)

        # 3. Persistence
        update("永続化設定チェック中...", 25)
        pers_c = PersistenceCollector()
        reg_c = RegistryCollector()
        persistence = reg_c.scan() + pers_c.scan()

        # 4. Network
        update("ネットワーク解析中...", 35)
        net_c = NetworkCollector()
        networks = net_c.scan()

        # 5. Evidence
        update("実行痕跡解析中...", 45)
        evid_c = EvidenceCollector()
        evidence = evid_c.scan(on_detail=set_scan_detail)

        # 6. EventLog
        update("イベントログ解析中...", 55)
        evt_c = EventLogCollector()
        logs = evt_c.scan()

        # 7. PCA
        update("PCA実行履歴解析中...", 62)
        pca_c = PCACollector()
        pca_results = pca_c.scan()

        # 8. ADS
        update("ダウンロード元追跡中...", 70)
        ads_c = ADSCollector()
        ads_results = ads_c.scan()

        # 9. WSL
        update("WSL環境検査中...", 77)
        wsl_c = WSLCollector()
        wsl_results = wsl_c.scan()

        # 10. CAM
        update("CAM DB解析中...", 82)
        cam_c = CAMCollector()
        cam_results = cam_c.scan()

        # 11. SRUM
        update("SRUM解析中...", 88)
        srum_c = SRUMCollector()
        srum_results = srum_c.scan()

        # 12. Recall
        update("Recall検知中...", 94)
        recall_c = RecallCollector()
        recall_results = recall_c.scan()

        # 13. BinaryRename
        update("バイナリリネーム検知中...", 95)
        binrename_c = BinaryRenameCollector()
        binrename_results = binrename_c.scan()

        # 14. LNK Forensics
        update("LNKファイル解析中...", 96)
        lnk_c = LnkForensicsCollector()
        lnk_results = lnk_c.scan()

        # 15. Mutant (ミューテックス)
        update("ミューテックス検知中...", 97)
        mutant_c = MutantCollector()
        mutant_results = mutant_c.scan()

        # 16. セキュリティ製品表面 / スキャン範囲ガイダンス（ユーザーモードのみ）
        update("セキュリティ面チェック中...", 98)
        security_surface = SecuritySurfaceCollector().scan()

        # Self-marking
        update("自己除外処理中...", 99)
        self_pids = {self_pid, self_ppid}
        for p in procs:
            p['is_self'] = p['pid'] in self_pids
        for n in networks:
            n['is_self'] = n.get('pid') in self_pids
        for m in injections:
            m['is_self'] = m.get('pid') in self_pids
        self_event_ids = {'4672', '4688', '4104'}
        for evt in logs:
            evt['is_self'] = False
            if evt.get('id') in self_event_ids:
                try:
                    evt_time = datetime.strptime(evt.get('time', ''), '%Y-%m-%d %H:%M:%S')
                    diff = abs((scan_start_time - evt_time).total_seconds())
                    if diff <= 120:
                        msg_lower = (evt.get('message', '') or '').lower()
                        if any(kw in msg_lower for kw in ['python', 'flask', 'sacabambaspis', 'powershell', 'main.py']):
                            evt['is_self'] = True
                except (ValueError, TypeError):
                    pass
        for e in evidence:
            e['is_self'] = False
        for br in binrename_results:
            br['is_self'] = False
        for lnk in lnk_results:
            lnk['is_self'] = False
        for mt in mutant_results:
            mt['is_self'] = False
        for p in persistence:
            p['is_self'] = False
        for sv in security_surface:
            sv['is_self'] = False

        # Aggregate（Threats バッジ: 各カテゴリの DANGER を自己関連イベント除きで合算）
        update("集計・スコアリング中...", 100)
        flags = sum(1 for x in procs if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in persistence if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in networks if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in logs if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in injections if x.get('status')=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in evidence if x.get('status')=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in pca_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in ads_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in wsl_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in cam_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in srum_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in recall_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in binrename_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in lnk_results if x['status']=='DANGER' and not x.get('is_self')) + \
                sum(1 for x in mutant_results if x['status']=='DANGER' and not x.get('is_self'))

        # UUID付与（証拠保全用一意識別子）
        assign_uids(procs)
        assign_uids(injections)
        assign_uids(persistence)
        assign_uids(networks)
        assign_uids(evidence)
        assign_uids(logs)
        assign_uids(pca_results)
        assign_uids(ads_results)
        assign_uids(wsl_results)
        assign_uids(cam_results)
        assign_uids(srum_results)
        assign_uids(recall_results)
        assign_uids(binrename_results)
        assign_uids(lnk_results)
        assign_uids(mutant_results)
        assign_uids(security_surface)

        result = {
            "system": {
                "hostname": socket.gethostname(),
                "os": os.name.upper(),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "red_flags": flags,
                "scan_capabilities": build_scan_capability_report(len(security_surface)),
            },
            "processes": procs,
            "memory": injections,
            "persistence": persistence,
            "networks": networks,
            "evidence": evidence,
            "eventlogs": logs,
            "pca": pca_results,
            "ads": ads_results,
            "wsl": wsl_results,
            "cam": cam_results,
            "srum": srum_results,
            "recall": recall_results,
            "binrename": binrename_results,
            "lnk": lnk_results,
            "mutant": mutant_results,
            "security_surface": security_surface,
        }

        threat_assessment = calculate_threat_score(result)
        result["system"]["threat_score"] = threat_assessment["total_danger"]
        result["system"]["threat_level"] = threat_assessment["level"]
        result["system"]["threat_level_ja"] = threat_assessment["level_ja"]
        result["system"]["threat_verdict"] = threat_assessment["verdict"]
        result["threat_assessment"] = threat_assessment

        save_report(result)

        with _state_lock:
            scan_results = result
            _scan_status["progress"] = 100
            _scan_status["step"] = "完了"
            _scan_status["detail"] = ""
            _scan_status["done"] = True
            _scan_status["running"] = False

    except Exception as e:
        logger.exception("スキャンパイプラインが失敗しました")
        with _state_lock:
            _scan_status["error"] = str(e)
            _scan_status["step"] = "エラー発生"
            _scan_status["detail"] = ""
            _scan_status["running"] = False
            _scan_status["done"] = True

# F1-d: 安全なシャットダウンエンドポイント
@app.route('/api/shutdown', methods=['POST'])
def shutdown_server():
    """UIからサーバーを安全に終了する"""
    import os
    def _shutdown():
        time.sleep(0.5)
        os._exit(0)
    threading.Thread(target=_shutdown, daemon=True).start()
    return jsonify({"status": "ok", "message": "サーバーを終了します"})


def start_server_only():
    """Start web server without scanning. Scan triggered via UI button."""
    global scan_results

    with _state_lock:
        scan_results = {}

    port = find_free_port()
    logger.info("Server starting on port %s (UI の Scan で解析を開始)", port)
    url = f"http://127.0.0.1:{port}"

    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)


# Flaskのデバッグモードやリローダーを使わない（PyInstaller対策）
if __name__ == "__main__":
    pass