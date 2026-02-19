# -*- coding: utf-8 -*-
import sys
import os
import socket
import json
import glob
import time
import threading
import webbrowser
from datetime import datetime
from flask import Flask, render_template, jsonify
from utils.path_helper import resource_path

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


# --- 設定 ---
template_dir = resource_path(os.path.join('web', 'templates'))
static_dir = resource_path(os.path.join('web', 'static'))

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)


# ================================================================
# P15: 統合脅威スコアリングエンジン
# ================================================================
def calculate_threat_score(scan_data):
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

    if len(danger_categories) >= 5:
        correlation_reasons.append(f'{len(danger_categories)}カテゴリでDANGER検知 → 深刻な侵害の可能性')
    elif len(danger_categories) >= 3:
        correlation_reasons.append(f'{len(danger_categories)}カテゴリでDANGER検知 → APT活動の兆候')

    # 脅威レベル: DANGERカテゴリ数で判定
    dc = len(danger_categories)
    if dc >= 5:
        level = 'CRITICAL'
        level_ja = '🔴 深刻'
        verdict = f'{dc}カテゴリでDANGER検知。即座にインシデント対応を開始してください。'
    elif dc >= 3:
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
        'category_details': details
    }


def find_free_port(start=5000, end=5010):
    """空きポートを自動探索（UFED等との競合回避）"""
    for port in range(start, end + 1):
        try:
            import socket as _socket
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.bind(('127.0.0.1', port))
            s.close()
            return port
        except OSError:
            continue
    return start  # 全て埋まっている場合はデフォルト

# ベースディレクトリの決定（プロジェクトルートを基準にする）
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # web/app.py から1階層上がプロジェクトルート
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_DIR = os.path.join(BASE_DIR, "logs")

scan_results = {}

# --- ルーティング ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    return jsonify(scan_results)

# --- 履歴管理API ---
@app.route('/api/history/list')
def list_history():
    if not os.path.exists(LOG_DIR): return jsonify([])
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
        except: continue
    return jsonify(sorted(history, key=lambda x: x['scan_time'], reverse=True))

@app.route('/api/history/load/<filename>')
def load_history(filename):
    global scan_results
    fp = os.path.join(LOG_DIR, filename)
    # ディレクトリトラバーサル対策
    if os.path.dirname(fp) != LOG_DIR or ".." in filename:
        return jsonify({"status": "error", "message": "Invalid filename"})
    if os.path.exists(fp):
        with open(fp, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "File not found"})

# 【追加】削除機能
@app.route('/api/history/delete/<filename>')
def delete_history(filename):
    fp = os.path.join(LOG_DIR, filename)
    # 安全対策: logsフォルダ以外の削除を禁止
    if os.path.dirname(fp) != LOG_DIR or ".." in filename:
        return jsonify({"status": "error", "message": "Invalid filename"})
    
    if os.path.exists(fp):
        try:
            os.remove(fp)
            return jsonify({"status": "ok"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "error", "message": "File not found"})

# --- メインロジック ---
def save_report(data):
    if not os.path.exists(LOG_DIR):
        try: os.makedirs(LOG_DIR)
        except: pass
    
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"scan_{ts}.json"
    fpath = os.path.join(LOG_DIR, fname)
    
    try:
        with open(fpath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] レポート保存完了: {fpath}")
    except Exception as e:
        print(f"[!] 保存エラー: {e}")

def start_scan_and_server():
    global scan_results
    print("--------------------------------------------------")
    print("[*] Sacabambaspis スキャンエンジン起動...")

    # 自プロセスPID取得（自己除外用）
    self_pid = os.getpid()
    self_ppid = os.getppid()  # 親プロセス（python.exe等）も除外対象
    scan_start_time = datetime.now()
    print(f"[*] Self PID: {self_pid}, Parent PID: {self_ppid}")


    # 1. Process
    print("[1/12] プロセス & DNA...")

    proc_c = ProcessCollector()
    procs = proc_c.scan()

    dna_c = DNACollector()
    for p in procs:
        if p['status'] != 'SAFE' and os.path.exists(p['path']):
            res = dna_c.analyze_file(p['path'])
            if res:
                p['dna'] = res
                if res['entropy'] > 7.2:
                    p['reason'] += " [高エントロピー]"
                    p['status'] = "DANGER"

    # 2. Memory
    print("[2/12] メモリ...")

    mem_c = MemoryCollector()
    injections = mem_c.scan()

    # 3. Persistence
    print("[3/12] 永続化設定...")

    pers_c = PersistenceCollector()
    reg_c = RegistryCollector()
    persistence = reg_c.scan() + pers_c.scan()

    # 4. Network
    print("[4/12] ネットワーク...")

    net_c = NetworkCollector()
    networks = net_c.scan()

    # 5. Evidence
    print("[5/12] 実行痕跡...")

    evid_c = EvidenceCollector()
    evidence = evid_c.scan()

    # 6. EventLog
    print("[6/12] イベントログ...")
    evt_c = EventLogCollector()
    logs = evt_c.scan()

    # 7. PCA (実行痕跡拡張)
    print("[7/12] PCA実行履歴...")
    pca_c = PCACollector()
    pca_results = pca_c.scan()

    # 8. ADS (Zone.Identifier)
    print("[8/12] ダウンロード元追跡 (ADS)...")
    ads_c = ADSCollector()
    ads_results = ads_c.scan()

    # 9. WSL検知
    print("[9/12] WSL環境検査...")
    wsl_c = WSLCollector()
    wsl_results = wsl_c.scan()

    # 10. CAM DB
    print("[10/12] CAM DB解析...")
    cam_c = CAMCollector()
    cam_results = cam_c.scan()

    # 11. SRUM解析
    print("[11/12] SRUM解析...")
    srum_c = SRUMCollector()
    srum_results = srum_c.scan()

    # 12. Recall検知
    print("[12/12] Recall検知...")
    recall_c = RecallCollector()
    recall_results = recall_c.scan()


    # 自己除外マーキング: 自プロセスとその関連プロセスにフラグを付与
    self_pids = {self_pid, self_ppid}
    for p in procs:
        if p['pid'] in self_pids:
            p['is_self'] = True
        else:
            p['is_self'] = False
    for n in networks:
        if n.get('pid') in self_pids:
            n['is_self'] = True
        else:
            n['is_self'] = False
    for m in injections:
        if m.get('pid') in self_pids:
            m['is_self'] = True
        else:
            m['is_self'] = False

    # イベントログの自己判別: スキャン前後2分以内 + 自プロセス関連キーワードで判定
    self_event_ids = {'4672', '4688', '4104'}
    for evt in logs:
        evt['is_self'] = False  # デフォルト
        if evt.get('id') in self_event_ids:
            try:
                evt_time = datetime.strptime(evt.get('time', ''), '%Y-%m-%d %H:%M:%S')
                diff = abs((scan_start_time - evt_time).total_seconds())
                if diff <= 120:  # 前後2分以内
                    msg_lower = (evt.get('message', '') or '').lower()
                    if any(kw in msg_lower for kw in ['python', 'flask', 'sacabambaspis', 'powershell', 'main.py']):
                        evt['is_self'] = True
            except (ValueError, TypeError):
                pass
    # evidence と persistence にも is_self を設定（常にFalse）
    for e in evidence:
        e['is_self'] = False
    for p in persistence:
        p['is_self'] = False



    # 集計（自己除外分はカウントしない）
    flags = sum(1 for x in procs if x['status']=='DANGER' and not x.get('is_self')) + \
            sum(1 for x in persistence if x['status']=='DANGER') + \
            sum(1 for x in networks if x['status']=='DANGER' and not x.get('is_self')) + \
            sum(1 for x in logs if x['status']=='DANGER') + \
            sum(1 for x in injections if not x.get('is_self')) + \
            sum(1 for x in pca_results if x['status']=='DANGER') + \
            sum(1 for x in ads_results if x['status']=='DANGER') + \
            sum(1 for x in wsl_results if x['status']=='DANGER') + \
            sum(1 for x in cam_results if x['status']=='DANGER') + \
            sum(1 for x in srum_results if x['status']=='DANGER') + \
            sum(1 for x in recall_results if x['status']=='DANGER')


    scan_results = {
        "system": {
            "hostname": socket.gethostname(),
            "os": os.name.upper(),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "red_flags": flags
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
        "recall": recall_results
    }

    # P15: 統合脅威スコアリング
    threat_assessment = calculate_threat_score(scan_results)
    scan_results["system"]["threat_score"] = threat_assessment["total_danger"]
    scan_results["system"]["threat_level"] = threat_assessment["level"]
    scan_results["system"]["threat_level_ja"] = threat_assessment["level_ja"]
    scan_results["system"]["threat_verdict"] = threat_assessment["verdict"]
    scan_results["threat_assessment"] = threat_assessment

    print(f"[*] 脅威レベル: {threat_assessment['level_ja']}")
    print(f"    DANGER: {threat_assessment['total_danger']}件 / WARNING: {threat_assessment['total_warning']}件 / 全{threat_assessment['total_items']}件")
    print(f"    DANGER検知カテゴリ: {threat_assessment['danger_category_count']}個")
    if threat_assessment['correlation_reasons']:
        print(f"    相関検知: {', '.join(threat_assessment['correlation_reasons'])}")

    save_report(scan_results)
    
    print("[*] 完了。ブラウザを起動します。")
    port = find_free_port()
    print(f"[*] 使用ポート: {port}")
    url = f"http://127.0.0.1:{port}"

    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)


def start_viewer_only():
    """スキャンを実行せずにWebサーバーのみ起動（空のデータで起動）"""
    global scan_results

    print("--------------------------------------------------")
    print("[*] Viewer Only Mode - No scan, no auto-load.")
    print("[*] Use the History tab to load past scan data.")

    # 空データで起動
    scan_results = {}

    port = find_free_port()
    print(f"[*] Starting viewer on port {port}")
    url = f"http://127.0.0.1:{port}"

    import threading
    import webbrowser
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)


# Flaskのデバッグモードやリローダーを使わない（PyInstaller対策）
if __name__ == "__main__":
    pass