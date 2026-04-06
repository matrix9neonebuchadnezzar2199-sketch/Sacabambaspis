# -*- coding: utf-8 -*-
"""
CAM DB Collector - PcaGeneralDb 解析
Windows 11 22H2以降の Program Compatibility Assistant データベースを解析し、
プログラム実行履歴を取得する。
"""

import os
import sqlite3
import shutil
import tempfile
from datetime import datetime

try:
    from utils.tutor_template import build_tutor_desc
except ImportError:
    def build_tutor_desc(**kwargs):
        return kwargs.get('detection', '')


class CAMCollector:
    """PcaGeneralDb0.db / PcaGeneralDb1.db からプログラム実行履歴を取得"""

    # ERR-CAM-001: 攻撃ツール名リスト
    ATTACK_TOOLS = [
        'mimikatz', 'psexec', 'psexesvc', 'cobalt', 'beacon',
        'rubeus', 'seatbelt', 'sharphound', 'bloodhound',
        'lazagne', 'procdump', 'nanodump', 'pypykatz',
        'impacket', 'crackmapexec', 'evil-winrm', 'chisel',
        'ligolo', 'sliver', 'havoc', 'brute', 'hydra',
        'nmap', 'masscan', 'whoami', 'net.exe',
        'wce', 'gsecdump', 'pwdump', 'fgdump',
        'nc.exe', 'ncat', 'netcat', 'socat',
        'certutil', 'bitsadmin',
    ]

    # ERR-CAM-002: 不審な実行パスパターン
    SUSPICIOUS_PATHS = [
        '\\temp\\', '\\tmp\\', '\\users\\public\\',
        '\\$recycle.bin\\', '\\appdata\\local\\temp\\',
        '\\downloads\\', '\\desktop\\',
        '\\programdata\\', '\\perflogs\\',
    ]

    def __init__(self):
        self.db_paths = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'),
                         'appcompat', 'pca', 'PcaGeneralDb0.db'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'),
                         'appcompat', 'pca', 'PcaGeneralDb1.db'),
        ]

    def scan(self):
        """メインスキャン処理"""
        results = []
        for db_path in self.db_paths:
            if os.path.exists(db_path):
                try:
                    entries = self._read_db(db_path)
                    source = os.path.basename(db_path)
                    for entry in entries:
                        analyzed = self._analyze_entry(entry, source)
                        results.append(analyzed)
                except Exception as e:
                    # ERR-CAM-003: DB読込エラー
                    results.append({
                        'source': os.path.basename(db_path),
                        'program_name': 'ERROR',
                        'exe_path': str(e),
                        'run_time': '',
                        'run_count': 0,
                        'exit_code': '',
                        'file_exists': False,
                        'reason': f'DB読込エラー: {e}',
                        'desc': '',
                        'status': 'WARNING',
                        'is_self': False,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    })
        return results

    def _read_db(self, db_path):
        """SQLite DBをコピーしてから読み込む（ロック回避）"""
        entries = []
        tmp_path = None
        try:
            # ERR-CAM-004: ファイルコピーでロック回避
            tmp_dir = tempfile.mkdtemp()
            tmp_path = os.path.join(tmp_dir, 'pca_copy.db')
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # テーブル一覧を取得して適切なテーブルを探す
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row['name'] for row in cursor.fetchall()]

            for table_name in tables:
                try:
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = [col[1] for col in cursor.fetchall()]

                    # ExePath または FilePath を含むテーブルを対象とする
                    path_col = None
                    for c in columns:
                        if c.lower() in ('exepath', 'filepath', 'path', 'executablepath'):
                            path_col = c
                            break

                    if not path_col:
                        continue

                    # 時刻カラムの候補
                    time_col = None
                    for c in columns:
                        if c.lower() in ('timestamp', 'runtime', 'lastrun', 'time', 'date'):
                            time_col = c
                            break

                    # 実行回数カラムの候補
                    count_col = None
                    for c in columns:
                        if c.lower() in ('runcount', 'count', 'executioncount'):
                            count_col = c
                            break

                    # 終了コードカラムの候補
                    exit_col = None
                    for c in columns:
                        if c.lower() in ('exitcode', 'returncode', 'errorcode'):
                            exit_col = c
                            break

                    query = f"SELECT * FROM {table_name}"
                    cursor.execute(query)
                    rows = cursor.fetchall()

                    for row in rows:
                        exe_path = row[path_col] if path_col else ''
                        if not exe_path:
                            continue
                        entry = {
                            'exe_path': str(exe_path),
                            'run_time': str(row[time_col]) if time_col and row[time_col] else '',
                            'run_count': int(row[count_col]) if count_col and row[count_col] else 0,
                            'exit_code': str(row[exit_col]) if exit_col and row[exit_col] else '',
                        }
                        entries.append(entry)
                except Exception:
                    continue

            conn.close()
        except Exception as e:
            raise e
        finally:
            # 一時ファイルの削除
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                    os.rmdir(os.path.dirname(tmp_path))
                except Exception:
                    pass
        return entries

    def _analyze_entry(self, entry, source):
        """エントリを解析して判定"""
        exe_path = entry.get('exe_path', '')
        exe_name = os.path.basename(exe_path).lower() if exe_path else ''
        status = 'SAFE'
        reason = ''
        desc = ''

        # ファイル存在確認
        file_exists = os.path.exists(exe_path) if exe_path else False

        # ルール1: 攻撃ツール名検知
        for tool in self.ATTACK_TOOLS:
            if tool in exe_name:
                status = 'DANGER'
                reason = f'攻撃ツール検知: {tool}'
                desc = build_tutor_desc(
                    detection=(
                        f'CAM DB（PcaGeneralDb）に攻撃ツール「{tool}」の実行記録があります。\n'
                        f'パス: {exe_path}'
                    ),
                    why_dangerous=(
                        'CAM DB（PcaGeneralDb0.db）はWindows互換性アシスタントが記録する'
                        'アプリケーション実行履歴です。ファイルが削除されていても'
                        '実行記録が残るため、攻撃者のツール使用を事後的に証明できます。'
                    ),
                    mitre_key='cam_suspicious',
                    normal_vs_abnormal=(
                        '正常: CAM DBにはブラウザ、Office、ゲーム等の一般アプリのみ記録される\n'
                        '異常: mimikatz、psexec、cobalt strike等の攻撃・侵入テストツールが記録されている'
                    ),
                    next_steps=[
                        'ファイルが存在すればハッシュ値をVirusTotalで検索する',
                        'Prefetch/PCAと照合し実行時刻を特定する',
                        '同時刻帯の他の実行ファイルを確認する',
                        'イベントログ(Security:4688)で実行コンテキストを確認する',
                    ],
                    status='DANGER',
                )
                break

        # ルール2: 削除済みファイル
        if not file_exists and exe_path and status == 'SAFE':
            status = 'WARNING'
            reason = 'ファイル削除済み（実行痕跡のみ残存）'
            desc = build_tutor_desc(
                detection=(
                    f'CAM DBに実行記録がありますが、該当ファイルは既に削除されています。\n'
                    f'パス: {exe_path}'
                ),
                why_dangerous=(
                    '攻撃者はツールを使用した後、証拠隠滅のためにファイルを削除します。'
                    'しかしCAM DBやPrefetchには実行痕跡が残るため、削除後でも実行の事実を証明できます。'
                ),
                mitre_key='pca_attack_tool',
                normal_vs_abnormal=(
                    '正常: アンインストールしたアプリや一時的なインストーラの痕跡\n'
                    '異常: 見覚えのないツール名、攻撃ツールに類似した名前、短時間で削除された形跡'
                ),
                next_steps=[
                    'Prefetch/PCAで同一ファイルの実行時刻を特定する',
                    'ごみ箱やVolume Shadow Copyからファイル復元を試みる',
                    '削除時刻の前後のイベントログを確認する',
                ],
                status='WARNING',
            )

        # ルール3: 不審パスからの実行
        if status == 'SAFE':
            path_lower = exe_path.lower()
            for susp in self.SUSPICIOUS_PATHS:
                if susp in path_lower:
                    status = 'WARNING'
                    reason = f'不審なフォルダからの実行: {susp.strip(chr(92))}'
                    desc = build_tutor_desc(
                        detection=(
                            f'CAM DBに不審なフォルダからの実行が記録されています。\n'
                            f'パス: {exe_path}'
                        ),
                        why_dangerous=(
                            'Temp、Downloads、Public等のユーザー書き込み可能フォルダは'
                            '攻撃者がマルウェアを配置する定番の場所です。'
                            '正規アプリは通常C:\\Program Filesにインストールされます。'
                        ),
                        mitre_key='pca_suspicious_path',
                        normal_vs_abnormal=(
                            '正常: インストーラやアップデータがTempから一時的に実行される\n'
                            '異常: 見慣れないexeがTemp/Downloads/Publicから実行され、ファイル名がランダム文字列'
                        ),
                        next_steps=[
                            'ファイルが存在すればデジタル署名を確認する',
                            'Zone.Identifier(ADS)でダウンロード元を確認する',
                            '同一パスに他の不審ファイルがないか確認する',
                        ],
                        status='WARNING',
                    )
                    break

        # ルール4: 異常な終了コード
        exit_code = entry.get('exit_code', '')
        if exit_code and exit_code not in ('', '0', 'None') and status == 'SAFE':
            try:
                code_int = int(exit_code)
                if code_int != 0 and code_int != 1:
                    status = 'WARNING'
                    reason = f'異常な終了コード: {exit_code}'
                    desc = build_tutor_desc(
                        detection=(
                            f'CAM DBに記録されたプログラムが異常終了しています。\n'
                            f'プログラム: {exe_path}\n'
                            f'終了コード: {exit_code}'
                        ),
                        why_dangerous=(
                            '異常終了コードは、プログラムのクラッシュ、権限不足による失敗、'
                            'またはセキュリティソフトによる強制終了を示します。'
                            '攻撃者のツールがAV/EDRに検知されて強制終了された可能性もあります。'
                        ),
                        mitre_key=None,
                        normal_vs_abnormal=(
                            '正常: 終了コード0（正常終了）または1（軽微なエラー）\n'
                            '異常: 0xC0000005（アクセス違反）、0xC000013A（Ctrl+Cによる終了）、大きな負の値'
                        ),
                        next_steps=[
                            '終了コードの意味を確認する（0xC0000005=アクセス違反等）',
                            '同時刻のセキュリティソフトのログを確認する',
                            'プログラムの正体をハッシュ値やデジタル署名で確認する',
                        ],
                        status='WARNING',
                    )
            except ValueError:
                pass

        # タイムスタンプの整形
        run_time = entry.get('run_time', '')
        timestamp = run_time if run_time else datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return {
            'source': source,
            'program_name': exe_name or os.path.basename(exe_path),
            'exe_path': exe_path,
            'run_time': run_time,
            'run_count': entry.get('run_count', 0),
            'exit_code': exit_code,
            'file_exists': file_exists,
            'reason': reason,
            'desc': desc,
            'status': status,
            'is_self': False,
            'timestamp': timestamp,
        }
