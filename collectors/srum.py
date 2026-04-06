# -*- coding: utf-8 -*-
"""
SRUM Collector - System Resource Usage Monitor 解析
SRUDB.dat のメタデータ解析と、NetworkUsage/AppTimeline のレジストリベース推定を行う。

注意: SRUDB.dat は ESEデータベースのため、pyesedb無しでは直接読込不可。
本コレクターでは以下のアプローチを採用:
  1. SRUDB.dat のメタデータ（サイズ・更新日時）を取得
  2. esentutl でコピーを試み、成功すれば追加解析
  3. SRU関連レジストリからアプリ使用情報を取得
  4. 異常検知（巨大DB、古い更新日時 = 改ざんの疑い）
"""

import os
import subprocess
import tempfile
import shutil
import winreg
from datetime import datetime

try:
    from utils.tutor_template import build_tutor_desc
except ImportError:
    def build_tutor_desc(**kwargs):
        return kwargs.get('detection', '')

from utils import threat_lists as _tl


class SRUMCollector:
    """System Resource Usage Monitor の解析"""

    # ERR-SRUM-001: SRUDBパス
    SRUDB_PATH = os.path.join(
        os.environ.get('SYSTEMROOT', 'C:\\Windows'),
        'System32', 'sru', 'SRUDB.dat'
    )

    # ERR-SRUM-002: SRU関連レジストリ
    SRU_REG_PATH = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions'

    # ERR-SRUM-003: ネットワーク使用量の閾値
    LARGE_DB_THRESHOLD_MB = 500  # DBサイズがこれ以上なら警告
    VERY_LARGE_DB_THRESHOLD_MB = 2000  # DBサイズがこれ以上なら危険

    # ERR-SRUM-004: 攻撃ツールパターン（threat_lists 一元管理）
    ATTACK_TOOLS = _tl.ATTACK_TOOLS

    def __init__(self):
        pass

    def scan(self):
        """メインスキャン処理"""
        results = []

        # 1. SRUDB.dat のメタデータ解析
        results.extend(self._check_srudb_metadata())

        # 2. SRU拡張レジストリの確認
        results.extend(self._check_sru_extensions())

        # 3. esentutl によるDBコピー＆テーブル一覧取得
        results.extend(self._try_esentutl_copy())

        # 4. NetworkUsage テーブルの推定（netstat ベース）
        results.extend(self._estimate_network_usage())

        return results

    def _check_srudb_metadata(self):
        """SRUDB.dat の存在・サイズ・更新日時を検査"""
        results = []

        if not os.path.exists(self.SRUDB_PATH):
            results.append(self._make_entry(
                source='SRUDB.dat',
                app_name='SRUDB.dat',
                detail='SRUDBファイルが見つかりません',
                reason='SRUDB.dat が存在しない（削除された可能性）',
                desc=build_tutor_desc(
                    detection='SRUDB.dat が存在しません。',
                    why_dangerous=(
                        'SRUDBはWindowsのリソース使用量モニター（SRUM）のデータベースです。'
                        'アプリ実行履歴・ネットワーク通信量・電力使用量等が記録されています。'
                        '攻撃者が証拠隠滅のためにSRUDBを削除した可能性があります。'
                    ),
                    mitre_key='srum_high_network',
                    normal_vs_abnormal=(
                        '正常: SRUDB.datはC:\\Windows\\System32\\sru\\に常に存在する\n'
                        '異常: ファイルが存在しない、またはサイズが0バイト'
                    ),
                    next_steps=[
                        'Volume Shadow CopyからSRUDBの復元を試みる',
                        'DiagTrackサービスの状態を確認する',
                        'イベントログでファイル削除の痕跡を確認する',
                    ],
                    status='WARNING',
                ),
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))
            return results

        try:
            stat = os.stat(self.SRUDB_PATH)
            size_mb = stat.st_size / (1024 * 1024)
            mtime = datetime.fromtimestamp(stat.st_mtime)
            ctime = datetime.fromtimestamp(stat.st_ctime)
            age_days = (datetime.now() - mtime).days

            status = 'SAFE'
            reason = ''
            desc = ''

            # 巨大DB検知
            if size_mb >= self.VERY_LARGE_DB_THRESHOLD_MB:
                status = 'DANGER'
                reason = f'SRUDBが異常に巨大: {size_mb:.0f}MB'
                desc = build_tutor_desc(
                    detection=f'SRUDBが {size_mb:.0f}MB あり、通常（50-300MB）を大幅に超えています。',
                    why_dangerous=(
                        'SRUDBの異常な肥大化は、大量のアプリ実行や'
                        'ネットワーク通信が行われていることを示唆します。'
                        'C2ビーコニングや大量データ送信（情報窃取）が記録されている可能性があります。'
                    ),
                    mitre_key='srum_high_network',
                    normal_vs_abnormal=(
                        '正常: SRUDBは通常50〜300MB程度\n'
                        '異常: 2GB以上に肥大化している場合、大量の通信やアプリ実行が発生している'
                    ),
                    next_steps=[
                        'srum-dump や SrumECmd で詳細なネットワーク通信量を解析する',
                        '異常に通信量の多いプロセスを特定する',
                        '通信先IPアドレスの評判を調査する',
                    ],
                    status='DANGER',
                )
            elif size_mb >= self.LARGE_DB_THRESHOLD_MB:
                status = 'WARNING'
                reason = f'SRUDBサイズが大きい: {size_mb:.0f}MB'
                desc = build_tutor_desc(
                    detection=f'SRUDBが {size_mb:.0f}MB あり、やや大きめです。',
                    why_dangerous=(
                        '長期間のデータが蓄積されています。'
                        'フォレンジック的には豊富な履歴が取得できる可能性があります。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 長期運用マシンでは500MB程度になることもある\n'
                        '異常: 短期間で急激にサイズが増加した場合は要注意'
                    ),
                    next_steps=[
                        'srum-dump で通信量の上位プロセスを確認する',
                        'サイズ増加の時期と他のイベントを照合する',
                    ],
                    status='WARNING',
                )

            # 更新日時が古い場合（30日以上前）
            if age_days > 30 and status == 'SAFE':
                status = 'WARNING'
                reason = f'SRUDBの最終更新が {age_days}日前'
                desc = build_tutor_desc(
                    detection=f'SRUDBが {age_days}日間更新されていません。',
                    why_dangerous=(
                        'SRUサービス（DiagTrack）が停止している、'
                        'またはDBが改ざん・凍結されている可能性があります。'
                        '攻撃者がSRUによる通信量記録を回避するため、'
                        'サービスを停止させた可能性も考えられます。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: SRUDBは数時間〜1日おきに更新される\n'
                        '異常: 30日以上更新がない場合、SRUサービスが停止している'
                    ),
                    next_steps=[
                        'DiagTrackサービスの状態を確認する（sc query DiagTrack）',
                        'サービス停止のイベントログ(System:7036)を確認する',
                        'レジストリでSRU設定の変更有無を確認する',
                    ],
                    status='WARNING',
                )

            results.append(self._make_entry(
                source='SRUDB.dat',
                app_name='SRUDB メタデータ',
                detail=f'サイズ: {size_mb:.1f}MB | 更新: {mtime.strftime("%Y-%m-%d %H:%M:%S")} | 作成: {ctime.strftime("%Y-%m-%d %H:%M:%S")}',
                reason=reason,
                desc=desc,
                status=status,
                timestamp=mtime.strftime('%Y-%m-%d %H:%M:%S'),
                network_sent='',
                network_recv='',
                cpu_time='',
                user_sid='',
            ))
        except PermissionError:
            results.append(self._make_entry(
                source='SRUDB.dat',
                app_name='SRUDB メタデータ',
                detail='アクセス権限不足（管理者権限が必要）',
                reason='SRUDB.dat へのアクセスが拒否されました',
                desc=build_tutor_desc(
                    detection='SRUDB.datへのアクセスが拒否されました。',
                    why_dangerous='管理者権限で再実行してください。SRUDBの解析には管理者権限が必要です。',
                    mitre_key=None,
                    status='WARNING',
                ),
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))
        except Exception as e:
            results.append(self._make_entry(
                source='SRUDB.dat',
                app_name='ERROR',
                detail=str(e),
                reason=f'メタデータ取得エラー: {e}',
                desc='',
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))

        return results


    def _check_sru_extensions(self):
        """SRU拡張レジストリを確認し、記録カテゴリを列挙"""
        results = []
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.SRU_REG_PATH)
            i = 0
            extensions = []
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    sub = winreg.OpenKey(key, subkey_name)
                    try:
                        dll_name, _ = winreg.QueryValueEx(sub, '')
                        extensions.append(f'{subkey_name}: {dll_name}')
                    except FileNotFoundError:
                        extensions.append(subkey_name)
                    winreg.CloseKey(sub)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)

            if extensions:
                results.append(self._make_entry(
                    source='レジストリ',
                    app_name='SRU Extensions',
                    detail=f'{len(extensions)}個の記録カテゴリが登録',
                    reason='',
                    desc=build_tutor_desc(
                        detection=f'SRUに{len(extensions)}個の記録カテゴリが登録されています。\n' + '\n'.join(extensions[:10]),
                        why_dangerous='SRUが正常に動作しており、各カテゴリのデータを記録しています。',
                        mitre_key=None,
                        normal_vs_abnormal=(
                            '正常: NetworkUsage、AppTimeline等の標準カテゴリが存在する\n'
                            '異常: カテゴリが極端に少ない、または存在しない'
                        ),
                        status='INFO',
                    ),
                    status='INFO',
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                ))
        except FileNotFoundError:
            results.append(self._make_entry(
                source='レジストリ',
                app_name='SRU Extensions',
                detail='SRU拡張レジストリが見つかりません',
                reason='SRUが無効化されている可能性',
                desc=build_tutor_desc(
                    detection='SRUの拡張レジストリキーが存在しません。',
                    why_dangerous=(
                        'SRUが無効化されている場合、アプリ実行履歴や'
                        'ネットワーク通信量の記録が停止しています。'
                        '攻撃者が検知回避のために無効化した可能性があります。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: SRU Extensionsレジストリキーは標準で存在する\n'
                        '異常: キーが存在しない場合、SRUが意図的に無効化されている'
                    ),
                    next_steps=[
                        'DiagTrackサービスの状態を確認する',
                        'グループポリシーでSRUが無効化されていないか確認する',
                    ],
                    status='WARNING',
                ),
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))
        except Exception as e:
            results.append(self._make_entry(
                source='レジストリ',
                app_name='ERROR',
                detail=str(e),
                reason='レジストリ読込エラー',
                desc='',
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))

        return results


    def _try_esentutl_copy(self):
        """esentutl でSRUDBのコピーを試み、テーブル情報を取得"""
        results = []
        if not os.path.exists(self.SRUDB_PATH):
            return results

        tmp_dir = None
        try:
            tmp_dir = tempfile.mkdtemp()
            tmp_path = os.path.join(tmp_dir, 'SRUDB_copy.dat')

            # esentutl /y でコピー（ロック中のファイルでもコピー可能）
            proc = subprocess.run(
                ['esentutl', '/y', self.SRUDB_PATH, '/d', tmp_path],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if proc.returncode == 0 and os.path.exists(tmp_path):
                copy_size = os.path.getsize(tmp_path) / (1024 * 1024)
                results.append(self._make_entry(
                    source='esentutl',
                    app_name='SRUDB コピー',
                    detail=f'コピー成功: {copy_size:.1f}MB | 専用ツール(srum-dump)での詳細解析を推奨',
                    reason='',
                    desc='esentutlによるDBコピーが成功しました。\n'
                         'srum-dump や SrumECmd 等の専用ツールで詳細なネットワーク使用量・アプリ実行履歴を取得できます。\n'
                         '→ コピー先: 一時ディレクトリ（自動削除済み）',
                    status='INFO',
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                ))
            else:
                results.append(self._make_entry(
                    source='esentutl',
                    app_name='SRUDB コピー',
                    detail=f'コピー失敗: {proc.stderr.strip()[:200] if proc.stderr else "不明"}',
                    reason='esentutlによるコピーが失敗',
                    desc='SRUDBのコピーに失敗しました。ファイルがロックされているか、権限が不足しています。',
                    status='WARNING',
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                ))
        except subprocess.TimeoutExpired:
            results.append(self._make_entry(
                source='esentutl',
                app_name='SRUDB コピー',
                detail='タイムアウト（30秒）',
                reason='esentutl がタイムアウト',
                desc='',
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))
        except FileNotFoundError:
            results.append(self._make_entry(
                source='esentutl',
                app_name='SRUDB コピー',
                detail='esentutl.exe が見つかりません',
                reason='',
                desc='',
                status='INFO',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))
        except Exception as e:
            results.append(self._make_entry(
                source='esentutl',
                app_name='ERROR',
                detail=str(e),
                reason='esentutlエラー',
                desc='',
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))
        finally:
            if tmp_dir and os.path.exists(tmp_dir):
                try:
                    shutil.rmtree(tmp_dir)
                except Exception:
                    pass

        return results

    def _estimate_network_usage(self):
        """netstat + tasklist ベースでネットワーク使用プロセスを列挙し、不審なものを検知"""
        results = []
        try:
            proc = subprocess.run(
                ['netstat', '-bno'],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if proc.returncode != 0:
                return results

            lines = proc.stdout.split('\n')
            connections = {}

            current_exe = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # プロセス名行（角括弧で囲まれた行）
                if line.startswith('[') and line.endswith(']'):
                    current_exe = line[1:-1].lower()
                    continue

                parts = line.split()
                if len(parts) >= 4 and parts[0] in ('TCP', 'UDP'):
                    parts[0]
                    remote = parts[2] if len(parts) > 2 else ''
                    pid = parts[-1]

                    if current_exe and remote and not remote.startswith('0.0.0.0') and not remote.startswith('[::]') and remote != '*:*':
                        if current_exe not in connections:
                            connections[current_exe] = {'count': 0, 'remotes': set(), 'pid': pid}
                        connections[current_exe]['count'] += 1
                        connections[current_exe]['remotes'].add(remote.split(':')[0])

            # 不審なプロセスの通信を検知
            for exe, info in connections.items():
                status = 'SAFE'
                reason = ''
                desc = ''

                # 攻撃ツール検知
                for tool in self.ATTACK_TOOLS:
                    if tool in exe:
                        status = 'DANGER'
                        reason = f'攻撃ツールのネットワーク通信: {exe}'
                        remote_list = ', '.join(list(info['remotes'])[:5])
                        desc = build_tutor_desc(
                            detection=(
                                f'攻撃ツール「{exe}」がネットワーク通信を行っています。\n'
                                f'接続先: {remote_list}'
                            ),
                            why_dangerous=(
                                '攻撃ツールのネットワーク通信は、C2サーバーへの接続、'
                                '窃取データの送信、追加ツールのダウンロード等を示します。'
                            ),
                            mitre_key='srum_suspicious_app',
                            normal_vs_abnormal=(
                                '正常: ブラウザ、Windows Update等の正規プロセスのみが通信している\n'
                                '異常: 攻撃ツールや見覚えのないプロセスが外部と通信している'
                            ),
                            next_steps=[
                                '即座にネットワークを遮断する',
                                '接続先IPの評判をVirusTotalやAbuseIPDBで調査する',
                                'ファイアウォールログで通信量と期間を特定する',
                            ],
                            status='DANGER',
                        )
                        break

                # 大量接続
                if info['count'] > 20 and status == 'SAFE':
                    status = 'WARNING'
                    reason = f'{exe} が {info["count"]}件の接続を保持'
                    desc = build_tutor_desc(
                        detection=f'{exe}が{info["count"]}件のネットワーク接続を保持しています。',
                        why_dangerous=(
                            '大量のネットワーク接続は、C2ビーコニング（定期的なC2通信）、'
                            'ポートスキャン、またはデータ窃取を示す可能性があります。'
                        ),
                        mitre_key='net_beaconing',
                        normal_vs_abnormal=(
                            '正常: ブラウザが多数のタブで接続を持つ場合は20件以上になることがある\n'
                            '異常: 見慣れないプロセスが大量接続を保持、接続先が海外の不明IPアドレス'
                        ),
                        next_steps=[
                            'プロセスの正当性を確認する',
                            '接続先IPアドレスを調査する',
                            '通信パターン（間隔・データ量）を確認する',
                        ],
                        status='WARNING',
                    )

                if status != 'SAFE':
                    results.append(self._make_entry(
                        source='netstat推定',
                        app_name=exe,
                        detail=f'接続数: {info["count"]} | 接続先: {", ".join(list(info["remotes"])[:5])}',
                        reason=reason,
                        desc=desc,
                        status=status,
                        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        network_sent=f'{info["count"]}接続',
                        network_recv='',
                        cpu_time='',
                        user_sid=f'PID:{info["pid"]}',
                    ))

        except Exception as e:
            results.append(self._make_entry(
                source='netstat推定',
                app_name='ERROR',
                detail=str(e),
                reason='ネットワーク使用量推定エラー',
                desc='',
                status='WARNING',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ))

        return results


    def _make_entry(self, source='', app_name='', detail='', reason='', desc='',
                    status='INFO', timestamp='', network_sent='', network_recv='',
                    cpu_time='', user_sid=''):
        """統一フォーマットでエントリを生成"""
        return {
            'source': source,
            'app_name': app_name,
            'detail': detail,
            'network_sent': network_sent,
            'network_recv': network_recv,
            'cpu_time': cpu_time,
            'user_sid': user_sid,
            'reason': reason,
            'desc': desc,
            'status': status,
            'is_self': False,
            'timestamp': timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
