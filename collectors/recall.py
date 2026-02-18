# -*- coding: utf-8 -*-
"""
Recall Collector - Windows Recall (AI Screenshots) 検知
Windows 11 24H2以降で導入された Recall 機能の有効状態・DBの存在を検査する。
P16: 統一解説フォーマット対応
"""

import os
import glob
import winreg
from datetime import datetime
from utils.tutor_template import build_tutor_desc


class RecallCollector:
    """Windows Recall の検知と状態検査"""

    def __init__(self):
        self.users_dir = os.path.join(
            os.environ.get('SYSTEMDRIVE', 'C:'), os.sep, 'Users')
        self.recall_patterns = [
            'AppData\\Local\\CoreAIPlatform.00\\UKP',
            'AppData\\Local\\CoreAIPlatform.00',
            'AppData\\Local\\Microsoft\\Windows\\Recall',
        ]
        self.reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Recall'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'),
        ]

    def scan(self):
        """メインスキャン処理"""
        results = []
        results.extend(self._check_registry())
        results.extend(self._check_recall_db())
        results.extend(self._check_recall_process())

        if not results:
            results.append(self._make_entry(
                source='総合判定',
                artifact='Windows Recall',
                detail='Recall機能は検出されませんでした',
                reason='',
                desc=build_tutor_desc(
                    detection=(
                        "このシステムにはWindows Recall機能がインストールされていません。"
                        "Windows 11 24H2以降のCopilot+ PC専用機能です。"
                    ),
                    why_dangerous="",
                    normal_vs_abnormal=(
                        "Recall未インストールのためリスクはありません。"
                        "今後のWindows Update等で自動的に有効化される可能性があるため、"
                        "定期的な再スキャンを推奨します。"
                    ),
                    status="INFO",
                ),
                status='INFO',
            ))
        return results

    def _check_registry(self):
        """Recall関連レジストリを検査"""
        results = []
        for hive, path in self.reg_paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                values = {}
                i = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(key, i)
                        values[name] = data
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)

                if not values:
                    continue

                disabled = values.get('DisableAIDataAnalysis', None)
                recall_enabled = values.get('EnableRecall', None)
                turn_off = values.get('TurnOffWindowsCopilot', None)

                detail_parts = [f'{k}={v}' for k, v in values.items()]

                if recall_enabled == 1 or (disabled is not None and disabled == 0):
                    results.append(self._make_entry(
                        source='レジストリ',
                        artifact=path.split('\\')[-1],
                        detail=' | '.join(detail_parts),
                        reason='Recall機能が有効化されています',
                        desc=build_tutor_desc(
                            detection=(
                                "Windows Recallが有効化されています。"
                                "定期的にスクリーンショットが取得・保存されています。\n"
                                f"レジストリ: {path}\n"
                                f"設定値: {' | '.join(detail_parts)}"
                            ),
                            why_dangerous=(
                                "Recallは画面内容を定期的にスクリーンショットとして保存し、"
                                "AIで検索可能にする機能です。パスワード入力画面、機密文書、"
                                "個人情報、社外秘メール、チャット内容等が全て記録されます。"
                                "攻撃者がRecall DBにアクセスした場合、大量の機密情報が一度に漏洩します。"
                                "また、Recall DB自体がフォレンジック的に非常に価値の高い"
                                "アーティファクトとなります。"
                            ),
                            mitre_key="recall_enabled",
                            normal_vs_abnormal=(
                                "【正常】組織が承認し、データ保護ポリシーの下で使用している場合。\n"
                                "【異常】組織が承認していない、または機密情報を扱う端末で有効な場合。"
                                "攻撃者がRecallを有効化して情報収集に悪用するシナリオも。\n"
                                "【判断基準】組織のセキュリティポリシーでRecall使用が承認されているか？"
                            ),
                            next_steps=[
                                "組織ポリシーでRecallを無効化することを推奨する",
                                "RecallのDBファイルの内容を専用ツールで検査する",
                                "Recall DBへのアクセスログを確認する",
                                "機密情報がRecall DBに含まれていないか確認する",
                            ],
                            status="WARNING",
                        ),
                        status='WARNING',
                    ))
                elif disabled == 1 or turn_off == 1:
                    results.append(self._make_entry(
                        source='レジストリ',
                        artifact=path.split('\\')[-1],
                        detail=' | '.join(detail_parts),
                        reason='',
                        desc=build_tutor_desc(
                            detection=(
                                "Recall/Copilot機能はポリシーにより無効化されています。\n"
                                f"レジストリ: {path}"
                            ),
                            why_dangerous="",
                            normal_vs_abnormal=(
                                "ポリシーで無効化されているため、Recall経由の情報漏洩リスクはありません。"
                                "設定が変更されていないか定期的に確認してください。"
                            ),
                            status="INFO",
                        ),
                        status='INFO',
                    ))

            except FileNotFoundError:
                continue
            except PermissionError:
                results.append(self._make_entry(
                    source='レジストリ',
                    artifact=path.split('\\')[-1],
                    detail='アクセス権限不足',
                    reason='レジストリへのアクセスが拒否されました',
                    desc=build_tutor_desc(
                        detection="レジストリへのアクセスが拒否されました。管理者権限で再実行してください。",
                        why_dangerous="アクセス拒否のためRecallの状態を確認できません。",
                        next_steps=["管理者権限(右クリック→管理者として実行)で再スキャンする"],
                        status="WARNING",
                    ),
                    status='WARNING',
                ))
            except Exception as e:
                results.append(self._make_entry(
                    source='レジストリ',
                    artifact='ERROR',
                    detail=str(e),
                    reason=f'レジストリ読込エラー',
                    desc='',
                    status='WARNING',
                ))
        return results

    def _check_recall_db(self):
        """各ユーザープロファイルのRecall DB存在を検査"""
        results = []
        if not os.path.exists(self.users_dir):
            return results

        try:
            user_dirs = [d for d in os.listdir(self.users_dir)
                        if os.path.isdir(os.path.join(self.users_dir, d))
                        and d.lower() not in (
                            'public', 'default', 'default user', 'all users')]
        except PermissionError:
            return results

        for user in user_dirs:
            for pattern in self.recall_patterns:
                recall_dir = os.path.join(self.users_dir, user, pattern)
                if not os.path.exists(recall_dir):
                    continue

                try:
                    all_files = []
                    total_size = 0
                    db_files = []

                    for root, dirs, files in os.walk(recall_dir):
                        for f in files:
                            fpath = os.path.join(root, f)
                            try:
                                fsize = os.path.getsize(fpath)
                                total_size += fsize
                                all_files.append(f)
                                if f.endswith(('.db', '.sqlite', '.dat')):
                                    db_files.append({
                                        'name': f,
                                        'size': fsize,
                                        'mtime': datetime.fromtimestamp(
                                            os.path.getmtime(fpath)),
                                    })
                            except:
                                continue

                    total_size_mb = total_size / (1024 * 1024)

                    db_info = ""
                    if db_files:
                        db_info = "\nDBファイル:\n"
                        for db in db_files[:5]:
                            db_info += (
                                f"  {db['name']}: {db['size']/(1024*1024):.1f}MB "
                                f"(更新: {db['mtime'].strftime('%Y-%m-%d %H:%M')})\n"
                            )

                    if total_size_mb > 500:
                        status = 'DANGER'
                        reason = f'Recall DBが巨大: {total_size_mb:.0f}MB (ユーザー: {user})'
                        desc = build_tutor_desc(
                            detection=(
                                f"ユーザー「{user}」のRecallデータが見つかりました。\n"
                                f"ファイル数: {len(all_files)} | "
                                f"合計サイズ: {total_size_mb:.1f}MB | "
                                f"DBファイル: {len(db_files)}個"
                                f"{db_info}"
                            ),
                            why_dangerous=(
                                f"Recall DBが{total_size_mb:.0f}MBと非常に大きく、"
                                "大量のスクリーンショットが保存されています。"
                                "機密情報（パスワード、個人情報、業務文書等）が含まれるリスクが"
                                "非常に高い状態です。攻撃者がアクセスした場合、"
                                "ユーザーの全操作履歴が漏洩する恐れがあります。"
                            ),
                            mitre_key="recall_db_large",
                            normal_vs_abnormal=(
                                "【正常】組織が承認した上でRecallを使用し、"
                                "DBの暗号化とアクセス制御が適切に設定されている場合。\n"
                                "【異常】500MBを超えるRecall DBは長期間の記録を含み、"
                                "セキュリティリスクが極めて高い。\n"
                                "【判断基準】即座にRecallを無効化し、DBの内容を検査すべき。"
                            ),
                            next_steps=[
                                "即座にRecallを無効化する（設定→プライバシー）",
                                "DBの内容を専用ツール(TotalRecall等)で検査する",
                                "機密情報が含まれるスクリーンショットを特定・削除する",
                                "Recall DBへの不正アクセスがなかったか確認する",
                            ],
                            status="DANGER",
                        )
                    else:
                        status = 'WARNING'
                        reason = f'Recall DBが存在: ユーザー {user}'
                        desc = build_tutor_desc(
                            detection=(
                                f"ユーザー「{user}」のRecallデータが見つかりました。\n"
                                f"ファイル数: {len(all_files)} | "
                                f"合計サイズ: {total_size_mb:.1f}MB | "
                                f"DBファイル: {len(db_files)}個"
                                f"{db_info}"
                            ),
                            why_dangerous=(
                                "Recallデータが存在し、スクリーンショットが保存されています。"
                                "現時点ではサイズは大きくありませんが、"
                                "機密情報が含まれている可能性があります。"
                            ),
                            normal_vs_abnormal=(
                                "【正常】Recallを意図的に使用し、リスクを理解している場合。\n"
                                "【異常】Recallを有効化した覚えがない場合。\n"
                                "【判断基準】組織のセキュリティポリシーを確認。"
                            ),
                            next_steps=[
                                "RecallのDBを専用ツールで開き記録内容を確認する",
                                "機密情報の記録有無を確認する",
                                "不要であればRecallを無効化しDBを削除する",
                            ],
                            status="WARNING",
                        )

                    timestamp = ''
                    if db_files:
                        latest = max(db_files, key=lambda x: x['mtime'])
                        timestamp = latest['mtime'].strftime('%Y-%m-%d %H:%M:%S')

                    results.append(self._make_entry(
                        source=f'ユーザー: {user}',
                        artifact=f'Recall DB ({pattern.split(chr(92))[-1]})',
                        detail=(f'ファイル数: {len(all_files)} | '
                                f'サイズ: {total_size_mb:.1f}MB | '
                                f'DB: {len(db_files)}個'),
                        reason=reason,
                        desc=desc,
                        status=status,
                        timestamp=timestamp,
                    ))

                except PermissionError:
                    results.append(self._make_entry(
                        source=f'ユーザー: {user}',
                        artifact=f'Recall DB ({pattern.split(chr(92))[-1]})',
                        detail='アクセス権限不足',
                        reason='Recall DBへのアクセスが拒否されました',
                        desc=build_tutor_desc(
                            detection="Recall DBへのアクセスが拒否されました。",
                            why_dangerous="他のユーザーのRecall DBにアクセスするには管理者権限が必要です。",
                            next_steps=["管理者権限で再スキャンする"],
                            status="WARNING",
                        ),
                        status='WARNING',
                    ))
                except Exception as e:
                    results.append(self._make_entry(
                        source=f'ユーザー: {user}',
                        artifact='ERROR',
                        detail=str(e),
                        reason='Recall DB検査エラー',
                        desc='',
                        status='WARNING',
                    ))
        return results

    def _check_recall_process(self):
        """Recall関連プロセスの存在を確認"""
        results = []
        recall_processes = [
            'RecallUI.exe', 'AIPlatform.exe', 'CoreAIPlatform.exe',
            'WindowsCopilotRuntime.exe', 'ScreenCapture.exe',
        ]

        try:
            import subprocess
            proc = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if proc.returncode == 0:
                running = []
                for line in proc.stdout.split('\n'):
                    for rp in recall_processes:
                        if rp.lower() in line.lower():
                            running.append(rp)

                if running:
                    proc_list = ", ".join(set(running))
                    results.append(self._make_entry(
                        source='プロセス',
                        artifact='Recall プロセス稼働中',
                        detail=f'検出: {proc_list}',
                        reason='Recall関連プロセスが実行中',
                        desc=build_tutor_desc(
                            detection=(
                                f"Recall関連プロセスが稼働しています: {proc_list}\n"
                                "Recallがアクティブに動作し、スクリーンショットを記録しています。"
                            ),
                            why_dangerous=(
                                "画面に表示される全ての情報（パスワード入力、機密文書、"
                                "チャット内容、メール本文等）がリアルタイムで記録されています。"
                                "攻撃者がこの端末にアクセスした場合、"
                                "Recall DBから全ての操作履歴を取得できます。"
                            ),
                            mitre_key="recall_process",
                            normal_vs_abnormal=(
                                "【正常】組織が承認した上でRecallを意図的に使用している場合。\n"
                                "【異常】Recallを有効化した覚えがない、"
                                "または機密情報を扱う業務端末で稼働している場合。\n"
                                "【判断基準】組織のセキュリティポリシーで承認されているか？"
                            ),
                            next_steps=[
                                "不要な場合は設定からRecallを無効化する",
                                "組織ポリシーでの一括無効化を検討する",
                                "既に保存されたRecall DBの内容を検査する",
                            ],
                            status="WARNING",
                        ),
                        status='WARNING',
                    ))
        except Exception:
            pass
        return results

    def _make_entry(self, source='', artifact='', detail='', reason='',
                    desc='', status='INFO', timestamp=''):
        """統一フォーマットでエントリを生成"""
        return {
            'source': source,
            'artifact': artifact,
            'detail': detail,
            'reason': reason,
            'desc': desc,
            'status': status,
            'is_self': False,
            'timestamp': timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
