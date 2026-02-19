# -*- coding: utf-8 -*-
# collectors/eventlog.py - P17: MITRE ATT&CK + Tutor Mode 統合版
import subprocess
import json
import re
from datetime import datetime

try:
    from utils.tutor_template import build_tutor_desc, MITRE_MAP
except ImportError:
    from tutor_template import build_tutor_desc, MITRE_MAP


class EventLogCollector:
    """P17: イベントログ解析 - 全イベントIDに3段構成Tutor解説を付与"""

    def __init__(self):
        # ERR-EVL-001: 監視対象イベント定義
        # 各エントリ: level, desc(短い表示名), tutor(build_tutor_desc統一フォーマット)
        self.target_events = {
            '1102': {
                'level': 'DANGER',
                'desc': '🗑️ 監査ログ消去',
                'tutor': build_tutor_desc(
                    detection='Securityイベントログが消去されました（Event ID: 1102）。',
                    why_dangerous=(
                        '監査ログの消去は、攻撃者が侵害の痕跡を隠滅する'
                        '最も典型的な手法の一つです。'
                        '正当な理由なくSecurityログが消去されることは通常ありません。'
                        'ログ消去の直前に記録されていたイベントが攻撃の核心である可能性が高いです。'
                    ),
                    mitre_key='evt_log_clear',
                    normal_vs_abnormal=(
                        '正常: ログローテーションやディスク容量管理で計画的に消去する場合がある\n'
                        '異常: 予告なくSecurityログのみが消去されている、深夜帯に実行されている'
                    ),
                    next_steps=[
                        'ログ消去を実行したアカウント名とログオン元IPを確認する',
                        '消去直前のイベント（バックアップやSIEMに転送済みのログ）を確認する',
                        '同時刻帯の他のログ（System, PowerShell）に残っている痕跡を確認する',
                        'Volume Shadow Copyからイベントログの復元を試みる',
                    ],
                    status='DANGER',
                ),
            },
            '4624': {
                'level': 'INFO',
                'desc': '🔑 ログオン成功',
                'tutor': build_tutor_desc(
                    detection='アカウントのログオンが成功しました（Event ID: 4624）。',
                    why_dangerous=(
                        'ログオン成功自体は正常な動作ですが、以下の場合は要注意です：\n'
                        '・ログオンタイプ3(ネットワーク)で見覚えのないソースIPからのアクセス\n'
                        '・ログオンタイプ10(RDP)が業務時間外に発生\n'
                        '・短時間に異なるアカウントで大量のログオン成功\n'
                        '・無効化されているはずのアカウントでのログオン'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 業務時間内に正規ユーザーが対話的ログオン(タイプ2)する\n'
                        '異常: 深夜にタイプ10(RDP)で外部IPからログオン成功している'
                    ),
                    next_steps=[
                        'ログオンタイプ（2=対話, 3=ネットワーク, 10=RDP）を確認する',
                        'ソースIPアドレスが既知の端末か確認する',
                        '同一アカウントのログオン失敗(4625)が直前に大量にないか確認する',
                        'ログオン時刻が業務時間内か確認する',
                    ],
                    status='INFO',
                ),
            },
            '4625': {
                'level': 'WARNING',
                'desc': '🚫 ログオン失敗',
                'tutor': build_tutor_desc(
                    detection='アカウントのログオンが失敗しました（Event ID: 4625）。',
                    why_dangerous=(
                        '単発のログオン失敗はパスワード入力ミスで日常的に発生しますが、'
                        '短時間に同一アカウントまたは同一ソースIPから大量に発生している場合、'
                        'ブルートフォース攻撃やパスワードスプレー攻撃の可能性があります。'
                        '特にサブステータス0xC000006A（パスワード誤り）が連続する場合は要注意です。'
                    ),
                    mitre_key='evt_brute_force',
                    normal_vs_abnormal=(
                        '正常: 散発的なパスワード入力ミス（1〜2回）\n'
                        '異常: 同一アカウントに対して10件以上/1時間の失敗が集中している'
                    ),
                    next_steps=[
                        '同一アカウントに対する失敗が10件以上/1時間ないか確認する',
                        'ソースIPアドレスが内部ネットワーク外でないか確認する',
                        '失敗の直後にログオン成功(4624)がないか確認する（突破された可能性）',
                        '対象アカウントのパスワード変更・ロックアウト状態を確認する',
                    ],
                    status='WARNING',
                ),
            },
            '4672': {
                'level': 'WARNING',
                'desc': '👑 管理者権限行使',
                'tutor': build_tutor_desc(
                    detection='特権（管理者権限）がアカウントに割り当てられました（Event ID: 4672）。',
                    why_dangerous=(
                        'SeDebugPrivilege、SeTcbPrivilege等の特権は'
                        'プロセスメモリの読み書き、トークン偽装、サービス操作など'
                        'システムの完全な制御を可能にします。'
                        '攻撃者が権限昇格に成功した場合、このイベントが記録されます。'
                        '正規の管理者アカウントでは正常に発生しますが、'
                        '一般ユーザーアカウントで発生した場合は権限昇格攻撃の疑いがあります。'
                    ),
                    mitre_key='evt_priv_escalation',
                    normal_vs_abnormal=(
                        '正常: ビルトインAdministratorやドメイン管理者でのログオン時に発生\n'
                        '異常: 一般ユーザーアカウントにSeDebugPrivilegeが付与されている'
                    ),
                    next_steps=[
                        '特権が付与されたアカウントが正規の管理者か確認する',
                        '一般ユーザーに特権が付与されていれば、権限昇格の手法を調査する',
                        '同時刻の4688(プロセス作成)で実行されたコマンドを確認する',
                        '付与された特権の種類（SeDebugPrivilege等）を確認する',
                    ],
                    status='WARNING',
                ),
            },
            '4688': {
                'level': 'INFO',
                'desc': '⚙️ プロセス作成',
                'tutor': build_tutor_desc(
                    detection='新しいプロセスが作成されました（Event ID: 4688）。',
                    why_dangerous=(
                        'プロセス作成イベント自体は正常ですが、'
                        'コマンドライン引数の監査が有効な場合、攻撃者が実行したコマンドの'
                        '完全な記録が残ります。以下のパターンに注目してください：\n'
                        '・PowerShellの-enc（Base64エンコード）引数\n'
                        '・cmd.exe /c による一時的なコマンド実行\n'
                        '・certutil -urlcache によるファイルダウンロード\n'
                        '・親プロセスがOfficeアプリ(WINWORD.EXE等)のケース'
                    ),
                    mitre_key='evt_process_create',
                    normal_vs_abnormal=(
                        '正常: ユーザー操作に応じたアプリ起動、Windows Updateによるプロセス\n'
                        '異常: 深夜にcmd.exe /cでBase64エンコードされた文字列が実行されている'
                    ),
                    next_steps=[
                        'コマンドライン引数にBase64文字列やURLが含まれていないか確認する',
                        '親プロセスが正当か確認する（ExcelからPowerShellが起動は異常）',
                        '実行ユーザーとプロセスの組み合わせが妥当か確認する',
                        '同時刻のネットワーク接続ログと照合する',
                    ],
                    status='INFO',
                ),
            },
            '6005': {
                'level': 'INFO',
                'desc': '🖥️ PC起動',
                'tutor': build_tutor_desc(
                    detection='イベントログサービスが開始されました＝PC起動（Event ID: 6005）。',
                    why_dangerous=(
                        '通常は正常な起動記録ですが、以下の場合は注意が必要です：\n'
                        '・業務時間外の深夜・早朝に起動されている\n'
                        '・直前に異常終了(ID:41)が記録されている\n'
                        '・短時間に複数回の起動・終了が繰り返されている'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 始業時間に起動、Windows Update後の再起動\n'
                        '異常: 深夜3時に起動、短時間に5回以上の再起動'
                    ),
                    next_steps=[
                        '起動時刻が想定される運用スケジュールと一致するか確認する',
                        '直前のシャットダウン(6006)または異常終了(41)の有無を確認する',
                        '起動直後のログオン(4624)でアクセスしたアカウントを確認する',
                    ],
                    status='INFO',
                ),
            },
            '6006': {
                'level': 'INFO',
                'desc': '💤 シャットダウン',
                'tutor': build_tutor_desc(
                    detection='イベントログサービスが停止されました＝正常シャットダウン（Event ID: 6006）。',
                    why_dangerous=(
                        '正常なシャットダウン記録です。'
                        '攻撃者がフォレンジック調査を妨害するために'
                        '意図的にシャットダウン・再起動を行う場合があります。'
                        'メモリ上の証拠（マルウェアのプロセス、ネットワーク接続）は'
                        '再起動で消失します。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 終業時のシャットダウン、メンテナンス後の再起動\n'
                        '異常: 不審なイベント直後のシャットダウン、ユーザー操作なしの停止'
                    ),
                    next_steps=[
                        'シャットダウンの前後で不審なイベント（ログ消去等）がないか確認する',
                        'シャットダウンを実行したユーザーアカウントを確認する',
                        '想定外のタイミングでのシャットダウンでないか確認する',
                    ],
                    status='INFO',
                ),
            },
            '41': {
                'level': 'DANGER',
                'desc': '⚡ 異常終了',
                'tutor': build_tutor_desc(
                    detection='システムが正常にシャットダウンされずに停止しました（Event ID: 41 - Kernel-Power）。',
                    why_dangerous=(
                        '異常終了は以下のケースで発生します：\n'
                        '・停電やハードウェア故障\n'
                        '・カーネルレベルのクラッシュ（BSoD）\n'
                        '・攻撃者がシステムを強制終了してメモリ上の証拠を消去\n'
                        '・ランサムウェアやワイパーによるシステム破壊\n'
                        '単発であればハードウェア要因の可能性が高いですが、'
                        '他の不審なイベントと組み合わさっている場合は攻撃の可能性があります。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 停電後の単発の異常終了\n'
                        '異常: 不審なイベント直後の異常終了、複数台で同時に発生'
                    ),
                    next_steps=[
                        '異常終了の直前に記録されたイベントを確認する',
                        'BugCheckCode（BSoDコード）が記録されていれば原因を特定する',
                        '同時期に複数台で異常終了が発生していないか確認する',
                        'ハードウェアの電源ログ・UPS記録を確認する',
                    ],
                    status='DANGER',
                ),
            },
            '7045': {
                'level': 'DANGER',
                'desc': '🆕 サービス登録',
                'tutor': build_tutor_desc(
                    detection='新しいサービスがシステムにインストールされました（Event ID: 7045）。',
                    why_dangerous=(
                        'サービス登録はシステムレベルの永続化手法として'
                        '攻撃者に頻繁に悪用されます。'
                        '登録されたサービスはSYSTEM権限で動作し、OS起動時に自動実行されます。'
                        '特に以下のパターンは高リスクです：\n'
                        '・サービスパスにPowerShellやcmd.exeが含まれる\n'
                        '・サービス名がランダム文字列\n'
                        '・パスがTemp、ProgramData等の書き込み可能フォルダ'
                    ),
                    mitre_key='evt_new_service',
                    normal_vs_abnormal=(
                        '正常: ソフトウェアインストール時にサービスが登録される\n'
                        '異常: サービスパスにPowerShellやTemp等が含まれる、サービス名が意味不明'
                    ),
                    next_steps=[
                        'サービス名とサービスパス（ImagePath）を確認する',
                        'パスのEXEファイルが正規のソフトウェアか確認する',
                        'サービスの実行アカウント（LocalSystem等）を確認する',
                        '同時刻にPsExec等のリモート実行ツールが使用されていないか確認する',
                    ],
                    status='DANGER',
                ),
            },
            '1000': {
                'level': 'WARNING',
                'desc': '💥 アプリクラッシュ',
                'tutor': build_tutor_desc(
                    detection='アプリケーションがクラッシュしました（Event ID: 1000 - Application Error）。',
                    why_dangerous=(
                        'アプリクラッシュ自体はバグによる正常な事象ですが、'
                        '以下の場合はエクスプロイト（脆弱性攻撃）の兆候である可能性があります：\n'
                        '・ブラウザ、Office、PDFリーダーが繰り返しクラッシュ\n'
                        '・例外コード0xC0000005（アクセス違反）が記録されている\n'
                        '・クラッシュ直後に新しいプロセスが起動されている\n'
                        '・見覚えのないアプリケーションがクラッシュしている'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 特定アプリのバグによる散発的なクラッシュ\n'
                        '異常: 例外コード0xC0000005が記録、クラッシュ直後に不審なプロセス起動'
                    ),
                    next_steps=[
                        'クラッシュしたアプリケーションの名前とバージョンを確認する',
                        '例外コードが0xC0000005（バッファオーバーフローの兆候）か確認する',
                        'クラッシュの直前・直後に新しいプロセス(4688)が作成されていないか確認する',
                        '同一アプリの繰り返しクラッシュがないか確認する',
                    ],
                    status='WARNING',
                ),
            },
            '11707': {
                'level': 'INFO',
                'desc': '📦 アプリインストール',
                'tutor': build_tutor_desc(
                    detection='MSIインストーラによるアプリケーションのインストールが完了しました（Event ID: 11707）。',
                    why_dangerous=(
                        '正規のインストール記録ですが、'
                        '攻撃者がリモートアクセスツール（RAT）や'
                        'バックドアをMSI形式で配布・インストールするケースがあります。'
                        '見覚えのないアプリケーション名、業務時間外のインストール、'
                        '一般ユーザーによるインストールは調査が必要です。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: IT部門が配布した既知のソフトウェアのインストール\n'
                        '異常: 見覚えのないアプリ名、深夜帯のインストール'
                    ),
                    next_steps=[
                        'インストールされたアプリケーション名を確認する',
                        'インストールを実行したユーザーアカウントを確認する',
                        'インストール時刻が業務時間内か確認する',
                        '正規のソフトウェア配布リストに含まれているか確認する',
                    ],
                    status='INFO',
                ),
            },
            '11724': {
                'level': 'INFO',
                'desc': '🗑️ アプリ削除',
                'tutor': build_tutor_desc(
                    detection='MSIインストーラによるアプリケーションの削除が完了しました（Event ID: 11724）。',
                    why_dangerous=(
                        'アプリ削除自体は正常な操作ですが、'
                        '攻撃者がセキュリティソフト（AV/EDR）をアンインストールする'
                        'ケースがあります。'
                        'セキュリティ製品の削除、監視エージェントの削除は即座に調査が必要です。'
                    ),
                    mitre_key='evt_app_uninstall',
                    normal_vs_abnormal=(
                        '正常: バージョンアップのための旧版削除、不要ソフトの整理\n'
                        '異常: セキュリティソフトや監視エージェントが削除されている'
                    ),
                    next_steps=[
                        '削除されたアプリケーション名がセキュリティ製品でないか確認する',
                        '削除を実行したユーザーアカウントを確認する',
                        '削除直後に不審なプロセスやサービスが登録されていないか確認する',
                    ],
                    status='INFO',
                ),
            },
            '4104': {
                'level': 'DANGER',
                'desc': '📜 PowerShell実行',
                'tutor': build_tutor_desc(
                    detection='PowerShellスクリプトブロックが実行されました（Event ID: 4104 - Script Block Logging）。',
                    why_dangerous=(
                        'PowerShellは攻撃者が最も多用するツールの一つで、'
                        'ファイルレス攻撃（ディスクにマルウェアを書かない手法）の主要な手段です。'
                        'スクリプトブロックログにはBase64デコード後の実際のコードが記録されるため、'
                        '難読化されたコマンドの実態を確認できる貴重な証拠です。'
                        '以下のキーワードが含まれる場合は高リスクです：\n'
                        '・Invoke-Expression / IEX（コード動的実行）\n'
                        '・Net.WebClient / DownloadString（リモートコード取得）\n'
                        '・-EncodedCommand（Base64エンコード）\n'
                        '・Invoke-Mimikatz / Get-Credential（認証情報窃取）\n'
                        '・New-Object IO.MemoryStream（メモリ内実行）'
                    ),
                    mitre_key='evt_powershell',
                    normal_vs_abnormal=(
                        '正常: IT管理者がモジュールインストールやシステム管理スクリプトを実行\n'
                        '異常: IEX、DownloadString、Invoke-Mimikatz等の攻撃用コマンドが含まれている'
                    ),
                    next_steps=[
                        'スクリプトブロックの全文を確認し、不審なコマンドを特定する',
                        '実行ユーザーアカウントと実行時刻を確認する',
                        'ダウンロード先URLが含まれていればアクセス先を調査する',
                        '同時刻のネットワーク接続ログと照合する',
                    ],
                    status='DANGER',
                ),
            },
        }

        # ERR-EVL-002: メッセージ内容から追加リスクを判定するキーワード
        self.danger_keywords_in_message = [
            'mimikatz', 'invoke-expression', 'iex ', 'downloadstring',
            'downloadfile', 'net.webclient', 'encodedcommand',
            'invoke-mimikatz', 'get-credential', 'sekurlsa',
            'kerberos::list', 'token::elevate', 'lsadump',
            'psexec', 'new-service', 'sc create', 'sc config',
            'reg add', 'schtasks /create', 'at \\\\',
            'net user /add', 'net localgroup administrators',
            'vssadmin delete shadows', 'bcdedit /set',
            'wbadmin delete catalog', 'cipher /w',
        ]

        # ERR-EVL-003: 7045サービス登録の不審パターン
        self.suspicious_service_patterns = [
            'powershell', 'cmd /c', 'cmd.exe /c', 'mshta',
            'rundll32', 'regsvr32', 'certutil',
            'bitsadmin', '\\temp\\', '\\tmp\\',
            '\\appdata\\', '\\programdata\\',
            'base64', '-enc ', '-encodedcommand',
        ]



    # P17: イベントIDごとのMITREマッピング
    EVT_MITRE_MAP = {
        '1102': 'evt_log_clear',
        '4624': 'net_account_anomaly',
        '4625': 'evt_brute_force',
        '4672': 'evt_priv_escalation',
        '4688': 'evt_process_create',
        '7045': 'evt_new_service',
        '4104': 'evt_powershell',
        '11724': 'evt_app_uninstall',
    }

    def scan(self):
        logs = []
        try:
            logs.extend(self._get_events('Security', [1102, 4624, 4625, 4672, 4688], 50))
        except Exception:
            print("[!] Securityログの取得に失敗 (スキップ)")

        try:
            logs.extend(self._get_events('System', [6005, 6006, 41, 7045], 50))
        except Exception:
            print("[!] Systemログの取得に失敗 (スキップ)")

        try:
            logs.extend(self._get_events('Application', [1000, 11707, 11724], 50))
        except Exception:
            print("[!] Applicationログの取得に失敗 (スキップ)")

        try:
            logs.extend(self._get_events('Microsoft-Windows-PowerShell/Operational', [4104], 50))
        except Exception:
            print("[!] PowerShellログの取得に失敗 (スキップ)")

        return sorted(logs, key=lambda x: x['time'], reverse=True)

    def _get_events(self, log_name, ids, max_events):
        results = []
        id_list = ','.join(map(str, ids))

        ps_command = f"""
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
        Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Id={id_list}}} -MaxEvents {max_events} -ErrorAction SilentlyContinue |
        Select-Object Id, TimeCreated, @{{Name='Msg';Expression={{$_.Message -replace '\\r?\\n',' ' | ForEach-Object {{ $_.Substring(0, [Math]::Min($_.Length, 500)) }}}}}} |
        ConvertTo-Json -Compress
        """

        try:
            cmd = ["powershell", "-NoProfile", "-Command", ps_command]
            output = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding='utf-8',
                errors='replace',
                creationflags=0x08000000
            )

            if not output.strip():
                return []

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                return []

            if isinstance(data, dict):
                data = [data]

            for entry in data:
                evt_id = str(entry.get('Id', ''))
                info = self.target_events.get(evt_id, {
                    'level': 'INFO',
                    'desc': f'Event {evt_id}',
                    'tutor': build_tutor_desc(
                        detection=f'イベントID {evt_id} の記録です。',
                        why_dangerous='',
                        mitre_key=None,
                        status='INFO',
                    ),
                })
                raw_msg = entry.get('Msg', '') or ''
                short_msg = (raw_msg[:300] + '...') if len(raw_msg) > 300 else raw_msg
                formatted_time = self._format_time(entry.get('TimeCreated', ''))

                # メッセージ内容に基づく追加判定
                status, reason, tutor_text = self._analyze_message(
                    evt_id, info, raw_msg
                )

                mitre_key = self.EVT_MITRE_MAP.get(evt_id)

                results.append({
                    "id": evt_id,
                    "log": log_name.split('/')[-1],
                    "time": formatted_time,
                    "message": short_msg,
                    "status": status,
                    "reason": reason,
                    "desc": tutor_text,
                    "mitre_key": mitre_key,
                })
        except Exception:
            return []

        return results


    def _analyze_message(self, evt_id, info, message):
        """イベントメッセージ内容に基づく動的な危険度判定"""
        msg_lower = message.lower()
        base_level = info['level']
        base_desc = info['desc']
        base_tutor = info.get('tutor', '')

        # --- 7045: サービス登録の不審パターン検知 ---
        if evt_id == '7045':
            for pattern in self.suspicious_service_patterns:
                if pattern in msg_lower:
                    return (
                        "DANGER",
                        f"{base_desc} - 不審なサービスパス: {pattern}",
                        base_tutor + build_tutor_desc(
                            detection=f'サービスのImagePathに不審なパターン「{pattern}」が含まれています。',
                            why_dangerous='攻撃者によるサービス永続化の可能性が高いです。',
                            mitre_key='evt_new_service',
                            status='DANGER',
                        ),
                    )
            return (base_level, base_desc, base_tutor)

        # --- 4104: PowerShellスクリプト内容の解析 ---
        if evt_id == '4104':
            found_keywords = []
            for kw in self.danger_keywords_in_message:
                if kw in msg_lower:
                    found_keywords.append(kw)
            if found_keywords:
                kw_str = ', '.join(found_keywords[:5])
                return (
                    "DANGER",
                    f"{base_desc} - 不審なコマンド検知: {kw_str}",
                    base_tutor + build_tutor_desc(
                        detection=f'スクリプトブロック内に危険なキーワード「{kw_str}」が検出されました。',
                        why_dangerous='攻撃コードが実行された可能性があります。',
                        mitre_key='evt_powershell',
                        status='DANGER',
                    ),
                )
            return (base_level, base_desc, base_tutor)

        # --- 4625: ログオン失敗のメッセージ解析 ---
        if evt_id == '4625':
            if '0xc000006a' in msg_lower:
                return (
                    "WARNING",
                    f"{base_desc} - パスワード誤り",
                    base_tutor,
                )
            if '0xc0000234' in msg_lower:
                return (
                    "DANGER",
                    f"{base_desc} - アカウントロックアウト",
                    base_tutor + build_tutor_desc(
                        detection='アカウントがロックアウトされています。',
                        why_dangerous='ブルートフォース攻撃によりロックアウト閾値に達した可能性があります。',
                        mitre_key='evt_brute_force',
                        status='DANGER',
                    ),
                )
            return (base_level, base_desc, base_tutor)

        # --- 1000: アプリクラッシュの例外コード解析 ---
        if evt_id == '1000':
            if '0xc0000005' in msg_lower:
                return (
                    "WARNING",
                    f"{base_desc} - アクセス違反 (0xC0000005)",
                    base_tutor + build_tutor_desc(
                        detection='例外コード0xC0000005（アクセス違反）が記録されています。',
                        why_dangerous='バッファオーバーフローによるエクスプロイトの兆候である可能性があります。',
                        mitre_key=None,
                        status='WARNING',
                    ),
                )
            return (base_level, base_desc, base_tutor)

        # --- 1102: ログ消去は常にDANGER ---
        if evt_id == '1102':
            return ("DANGER", base_desc, base_tutor)

        # --- その他: メッセージ内の危険キーワードスキャン ---
        for kw in self.danger_keywords_in_message:
            if kw in msg_lower:
                escalated = "DANGER" if base_level == "WARNING" else base_level
                if base_level == "INFO":
                    escalated = "WARNING"
                return (
                    escalated,
                    f"{base_desc} - 不審キーワード: {kw}",
                    base_tutor + build_tutor_desc(
                        detection=f'メッセージ内に不審なキーワード「{kw}」が含まれています。',
                        why_dangerous='攻撃に関連するコマンドやツール名が検出されました。',
                        mitre_key=None,
                        status=escalated,
                    ),
                )

        return (base_level, base_desc, base_tutor)


    def _format_time(self, raw_time):
        if not raw_time:
            return ""
        raw_str = str(raw_time)
        match = re.search(r'/Date\((\d+)\)/', raw_str)
        if match:
            try:
                timestamp_ms = int(match.group(1))
                dt = datetime.fromtimestamp(timestamp_ms / 1000.0)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, OSError):
                pass
        return raw_str