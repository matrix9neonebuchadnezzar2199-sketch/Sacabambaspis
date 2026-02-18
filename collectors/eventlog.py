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
        # 各エントリ: level, desc(短い表示名), tutor(3段構成の詳細解説)
        self.target_events = {
            '1102': {
                'level': 'DANGER',
                'desc': '🗑️ 監査ログ消去',
                'tutor': (
                    "【検知内容】Securityイベントログが消去されました（Event ID: 1102）。\n\n"
                    "【なぜ危険か】監査ログの消去は、攻撃者が侵害の痕跡を隠滅する"
                    "最も典型的な手法の一つです（MITRE ATT&CK: T1070.001）。"
                    "正当な理由なくSecurityログが消去されることは通常ありません。"
                    "ログ消去の直前に記録されていたイベントが攻撃の核心である可能性が高いです。\n\n"
                    "【次の調査手順】\n"
                    "① ログ消去を実行したアカウント名とログオン元IPを確認する\n"
                    "② 消去直前のイベント（バックアップやSIEMに転送済みのログ）を確認する\n"
                    "③ 同時刻帯の他のログ（System, PowerShell）に残っている痕跡を確認する\n"
                    "④ Volume Shadow Copyからイベントログの復元を試みる"
                ),
            },
            '4624': {
                'level': 'INFO',
                'desc': '🔑 ログオン成功',
                'tutor': (
                    "【検知内容】アカウントのログオンが成功しました（Event ID: 4624）。\n\n"
                    "【なぜ危険か】ログオン成功自体は正常な動作ですが、以下の場合は要注意です：\n"
                    "・ログオンタイプ3(ネットワーク)で見覚えのないソースIPからのアクセス\n"
                    "・ログオンタイプ10(RDP)が業務時間外に発生\n"
                    "・短時間に異なるアカウントで大量のログオン成功\n"
                    "・無効化されているはずのアカウントでのログオン\n\n"
                    "【次の調査手順】\n"
                    "① ログオンタイプ（2=対話, 3=ネットワーク, 10=RDP）を確認する\n"
                    "② ソースIPアドレスが既知の端末か確認する\n"
                    "③ 同一アカウントのログオン失敗(4625)が直前に大量にないか確認する\n"
                    "④ ログオン時刻が業務時間内か確認する"
                ),
            },
            '4625': {
                'level': 'WARNING',
                'desc': '🚫 ログオン失敗',
                'tutor': (
                    "【検知内容】アカウントのログオンが失敗しました（Event ID: 4625）。\n\n"
                    "【なぜ危険か】単発のログオン失敗はパスワード入力ミスで日常的に発生しますが、"
                    "短時間に同一アカウントまたは同一ソースIPから大量に発生している場合、"
                    "ブルートフォース攻撃やパスワードスプレー攻撃の可能性があります"
                    "（MITRE ATT&CK: T1110）。"
                    "特にサブステータス0xC000006A（パスワード誤り）が連続する場合は要注意です。\n\n"
                    "【次の調査手順】\n"
                    "① 同一アカウントに対する失敗が10件以上/1時間ないか確認する\n"
                    "② ソースIPアドレスが内部ネットワーク外でないか確認する\n"
                    "③ 失敗の直後にログオン成功(4624)がないか確認する（突破された可能性）\n"
                    "④ 対象アカウントのパスワード変更・ロックアウト状態を確認する"
                ),
            },
            '4672': {
                'level': 'WARNING',
                'desc': '👑 管理者権限行使',
                'tutor': (
                    "【検知内容】特権（管理者権限）がアカウントに割り当てられました"
                    "（Event ID: 4672）。\n\n"
                    "【なぜ危険か】SeDebugPrivilege、SeTcbPrivilege等の特権は"
                    "プロセスメモリの読み書き、トークン偽装、サービス操作など"
                    "システムの完全な制御を可能にします。"
                    "攻撃者が権限昇格に成功した場合、このイベントが記録されます。"
                    "正規の管理者アカウントでは正常に発生しますが、"
                    "一般ユーザーアカウントで発生した場合は権限昇格攻撃の疑いがあります。\n\n"
                    "【次の調査手順】\n"
                    "① 特権が付与されたアカウントが正規の管理者か確認する\n"
                    "② 一般ユーザーに特権が付与されていれば、権限昇格の手法を調査する\n"
                    "③ 同時刻の4688(プロセス作成)で実行されたコマンドを確認する\n"
                    "④ 付与された特権の種類（SeDebugPrivilege等）を確認する"
                ),
            },
            '4688': {
                'level': 'INFO',
                'desc': '⚙️ プロセス作成',
                'tutor': (
                    "【検知内容】新しいプロセスが作成されました（Event ID: 4688）。\n\n"
                    "【なぜ危険か】プロセス作成イベント自体は正常ですが、"
                    "コマンドライン引数の監査が有効な場合、攻撃者が実行したコマンドの"
                    "完全な記録が残ります。以下のパターンに注目してください：\n"
                    "・PowerShellの-enc（Base64エンコード）引数\n"
                    "・cmd.exe /c による一時的なコマンド実行\n"
                    "・certutil -urlcache によるファイルダウンロード\n"
                    "・親プロセスがOfficeアプリ(WINWORD.EXE等)のケース\n\n"
                    "【次の調査手順】\n"
                    "① コマンドライン引数にBase64文字列やURLが含まれていないか確認する\n"
                    "② 親プロセスが正当か確認する（ExcelからPowerShellが起動は異常）\n"
                    "③ 実行ユーザーとプロセスの組み合わせが妥当か確認する\n"
                    "④ 同時刻のネットワーク接続ログと照合する"
                ),
            },
            '6005': {
                'level': 'INFO',
                'desc': '🖥️ PC起動',
                'tutor': (
                    "【検知内容】イベントログサービスが開始されました＝PC起動"
                    "（Event ID: 6005）。\n\n"
                    "【なぜ危険か】通常は正常な起動記録ですが、以下の場合は注意が必要です：\n"
                    "・業務時間外の深夜・早朝に起動されている\n"
                    "・直前に異常終了(ID:41)が記録されている\n"
                    "・短時間に複数回の起動・終了が繰り返されている\n\n"
                    "【次の調査手順】\n"
                    "① 起動時刻が想定される運用スケジュールと一致するか確認する\n"
                    "② 直前のシャットダウン(6006)または異常終了(41)の有無を確認する\n"
                    "③ 起動直後のログオン(4624)でアクセスしたアカウントを確認する"
                ),
            },
            '6006': {
                'level': 'INFO',
                'desc': '💤 シャットダウン',
                'tutor': (
                    "【検知内容】イベントログサービスが停止されました＝正常シャットダウン"
                    "（Event ID: 6006）。\n\n"
                    "【なぜ危険か】正常なシャットダウン記録です。"
                    "攻撃者がフォレンジック調査を妨害するために"
                    "意図的にシャットダウン・再起動を行う場合があります。"
                    "メモリ上の証拠（マルウェアのプロセス、ネットワーク接続）は"
                    "再起動で消失します。\n\n"
                    "【次の調査手順】\n"
                    "① シャットダウンの前後で不審なイベント（ログ消去等）がないか確認する\n"
                    "② シャットダウンを実行したユーザーアカウントを確認する\n"
                    "③ 想定外のタイミングでのシャットダウンでないか確認する"
                ),
            },
            '41': {
                'level': 'DANGER',
                'desc': '⚡ 異常終了',
                'tutor': (
                    "【検知内容】システムが正常にシャットダウンされずに停止しました"
                    "（Event ID: 41 - Kernel-Power）。\n\n"
                    "【なぜ危険か】異常終了は以下のケースで発生します：\n"
                    "・停電やハードウェア故障\n"
                    "・カーネルレベルのクラッシュ（BSoD）\n"
                    "・攻撃者がシステムを強制終了してメモリ上の証拠を消去\n"
                    "・ランサムウェアやワイパーによるシステム破壊\n"
                    "単発であればハードウェア要因の可能性が高いですが、"
                    "他の不審なイベントと組み合わさっている場合は攻撃の可能性があります。\n\n"
                    "【次の調査手順】\n"
                    "① 異常終了の直前に記録されたイベントを確認する\n"
                    "② BugCheckCode（BSoDコード）が記録されていれば原因を特定する\n"
                    "③ 同時期に複数台で異常終了が発生していないか確認する\n"
                    "④ ハードウェアの電源ログ・UPS記録を確認する"
                ),
            },
            '7045': {
                'level': 'DANGER',
                'desc': '🆕 サービス登録',
                'tutor': (
                    "【検知内容】新しいサービスがシステムにインストールされました"
                    "（Event ID: 7045）。\n\n"
                    "【なぜ危険か】サービス登録はシステムレベルの永続化手法として"
                    "攻撃者に頻繁に悪用されます（MITRE ATT&CK: T1543.003）。"
                    "登録されたサービスはSYSTEM権限で動作し、OS起動時に自動実行されます。"
                    "特に以下のパターンは高リスクです：\n"
                    "・サービスパスにPowerShellやcmd.exeが含まれる\n"
                    "・サービス名がランダム文字列\n"
                    "・パスがTemp、ProgramData等の書き込み可能フォルダ\n\n"
                    "【次の調査手順】\n"
                    "① サービス名とサービスパス（ImagePath）を確認する\n"
                    "② パスのEXEファイルが正規のソフトウェアか確認する\n"
                    "③ サービスの実行アカウント（LocalSystem等）を確認する\n"
                    "④ 同時刻にPsExec等のリモート実行ツールが使用されていないか確認する"
                ),
            },
            '1000': {
                'level': 'WARNING',
                'desc': '💥 アプリクラッシュ',
                'tutor': (
                    "【検知内容】アプリケーションがクラッシュしました"
                    "（Event ID: 1000 - Application Error）。\n\n"
                    "【なぜ危険か】アプリクラッシュ自体はバグによる正常な事象ですが、"
                    "以下の場合はエクスプロイト（脆弱性攻撃）の兆候である可能性があります：\n"
                    "・ブラウザ、Office、PDFリーダーが繰り返しクラッシュ\n"
                    "・例外コード0xC0000005（アクセス違反）が記録されている\n"
                    "・クラッシュ直後に新しいプロセスが起動されている\n"
                    "・見覚えのないアプリケーションがクラッシュしている\n\n"
                    "【次の調査手順】\n"
                    "① クラッシュしたアプリケーションの名前とバージョンを確認する\n"
                    "② 例外コードが0xC0000005（バッファオーバーフローの兆候）か確認する\n"
                    "③ クラッシュの直前・直後に新しいプロセス(4688)が作成されていないか確認する\n"
                    "④ 同一アプリの繰り返しクラッシュがないか確認する"
                ),
            },
            '11707': {
                'level': 'INFO',
                'desc': '📦 アプリインストール',
                'tutor': (
                    "【検知内容】MSIインストーラによるアプリケーションのインストールが"
                    "完了しました（Event ID: 11707）。\n\n"
                    "【なぜ危険か】正規のインストール記録ですが、"
                    "攻撃者がリモートアクセスツール（RAT）や"
                    "バックドアをMSI形式で配布・インストールするケースがあります。"
                    "見覚えのないアプリケーション名、業務時間外のインストール、"
                    "一般ユーザーによるインストールは調査が必要です。\n\n"
                    "【次の調査手順】\n"
                    "① インストールされたアプリケーション名を確認する\n"
                    "② インストールを実行したユーザーアカウントを確認する\n"
                    "③ インストール時刻が業務時間内か確認する\n"
                    "④ 正規のソフトウェア配布リストに含まれているか確認する"
                ),
            },
            '11724': {
                'level': 'INFO',
                'desc': '🗑️ アプリ削除',
                'tutor': (
                    "【検知内容】MSIインストーラによるアプリケーションの削除が"
                    "完了しました（Event ID: 11724）。\n\n"
                    "【なぜ危険か】アプリ削除自体は正常な操作ですが、"
                    "攻撃者がセキュリティソフト（AV/EDR）をアンインストールする"
                    "ケースがあります（MITRE ATT&CK: T1562.001）。"
                    "セキュリティ製品の削除、監視エージェントの削除は即座に調査が必要です。\n\n"
                    "【次の調査手順】\n"
                    "① 削除されたアプリケーション名がセキュリティ製品でないか確認する\n"
                    "② 削除を実行したユーザーアカウントを確認する\n"
                    "③ 削除直後に不審なプロセスやサービスが登録されていないか確認する"
                ),
            },
            '4104': {
                'level': 'DANGER',
                'desc': '📜 PowerShell実行',
                'tutor': (
                    "【検知内容】PowerShellスクリプトブロックが実行されました"
                    "（Event ID: 4104 - Script Block Logging）。\n\n"
                    "【なぜ危険か】PowerShellは攻撃者が最も多用するツールの一つで、"
                    "ファイルレス攻撃（ディスクにマルウェアを書かない手法）の主要な手段です。"
                    "スクリプトブロックログにはBase64デコード後の実際のコードが記録されるため、"
                    "難読化されたコマンドの実態を確認できる貴重な証拠です。"
                    "以下のキーワードが含まれる場合は高リスクです：\n"
                    "・Invoke-Expression / IEX（コード動的実行）\n"
                    "・Net.WebClient / DownloadString（リモートコード取得）\n"
                    "・-EncodedCommand（Base64エンコード）\n"
                    "・Invoke-Mimikatz / Get-Credential（認証情報窃取）\n"
                    "・New-Object IO.MemoryStream（メモリ内実行）\n\n"
                    "【次の調査手順】\n"
                    "① スクリプトブロックの全文を確認し、不審なコマンドを特定する\n"
                    "② 実行ユーザーアカウントと実行時刻を確認する\n"
                    "③ ダウンロード先URLが含まれていればアクセス先を調査する\n"
                    "④ 同時刻のネットワーク接続ログと照合する"
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
                    'tutor': f'イベントID {evt_id} の記録です。',
                })
                raw_msg = entry.get('Msg', '') or ''
                short_msg = (raw_msg[:300] + '...') if len(raw_msg) > 300 else raw_msg
                formatted_time = self._format_time(entry.get('TimeCreated', ''))

                # メッセージ内容に基づく追加判定
                status, reason, tutor_text = self._analyze_message(
                    evt_id, info, raw_msg
                )

                # P17: MITREマッピング付きで出力
                mitre_key = self.EVT_MITRE_MAP.get(evt_id)
                mitre_info = ""
                if mitre_key and mitre_key in MITRE_MAP:
                    tid, tname, turl = MITRE_MAP[mitre_key]
                    mitre_info = f"\n\n【MITRE ATT&CK】{tid} - {tname}\n{turl}"

                results.append({
                    "id": evt_id,
                    "log": log_name.split('/')[-1],
                    "time": formatted_time,
                    "message": short_msg,
                    "status": status,
                    "reason": reason,
                    "desc": tutor_text + mitre_info,
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
                        base_tutor + (
                            f"\n\n⚠️ 【追加検知】サービスのImagePathに"
                            f"不審なパターン「{pattern}」が含まれています。"
                            f"攻撃者によるサービス永続化の可能性が高いです。"
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
                    base_tutor + (
                        f"\n\n⚠️ 【追加検知】スクリプトブロック内に"
                        f"危険なキーワード「{kw_str}」が検出されました。"
                        f"攻撃コードが実行された可能性があります。"
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
                    base_tutor + (
                        "\n\n⚠️ 【追加検知】アカウントがロックアウトされています。"
                        "ブルートフォース攻撃によりロックアウト閾値に達した可能性があります。"
                    ),
                )
            return (base_level, base_desc, base_tutor)

        # --- 1000: アプリクラッシュの例外コード解析 ---
        if evt_id == '1000':
            if '0xc0000005' in msg_lower:
                return (
                    "WARNING",
                    f"{base_desc} - アクセス違反 (0xC0000005)",
                    base_tutor + (
                        "\n\n⚠️ 【追加検知】例外コード0xC0000005（アクセス違反）が記録されています。"
                        "バッファオーバーフローによるエクスプロイトの兆候である可能性があります。"
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
                    base_tutor + (
                        f"\n\n⚠️ 【追加検知】メッセージ内に"
                        f"不審なキーワード「{kw}」が含まれています。"
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