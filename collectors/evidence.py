import winreg
import os
import codecs
import struct
import datetime

try:
    from utils.tutor_template import build_tutor_desc, MITRE_MAP
except ImportError:
    from tutor_template import build_tutor_desc, MITRE_MAP


class EvidenceCollector:
    """P17: MITRE ATT&CK + Tutor Mode 統合版 - 実行痕跡(UserAssist/Prefetch)解析"""

    def __init__(self):
        # ERR-EVD-001: 攻撃ツール検知キーワード
        self.attack_tools = [
            'mimikatz', 'psexec', 'paexec', 'cobalt', 'beacon',
            'rubeus', 'seatbelt', 'sharphound', 'bloodhound',
            'lazagne', 'procdump', 'nanodump', 'safetykatz',
            'sharpwmi', 'covenant', 'sliver', 'brute', 'crack',
            'hashcat', 'john', 'hydra', 'nmap', 'masscan',
            'chisel', 'ligolo', 'ngrok', 'frp', 'netcat', 'nc.exe',
            'plink', 'socat', 'rclone', 'megasync',
            'advanced_ip_scanner', 'angry_ip', 'nbtscan',
        ]

        # ERR-EVD-002: LOLBins / 不審なスクリプトエンジン
        self.lolbins = [
            'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
            'mshta', 'rundll32', 'regsvr32', 'certutil',
            'bitsadmin', 'msiexec', 'wmic', 'msconfig',
            'installutil', 'regasm', 'regsvcs', 'msbuild',
            'cmstp', 'esentutl', 'expand', 'extrac32',
            'makecab', 'replace', 'xwizard', 'msdt',
        ]

        # ERR-EVD-003: 横展開・偵察コマンド
        self.recon_tools = [
            'whoami', 'systeminfo', 'ipconfig', 'net.exe', 'net1.exe',
            'nltest', 'dsquery', 'csvde', 'ldifde',
            'quser', 'qwinsta', 'query', 'klist',
            'tasklist', 'taskkill', 'sc.exe', 'schtasks',
            'reg.exe', 'arp.exe', 'route', 'tracert',
            'netstat', 'nslookup', 'ping.exe',
        ]

        # ERR-EVD-004: 不審な実行パス
        self.suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\downloads\\',
            '\\perflogs\\', '\\programdata\\',
            '\\recycler\\', '\\$recycle.bin\\',
            '\\windows\\debug\\', '\\windows\\temp\\',
        ]

    def scan(self):
        evidence = []
        evidence.extend(self._scan_userassist())
        evidence.extend(self._scan_prefetch())
        return evidence

    # ==========================================================
    # UserAssist 解析
    # ==========================================================
    def _scan_userassist(self):
        results = []
        sub_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                guid_count = winreg.QueryInfoKey(key)[0]
                for i in range(guid_count):
                    guid = winreg.EnumKey(key, i)
                    count_subkey = (
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer"
                        r"\UserAssist\{}\Count".format(guid)
                    )

                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_subkey) as key2:
                            val_count = winreg.QueryInfoKey(key2)[1]
                            for j in range(val_count):
                                name, value, _ = winreg.EnumValue(key2, j)
                                # ROT13デコード
                                decoded_name = codecs.decode(name, 'rot_13')

                                # GUIアプリ実行履歴のみ抽出
                                if "{" in decoded_name or ".exe" not in decoded_name.lower():
                                    continue

                                # タイムスタンプ抽出（FILETIME: offset 60, 8 bytes）
                                timestamp_str = self._parse_userassist_timestamp(value)

                                # 実行回数抽出（offset 4, 4 bytes）
                                run_count = self._parse_userassist_runcount(value)

                                # 危険度判定
                                status, reason, desc = self._analyze_userassist(
                                    decoded_name, run_count
                                )

                                results.append({
                                    "source": "UserAssist (Registry)",
                                    "artifact": decoded_name,
                                    "timestamp": timestamp_str,
                                    "run_count": run_count,
                                    "status": status,
                                    "reason": reason,
                                    "desc": desc,
                                })
                    except Exception:
                        continue
        except Exception:
            pass

        # DANGER → WARNING → INFO の順にソート
        priority = {"DANGER": 0, "WARNING": 1, "INFO": 2, "SAFE": 3}
        results.sort(key=lambda x: (priority.get(x["status"], 9), x["artifact"]))
        return results

    def _parse_userassist_timestamp(self, raw_value):
        """UserAssistバイナリからFILETIMEを抽出（offset 60）"""
        try:
            if isinstance(raw_value, bytes) and len(raw_value) >= 68:
                filetime = struct.unpack('<Q', raw_value[60:68])[0]
                if filetime > 0:
                    # FILETIME → Python datetime
                    # FILETIMEは1601-01-01からの100ナノ秒単位
                    epoch_diff = 116444736000000000
                    timestamp = (filetime - epoch_diff) / 10000000
                    if timestamp > 0:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (struct.error, ValueError, OSError):
            pass
        return "Unknown"

    def _parse_userassist_runcount(self, raw_value):
        """UserAssistバイナリから実行回数を抽出（offset 4）"""
        try:
            if isinstance(raw_value, bytes) and len(raw_value) >= 8:
                return struct.unpack('<I', raw_value[4:8])[0]
        except (struct.error, ValueError):
            pass
        return 0

    def _analyze_userassist(self, decoded_name, run_count):
        """UserAssistエントリの危険度を判定し、統一フォーマットの解説を生成"""
        name_lower = decoded_name.lower()
        exe_name = os.path.basename(decoded_name).lower()

        # --- Rule 1: 攻撃ツールの実行痕跡 ---
        for tool in self.attack_tools:
            if tool in name_lower:
                return (
                    "DANGER",
                    f"攻撃ツール検知: {tool}",
                    build_tutor_desc(
                        detection=(
                            f'UserAssistレジストリに攻撃ツール「{tool}」の実行記録が残っています。'
                            f'実行回数: {run_count}回\n'
                            f'パス: {decoded_name}'
                        ),
                        why_dangerous=(
                            'UserAssistはエクスプローラ経由で実行されたプログラムの履歴を'
                            'ROT13エンコードで記録するレジストリキーです。'
                            '攻撃者がGUI操作でツールを実行した証拠であり、'
                            '侵害が対話的（ハンズオンキーボード）段階に進んでいることを示します。'
                        ),
                        mitre_key='evid_userassist_tool',
                        normal_vs_abnormal=(
                            '正常: UserAssistにはブラウザ、Office、設定画面等の一般アプリのみ記録される\n'
                            '異常: mimikatz、psexec、cobalt strike等の攻撃ツールが記録されている'
                        ),
                        next_steps=[
                            'Prefetchで同ファイルの実行時刻を照合する',
                            '同時刻帯に実行された他のプログラムを確認する',
                            'ファイルのハッシュ値を取得し、VirusTotal等で検索する',
                            'イベントログ(Security:4688)でコマンドライン引数を確認する',
                        ],
                        status='DANGER',
                    ),
                )

        # --- Rule 2: LOLBinsの実行 ---
        for lolbin in self.lolbins:
            lolbin_base = lolbin.replace('.exe', '')
            if exe_name == lolbin or exe_name == lolbin_base or exe_name.startswith(lolbin_base + '.'):
                return (
                    "WARNING",
                    f"LOLBin実行: {lolbin}",
                    build_tutor_desc(
                        detection=(
                            f'UserAssistにLiving-off-the-Land Binary「{lolbin}」の'
                            f'実行記録があります。実行回数: {run_count}回\n'
                            f'パス: {decoded_name}'
                        ),
                        why_dangerous=(
                            'LOLBin（Living-off-the-Land Binary）はWindowsに標準搭載された'
                            '正規ツールですが、攻撃者がマルウェアのダウンロード・実行・横展開に'
                            '悪用するケースが非常に多いです。'
                            '正規の管理作業で使用される場合もあるため、実行コンテキストの確認が必要です。'
                        ),
                        mitre_key='evid_userassist_recon',
                        normal_vs_abnormal=(
                            '正常: IT管理者が業務時間内にPowerShellやcmd.exeを使用する\n'
                            '異常: 深夜帯に一般ユーザーアカウントでcertutil、mshta等が実行されている'
                        ),
                        next_steps=[
                            'イベントログ(Security:4688, PowerShell:4104)でコマンドライン引数を確認する',
                            '実行時刻が業務時間内か確認する',
                            '同時刻帯のネットワーク接続(netstat)を確認する',
                            '正規の管理作業として説明がつくか、担当者に確認する',
                        ],
                        status='WARNING',
                    ),
                )

        # --- Rule 3: 偵察コマンドの実行 ---
        for recon in self.recon_tools:
            if recon in exe_name:
                return (
                    "WARNING",
                    f"偵察コマンド実行: {recon}",
                    build_tutor_desc(
                        detection=(
                            f'UserAssistに偵察コマンド「{recon}」の実行記録があります。'
                            f'実行回数: {run_count}回\n'
                            f'パス: {decoded_name}'
                        ),
                        why_dangerous=(
                            '攻撃者は侵害後の初期段階で、ネットワーク構成・ユーザー情報・'
                            'ドメイン情報を収集する「偵察活動」を行います。'
                            'whoami、systeminfo、net user 等のコマンドが短時間に集中して実行された場合、'
                            '攻撃者の手動偵察（Discovery フェーズ）の可能性があります。'
                        ),
                        mitre_key='evid_userassist_recon',
                        normal_vs_abnormal=(
                            '正常: IT管理者がトラブルシューティングでipconfig、netstat等を使用する\n'
                            '異常: whoami→systeminfo→net user→nltest が短時間に連続実行されている'
                        ),
                        next_steps=[
                            '同一時間帯（前後30分）に他の偵察コマンドが実行されていないか確認する',
                            '実行ユーザーアカウントが正当な管理者か確認する',
                            'イベントログでコマンドライン引数と出力先を確認する',
                            '3つ以上の偵察コマンドが集中していれば、インシデント対応を検討する',
                        ],
                        status='WARNING',
                    ),
                )

        # --- Rule 4: 不審なパスからの実行 ---
        for susp_path in self.suspicious_paths:
            if susp_path in name_lower:
                return (
                    "WARNING",
                    f"不審パスからの実行: {susp_path.strip(chr(92))}",
                    build_tutor_desc(
                        detection=(
                            f'UserAssistに不審なフォルダから実行されたプログラムの記録があります。'
                            f'実行回数: {run_count}回\n'
                            f'パス: {decoded_name}'
                        ),
                        why_dangerous=(
                            'Temp、Downloads、Publicフォルダはユーザー権限で書き込めるため、'
                            '攻撃者がマルウェアを配置する定番の場所です。'
                            '正規のインストーラが一時的に使用する場合もありますが、'
                            '見覚えのないEXEファイルが実行されていた場合は調査が必要です。'
                        ),
                        mitre_key='evid_userassist_path',
                        normal_vs_abnormal=(
                            '正常: ダウンロードしたインストーラをDownloadsフォルダから実行する\n'
                            '異常: Temp/ProgramData/Publicからランダム名のEXEが実行されている'
                        ),
                        next_steps=[
                            '該当パスにファイルがまだ存在するか確認する',
                            '存在する場合、ファイルのハッシュ値をVirusTotalで検索する',
                            'Zone.Identifier(ADS)でダウンロード元URLを確認する',
                            '削除済みの場合、Prefetch/PCAで実行時刻を特定する',
                        ],
                        status='WARNING',
                    ),
                )

        # --- Rule 5: 正常なエントリ ---
        return (
            "INFO",
            "",
            build_tutor_desc(
                detection=(
                    f'エクスプローラ経由で実行されたプログラムの記録です。'
                    f'実行回数: {run_count}回'
                ),
                why_dangerous='',
                mitre_key=None,
                status='INFO',
            ),
        )


    # ==========================================================
    # Prefetch 解析
    # ==========================================================
    def _scan_prefetch(self):
        results = []
        prefetch_dir = r"C:\Windows\Prefetch"
        if not os.path.exists(prefetch_dir):
            results.append({
                "source": "Prefetch",
                "artifact": "Prefetchフォルダ不在",
                "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "status": "WARNING",
                "reason": "Prefetchが無効化されている可能性",
                "desc": build_tutor_desc(
                    detection='C:\\Windows\\Prefetch フォルダが存在しません。',
                    why_dangerous=(
                        'Prefetchはプログラムの起動を高速化するためのキャッシュで、'
                        '実行されたプログラムの名前・パス・実行時刻が記録されます。'
                        '攻撃者が証拠隠滅のためにPrefetchを無効化・削除することがあります。'
                        'ただし、SSD環境やグループポリシーで正当に無効化されている場合もあります。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: C:\\Windows\\Prefetch が存在し、.pfファイルが多数格納されている\n'
                        '異常: フォルダ自体が存在しない、またはフォルダ内が空'
                    ),
                    next_steps=[
                        'レジストリ HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
                        '\\Memory Management\\PrefetchParameters の EnablePrefetcher 値を確認する',
                        '値が0なら無効化されている→いつ変更されたかイベントログで確認',
                        'Volume Shadow Copyから過去のPrefetchファイルを復元できないか試みる',
                    ],
                    status='WARNING',
                ),
            })
            return results

        try:
            pf_files = []
            for filename in os.listdir(prefetch_dir):
                if filename.endswith(".pf"):
                    filepath = os.path.join(prefetch_dir, filename)
                    try:
                        mtime = os.path.getmtime(filepath)
                        dt = datetime.datetime.fromtimestamp(mtime)
                        pf_files.append((filename, dt))
                    except OSError:
                        continue

            # 最新順にソート
            pf_files.sort(key=lambda x: x[1], reverse=True)

            for filename, dt in pf_files[:80]:
                timestamp_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                status, reason, desc = self._analyze_prefetch(filename, dt)

                results.append({
                    "source": "Prefetch File",
                    "artifact": filename,
                    "timestamp": timestamp_str,
                    "status": status,
                    "reason": reason,
                    "desc": desc,
                })
        except PermissionError:
            results.append({
                "source": "Prefetch",
                "artifact": "アクセス拒否",
                "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "status": "WARNING",
                "reason": "管理者権限が必要です",
                "desc": build_tutor_desc(
                    detection='C:\\Windows\\Prefetch フォルダへのアクセスが拒否されました。',
                    why_dangerous=(
                        'Prefetchフォルダの読み取りには管理者権限が必要です。'
                        '権限不足の場合、プログラム実行痕跡の解析ができず、'
                        '攻撃ツールの実行有無を確認できません。'
                    ),
                    mitre_key=None,
                    normal_vs_abnormal=(
                        '正常: 管理者権限で実行すればアクセス可能\n'
                        '異常: 管理者でもアクセスできない場合はACLが改変されている可能性'
                    ),
                    next_steps=[
                        'このツールを「管理者として実行」で再起動してください',
                        'start.batを右クリック→「管理者として実行」を選択',
                    ],
                    status='WARNING',
                ),
            })
        except Exception:
            pass

        # DANGER → WARNING → INFO の順にソート、同一ステータス内は新しい順
        priority = {"DANGER": 0, "WARNING": 1, "INFO": 2, "SAFE": 3}
        results.sort(key=lambda x: (priority.get(x["status"], 9), x["artifact"]))
        return results

    def _analyze_prefetch(self, filename, dt):
        """Prefetchファイル名から危険度を判定し、統一フォーマットの解説を生成"""
        # Prefetchファイル名形式: EXENAME-XXXXXXXX.pf
        name_lower = filename.lower()
        # ハッシュ部分を除去してEXE名を抽出
        exe_part = filename.rsplit('-', 1)[0] if '-' in filename else filename.replace('.pf', '')
        exe_lower = exe_part.lower()
        timestamp_str = dt.strftime('%Y-%m-%d %H:%M:%S')

        # --- Rule 1: 攻撃ツールのPrefetch ---
        for tool in self.attack_tools:
            if tool in exe_lower:
                return (
                    "DANGER",
                    f"攻撃ツール実行痕跡: {tool}",
                    build_tutor_desc(
                        detection=(
                            f'Prefetchに攻撃ツール「{tool}」の実行キャッシュが残っています。\n'
                            f'ファイル: {filename}\n'
                            f'最終実行: {timestamp_str}'
                        ),
                        why_dangerous=(
                            'Prefetchはプログラム実行時にOSが自動作成するキャッシュファイルで、'
                            'プログラム本体が削除されても実行の証拠として残り続けます。'
                            '攻撃ツールのPrefetchが存在するということは、'
                            '過去にこのPCで当該ツールが実行されたことを意味します。'
                        ),
                        mitre_key='evid_prefetch_tool',
                        normal_vs_abnormal=(
                            '正常: ブラウザ、Office、Windows標準ツールのPrefetchのみ存在する\n'
                            '異常: mimikatz、psexec、sharphound等のPrefetchが存在する'
                        ),
                        next_steps=[
                            'Prefetch解析ツール(PECmd等)で詳細な実行時刻とロードしたDLLを確認する',
                            '同時刻帯に他の攻撃ツールが実行されていないか確認する',
                            'UserAssist/PCA/CAM DBと照合して実行パスを特定する',
                            'イベントログ(Security:4688)で実行ユーザーとコマンドラインを確認する',
                        ],
                        status='DANGER',
                    ),
                )

        # --- Rule 2: LOLBinsのPrefetch ---
        for lolbin in self.lolbins:
            lolbin_name = lolbin.replace('.exe', '')
            if exe_lower == lolbin_name or exe_lower == lolbin_name + '.exe' or exe_lower.startswith(lolbin_name + '.'):
                return (
                    "WARNING",
                    f"LOLBin実行痕跡: {lolbin}",
                    build_tutor_desc(
                        detection=(
                            f'PrefetchにLOLBin「{lolbin}」の実行キャッシュがあります。\n'
                            f'ファイル: {filename}\n'
                            f'最終実行: {timestamp_str}'
                        ),
                        why_dangerous=(
                            'LOLBin自体はWindows標準ツールですが、'
                            '攻撃者がファイルレス攻撃やダウンローダとして悪用するケースが多く、'
                            'Prefetchからはコマンドライン引数が分からないため、'
                            'イベントログとの照合で正規利用か攻撃利用かを判断する必要があります。'
                        ),
                        mitre_key='evid_prefetch_lolbin',
                        normal_vs_abnormal=(
                            '正常: PowerShell、cmd.exe等は日常的に実行される\n'
                            '異常: mshta、cmstp、regsvr32等の通常使わないLOLBinのPrefetchが存在する'
                        ),
                        next_steps=[
                            'イベントログ(Security:4688)で同時刻のコマンドライン引数を確認する',
                            'PowerShell:4104でスクリプトブロックログを確認する',
                            '正規の管理作業として説明がつくか確認する',
                        ],
                        status='WARNING',
                    ),
                )

        # --- Rule 3: 偵察コマンドのPrefetch ---
        for recon in self.recon_tools:
            recon_name = recon.replace('.exe', '')
            if exe_lower == recon_name or exe_lower == recon_name.replace('.exe', '') + '.exe' or exe_lower.startswith(recon_name + '.') or exe_lower.startswith(recon_name + '_'):
                return (
                    "WARNING",
                    f"偵察コマンド痕跡: {recon}",
                    build_tutor_desc(
                        detection=(
                            f'Prefetchに偵察コマンド「{recon}」の実行キャッシュがあります。\n'
                            f'ファイル: {filename}\n'
                            f'最終実行: {timestamp_str}'
                        ),
                        why_dangerous=(
                            '偵察コマンド単体では必ずしも危険とは限りませんが、'
                            '複数の偵察コマンドが短時間に集中して実行されている場合、'
                            '攻撃者による環境調査（MITRE ATT&CK: Discovery）の可能性があります。'
                        ),
                        mitre_key='evid_prefetch_recon',
                        normal_vs_abnormal=(
                            '正常: IT管理者がトラブルシューティングで偵察コマンドを使用する\n'
                            '異常: 短時間に3つ以上の偵察コマンドが集中して実行されている'
                        ),
                        next_steps=[
                            '同時刻帯（前後1時間）に他の偵察コマンドのPrefetchがないか確認する',
                            '3つ以上の偵察コマンドが集中していればインシデント対応を検討する',
                            '実行ユーザーと実行時間帯（業務時間内/外）を確認する',
                        ],
                        status='WARNING',
                    ),
                )

        # --- Rule 4: 正常なエントリ ---
        return (
            "INFO",
            "",
            build_tutor_desc(
                detection=f'プログラム実行キャッシュです。最終実行: {timestamp_str}',
                why_dangerous='',
                mitre_key=None,
                status='INFO',
            ),
        )
