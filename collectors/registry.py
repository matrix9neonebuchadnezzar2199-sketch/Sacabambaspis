# -*- coding: utf-8 -*-
# collectors/registry.py - P12+P16: Tutor Mode 3段構成 + 統一解説フォーマット対応
import winreg
import os
from utils.tutor_template import build_tutor_desc


class RegistryCollector:
    """レジストリ自動起動解析 - Run/RunOnceキーの検査"""

    def __init__(self):
        self.autorun_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        self.attack_tools = [
            'mimikatz', 'psexec', 'cobalt', 'beacon', 'rubeus',
            'sharphound', 'bloodhound', 'lazagne', 'sliver',
            'chisel', 'ligolo', 'ngrok', 'netcat', 'nmap',
            'rclone', 'megasync', 'procdump',
        ]

        self.lolbins = [
            'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
            'mshta', 'rundll32', 'regsvr32', 'certutil',
            'bitsadmin', 'msiexec', 'bash', 'installutil',
            'regasm', 'msbuild', 'cmstp',
        ]

        self.suspicious_args = [
            '-enc ', '-encodedcommand', '-nop', '-noprofile',
            '-windowstyle hidden', '-w hidden', '-ep bypass',
            '-executionpolicy bypass', 'base64', 'invoke-expression',
            'iex ', 'downloadstring', 'downloadfile', 'net.webclient',
            'http://', 'https://', 'frombase64string',
        ]

        self.suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\downloads\\',
            '\\perflogs\\', '\\programdata\\',
            '\\recycler\\', '\\$recycle.bin\\',
        ]

    def scan(self):
        results = []
        for hive, subkey in self.autorun_keys:
            results.extend(self._read_key(hive, subkey))

        priority = {"DANGER": 0, "WARNING": 1, "SAFE": 2, "INFO": 3}
        results.sort(key=lambda x: (
            priority.get(x["status"], 9), x["entry"]))
        return results

    def _read_key(self, hive, subkey):
        entries = []
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        value_str = str(value)
                        hive_name = ("HKLM" if hive == winreg.HKEY_LOCAL_MACHINE
                                     else "HKCU")
                        location = f"{hive_name}\\{subkey}"

                        status, reason, desc = self._analyze_value(
                            name, value_str, location)

                        entries.append({
                            "location": location,
                            "entry": name,
                            "value": value_str,
                            "status": status,
                            "reason": reason,
                            "desc": desc,
                        })
                    except OSError:
                        continue
        except OSError:
            pass
        return entries

    def _analyze_value(self, entry_name, value, location):
        """レジストリ自動起動エントリの危険度判定と統一解説生成"""
        val_lower = value.lower()
        name_lower = entry_name.lower()

        # --- Rule 1: 攻撃ツールの自動起動 ---
        for tool in self.attack_tools:
            tool_base = tool.replace('.exe', '')
            if (f'\\{tool}' in val_lower
                    or f'\\{tool_base}.exe' in val_lower
                    or f'/{tool}' in val_lower
                    or val_lower.startswith(tool)
                    or tool in name_lower):
                return (
                    "DANGER",
                    f"攻撃ツール検知: {tool}",
                    build_tutor_desc(
                        detection=(
                            f"レジストリ自動起動キーに攻撃ツール「{tool}」が"
                            f"登録されています。\n"
                            f"場所: {location}\n"
                            f"エントリ名: {entry_name}\n"
                            f"値: {value}"
                        ),
                        why_dangerous=(
                            "レジストリのRunキーは、ユーザーログオン時に"
                            "自動的にプログラムを実行する最も基本的な永続化手法です。"
                            "攻撃ツールが登録されている場合、OS起動のたびに"
                            "悪意のあるプログラムが自動実行されています。"
                            "攻撃者は初期侵入後、Runキーに永続化を設定し、"
                            "再起動後もアクセスを維持します。"
                        ),
                        mitre_key="reg_attack_tool",
                        normal_vs_abnormal=(
                            "【正常】攻撃ツールがRunキーに登録されることは"
                            "いかなる場合も正常ではありません。\n"
                            "【異常】100%異常です。即座に対応が必要です。\n"
                            "【判断基準】攻撃ツールの自動起動は誤検知の可能性が極めて低い。"
                        ),
                        next_steps=[
                            "該当レジストリエントリを即座に削除する",
                            "値に記載されたファイルパスのEXEを確保（隔離）する",
                            "ファイルのハッシュ値をVirusTotalで検索する",
                            "同時刻帯に他のRunキーやサービスが追加されていないか確認する",
                            "「イベントログ」タブで同時刻のログオン・プロセス作成を確認する",
                        ],
                        status="DANGER",
                    ),
                )

        # --- Rule 2: LOLBin + 不審引数の組み合わせ ---
        found_lolbin = None
        for lolbin in self.lolbins:
            lolbin_base = lolbin.replace('.exe', '')
            if lolbin in val_lower or lolbin_base in val_lower:
                found_lolbin = lolbin
                break

        if found_lolbin:
            found_args = [a for a in self.suspicious_args if a in val_lower]

            if found_args:
                args_str = ', '.join(found_args[:3])
                return (
                    "DANGER",
                    f"LOLBin+不審引数: {found_lolbin} ({args_str})",
                    build_tutor_desc(
                        detection=(
                            f"レジストリ自動起動キーにLOLBin「{found_lolbin}」が"
                            f"不審な引数付きで登録されています。\n"
                            f"場所: {location}\n"
                            f"エントリ名: {entry_name}\n"
                            f"値: {value}\n"
                            f"検知引数: {args_str}"
                        ),
                        why_dangerous=(
                            "Windows標準ツールにBase64エンコード、非表示実行、"
                            "ダウンロードコマンド等の不審な引数が組み合わされている場合、"
                            "ファイルレス攻撃による永続化の可能性が非常に高いです。"
                            "攻撃者はログオンのたびにC2サーバーに接続したり、"
                            "追加のマルウェアをダウンロードする仕組みを構築します。"
                            "ディスク上にマルウェア本体がないため、"
                            "アンチウイルスでの検知が困難です。"
                        ),
                        mitre_key="reg_lolbin_args",
                        normal_vs_abnormal=(
                            "【正常】-noprofileや-executionpolicy bypassは"
                            "管理スクリプトで使用されることがありますが、"
                            "Runキーとの組み合わせは稀です。\n"
                            "【異常】-enc（Base64）、downloadstring、iex等は"
                            "ほぼ確実に攻撃です。\n"
                            "【判断基準】Base64部分をデコードして内容を確認。"
                            "URL/IPが含まれていればC2通信の可能性大。"
                        ),
                        next_steps=[
                            "Base64部分があればデコードして実際のコマンドを確認する",
                            "URL/IPが含まれていればC2サーバーの可能性を調査する",
                            "該当レジストリエントリを即座に削除する",
                            "イベントログ(PowerShell:4104)で実行履歴を確認する",
                        ],
                        status="DANGER",
                    ),
                )

            # LOLBin + 不審パス
            found_path = None
            for susp_path in self.suspicious_paths:
                if susp_path in val_lower:
                    found_path = susp_path
                    break

            if found_path:
                return (
                    "DANGER",
                    f"LOLBin+不審パス: {found_lolbin} ({found_path.strip(chr(92))})",
                    build_tutor_desc(
                        detection=(
                            f"LOLBin「{found_lolbin}」が不審なフォルダから"
                            f"自動起動されるよう登録されています。\n"
                            f"場所: {location}\n"
                            f"エントリ名: {entry_name}\n"
                            f"値: {value}"
                        ),
                        why_dangerous=(
                            f"「{found_path.strip(chr(92))}」はユーザー権限で"
                            "書き込めるフォルダです。"
                            "正規の自動起動設定では、通常これらのパスから"
                            "スクリプトエンジンを呼び出すことはありません。"
                            "攻撃者がスクリプトファイルを配置し、LOLBin経由で"
                            "実行する永続化手法です。"
                        ),
                        mitre_key="reg_lolbin_path",
                        normal_vs_abnormal=(
                            "【正常】一部のインストーラーがTemp経由で"
                            "セットアップスクリプトを実行する場合がありますが、"
                            "永続的なRunキー登録は通常行いません。\n"
                            "【異常】Temp/Public/ProgramDataからLOLBinを起動は高リスク。\n"
                            "【判断基準】指定パスのファイルが正規ソフトウェアか確認。"
                        ),
                        next_steps=[
                            "指定パスのファイルが存在するか確認する",
                            "存在する場合、ファイル内容とデジタル署名を確認する",
                            "Zone.Identifier(ADS)でファイルの出所を確認する",
                            "該当レジストリエントリの削除を検討する",
                        ],
                        status="DANGER",
                    ),
                )

            # LOLBinのみ
            return (
                "WARNING",
                f"LOLBin自動起動: {found_lolbin}",
                build_tutor_desc(
                    detection=(
                        f"レジストリ自動起動キーにLOLBin「{found_lolbin}」が"
                        f"登録されています。\n"
                        f"場所: {location}\n"
                        f"エントリ名: {entry_name}\n"
                        f"値: {value}"
                    ),
                    why_dangerous=(
                        "LOLBin（Living-off-the-Land Binary）はWindows標準ツールですが、"
                        "攻撃者がRunキーと組み合わせて悪用するケースがあります。"
                        "ただし、正規のソフトウェアがrundll32やcmd.exeを使用して"
                        "起動時処理を行う場合もあるため、コマンドの内容確認が必要です。"
                    ),
                    normal_vs_abnormal=(
                        "【正常】企業配布のログオンスクリプト、"
                        "正規ソフトのrundll32呼び出し等。\n"
                        "【異常】不明なエントリ名、見覚えのないコマンド引数。\n"
                        "【判断基準】エントリ名から正規のソフトウェアを特定できるか。"
                    ),
                    next_steps=[
                        "コマンドライン引数の全文を確認し正規ソフトか判断する",
                        "エントリ名から正規のソフトウェア名が推測できるか確認する",
                        "不明なエントリは管理者に正当性を確認する",
                    ],
                    status="WARNING",
                ),
            )

        # --- Rule 3: 不審パスからの自動起動 ---
        for susp_path in self.suspicious_paths:
            if susp_path in val_lower:
                return (
                    "WARNING",
                    f"不審パスからの自動起動: {susp_path.strip(chr(92))}",
                    build_tutor_desc(
                        detection=(
                            f"不審なフォルダからプログラムが自動起動されるよう"
                            f"レジストリに登録されています。\n"
                            f"場所: {location}\n"
                            f"エントリ名: {entry_name}\n"
                            f"値: {value}"
                        ),
                        why_dangerous=(
                            f"「{susp_path.strip(chr(92))}」等のユーザー書き込み可能フォルダ"
                            "から自動起動されるプログラムは、攻撃者がマルウェアを"
                            "配置した可能性があります。正規のソフトウェアは"
                            "Program Files配下からの起動が標準です。"
                        ),
                        normal_vs_abnormal=(
                            "【正常】一時的なソフトウェアアップデータが"
                            "Tempを使用する場合がありますが、通常はRunOnceに"
                            "登録され1回実行後に削除されます。\n"
                            "【異常】恒久的なRunキーにTemp/Publicパスが登録。\n"
                            "【判断基準】ファイルの署名と作成時期を確認。"
                        ),
                        next_steps=[
                            "指定パスのファイルが存在するか確認する",
                            "ファイルのデジタル署名を確認する",
                            "ファイルのハッシュ値をVirusTotalで検索する",
                        ],
                        status="WARNING",
                    ),
                )

        # --- Rule 4: 正常 ---
        return (
            "SAFE",
            "",
            build_tutor_desc(
                detection=(
                    f"レジストリ自動起動キーに登録されたエントリです。\n"
                    f"場所: {location}\n"
                    f"エントリ名: {entry_name}\n"
                    f"値: {value}"
                ),
                why_dangerous="",
                normal_vs_abnormal=(
                    "コマンド内容に明らかな不審点は検出されませんでした。"
                    "正規のソフトウェアによる自動起動設定と判断されます。"
                ),
                status="SAFE",
            ),
        )
