# -*- coding: utf-8 -*-
# collectors/persistence.py - P12+P17: 永続化メカニズム解析 + 統一解説+MITREマッピング
import os
import xml.etree.ElementTree as ET
import subprocess
from utils.tutor_template import build_tutor_desc


class PersistenceCollector:
    """永続化メカニズム解析 - タスクスケジューラ/WMI"""

    def __init__(self):
        self.tasks_dir = r"C:\Windows\System32\Tasks"

        self.attack_tools = [
            'mimikatz', 'psexec', 'cobalt', 'beacon', 'rubeus',
            'sharphound', 'bloodhound', 'lazagne', 'sliver',
            'covenant', 'chisel', 'ligolo', 'ngrok', 'netcat',
            'nc.exe', 'nmap', 'rclone', 'megasync',
        ]

        self.lolbins = [
            'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
            'mshta', 'rundll32', 'regsvr32', 'certutil',
            'bitsadmin', 'msiexec', 'bash', 'curl', 'wget',
            'installutil', 'regasm', 'msbuild', 'cmstp',
        ]

        self.suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\downloads\\',
            '\\perflogs\\', '\\programdata\\',
            '\\recycler\\', '\\$recycle.bin\\',
        ]

        self.suspicious_args = [
            '-enc ', '-encodedcommand', '-nop', '-noprofile',
            '-windowstyle hidden', '-w hidden', '-ep bypass',
            '-executionpolicy bypass', 'base64', 'invoke-expression',
            'iex ', 'downloadstring', 'downloadfile', 'net.webclient',
            'start-process', 'new-object', 'io.memorystream',
            'frombase64string', 'http://', 'https://',
        ]

    def scan(self):
        results = []
        results.extend(self._scan_tasks())
        results.extend(self._scan_wmi())
        return results

    # ==========================================================
    # タスクスケジューラ解析
    # ==========================================================
    def _scan_tasks(self):
        task_list = []
        if not os.path.exists(self.tasks_dir):
            task_list.append({
                "type": "タスクスケジューラ",
                "name": "Tasks フォルダ不在",
                "command": "",
                "status": "WARNING",
                "reason": "タスクフォルダが存在しない",
                "desc": build_tutor_desc(
                    detection=(
                        "C:\\Windows\\System32\\Tasks フォルダが存在しません。"
                    ),
                    why_dangerous=(
                        "タスクスケジューラのXMLファイルが格納されるフォルダです。"
                        "攻撃者が証拠隠滅のためにフォルダ内容を削除した可能性、"
                        "またはアクセス権限の問題で読み取れない可能性があります。"
                    ),
                    normal_vs_abnormal=(
                        "【正常】通常このフォルダは必ず存在します。\n"
                        "【異常】フォルダが存在しないこと自体が異常です。\n"
                        "【判断基準】管理者権限で再実行し、それでもない場合は調査必要。"
                    ),
                    next_steps=[
                        "schtasks /query でタスク一覧を取得しレジストリベースのタスクを確認する",
                        "イベントログ(Security:4698/4699)でタスク作成/削除の履歴を確認する",
                    ],
                    status="WARNING",
                ),
            })
            return task_list

        for root_dir, dirs, files in os.walk(self.tasks_dir):
            for filename in files:
                filepath = os.path.join(root_dir, filename)
                try:
                    tree = ET.parse(filepath)
                    root = tree.getroot()

                    actions = []
                    for elem in root.iter():
                        if 'Command' in elem.tag and elem.text:
                            actions.append(elem.text.strip())
                        if 'Arguments' in elem.tag and elem.text:
                            if actions:
                                actions[-1] += f" {elem.text.strip()}"

                    for cmd in actions:
                        status, reason, desc = self._analyze_task(filename, cmd)
                        task_list.append({
                            "type": "タスクスケジューラ",
                            "name": filename,
                            "command": cmd,
                            "status": status,
                            "reason": reason,
                            "desc": desc,
                        })

                except Exception:
                    continue

        priority = {"DANGER": 0, "WARNING": 1, "SAFE": 2, "INFO": 3}
        task_list.sort(key=lambda x: (priority.get(x["status"], 9), x["name"]))
        return task_list

    def _analyze_task(self, task_name, command):
        """タスクスケジューラエントリの危険度判定"""
        cmd_lower = command.lower()
        name_lower = task_name.lower()

        # --- Rule 1: 攻撃ツールの自動実行 ---
        cmd_basename = (os.path.basename(cmd_lower.split()[0])
                        if cmd_lower.strip() else '')
        for tool in self.attack_tools:
            tool_base = tool.replace('.exe', '')
            if (cmd_basename == tool or cmd_basename == tool_base
                    or cmd_basename == tool_base + '.exe'
                    or f'\\{tool}' in cmd_lower
                    or f'\\{tool_base}.exe' in cmd_lower
                    or f'/{tool}' in cmd_lower
                    or f'/{tool_base}.exe' in cmd_lower):
                return (
                    "DANGER",
                    f"攻撃ツールの自動実行: {tool}",
                    build_tutor_desc(
                        detection=(
                            f"タスクスケジューラに攻撃ツール「{tool}」が登録されています。\n"
                            f"タスク名: {task_name}\n"
                            f"コマンド: {command}"
                        ),
                        why_dangerous=(
                            "タスクスケジューラはSYSTEM権限でプログラムを"
                            "定期実行できるため、攻撃者の永続化手法として多用されます。"
                            "攻撃ツールがタスクに登録されている場合、"
                            "侵害が進行中であり、定期的に悪意のある操作が実行されています。"
                        ),
                        mitre_key="pers_scheduled_task",
                        normal_vs_abnormal=(
                            "【正常】攻撃ツールがタスクに登録されることは"
                            "いかなる場合も正常ではありません。\n"
                            "【異常】100%異常です。即座に対応が必要です。\n"
                            "【判断基準】攻撃ツールの自動実行は誤検知の可能性が極めて低い。"
                        ),
                        next_steps=[
                            f"タスクの作成日時を確認する（schtasks /query /tn \"{task_name}\" /fo LIST /v）",
                            "コマンドのファイルパスを確認しハッシュ値を取得する",
                            "イベントログ(Security:4698)でタスク作成者を特定する",
                            "同時刻帯に作成された他のタスクがないか確認する",
                        ],
                        status="DANGER",
                    ),
                )

        # --- Rule 2: LOLBin + 不審な引数 ---
        found_lolbin = None
        for lolbin in self.lolbins:
            if lolbin in cmd_lower:
                found_lolbin = lolbin
                break

        if found_lolbin:
            found_args = [a for a in self.suspicious_args if a in cmd_lower]

            if found_args:
                args_str = ', '.join(found_args[:3])
                return (
                    "DANGER",
                    f"LOLBin+不審引数: {found_lolbin} ({args_str})",
                    build_tutor_desc(
                        detection=(
                            f"タスクスケジューラにLOLBin「{found_lolbin}」が"
                            f"不審な引数付きで登録されています。\n"
                            f"タスク名: {task_name}\n"
                            f"コマンド: {command}\n"
                            f"検知引数: {args_str}"
                        ),
                        why_dangerous=(
                            "Windows標準ツール（LOLBin）にBase64エンコード、"
                            "非表示実行、ダウンロードコマンド等の不審な引数が"
                            "組み合わされている場合、ファイルレス攻撃による"
                            "永続化の可能性が非常に高いです。"
                            "特に「-enc」「-windowstyle hidden」「downloadstring」は"
                            "攻撃の典型的なパターンです。"
                        ),
                        mitre_key="pers_scheduled_task",
                        normal_vs_abnormal=(
                            "【正常】一部の管理スクリプトが-noprofile等を使用しますが、"
                            "Base64やdownloadstringとの組み合わせは稀。\n"
                            "【異常】-enc + downloadstring等は"
                            "ほぼ確実にファイルレス攻撃の永続化。\n"
                            "【判断基準】Base64部分をデコードして内容を確認。"
                        ),
                        next_steps=[
                            "Base64部分をデコードして実際のコマンドを確認する",
                            "URL/IPが含まれていればC2サーバーの可能性を調査する",
                            "タスクの実行履歴（前回実行時刻）を確認する",
                            "同一の手法が他のPCにも展開されていないか確認する",
                        ],
                        status="DANGER",
                    ),
                )

            # LOLBin + 不審パス
            found_path = None
            for susp_path in self.suspicious_paths:
                if susp_path in cmd_lower:
                    found_path = susp_path
                    break

            if found_path:
                return (
                    "DANGER",
                    f"LOLBin+不審パス: {found_lolbin} ({found_path.strip(chr(92))})",
                    build_tutor_desc(
                        detection=(
                            f"LOLBin「{found_lolbin}」が不審なフォルダから"
                            f"自動実行されるよう登録されています。\n"
                            f"タスク名: {task_name}\n"
                            f"コマンド: {command}"
                        ),
                        why_dangerous=(
                            f"「{found_path.strip(chr(92))}」はユーザー権限で"
                            "書き込めるフォルダです。正規のタスク設定では"
                            "通常これらのパスからスクリプトエンジンを"
                            "呼び出すことはありません。攻撃者がマルウェアの"
                            "スクリプトを配置しLOLBinで定期実行している可能性があります。"
                        ),
                        mitre_key="pers_scheduled_task",
                        normal_vs_abnormal=(
                            "【正常】一時的なインストーラーがTempを使うことはあるが、"
                            "永続タスクとしては異常。\n"
                            "【異常】Temp/Public/ProgramDataからLOLBin起動は高リスク。\n"
                            "【判断基準】指定パスのファイルが正規ソフトウェアか確認。"
                        ),
                        next_steps=[
                            "指定パスのファイルがまだ存在するか確認する",
                            "存在する場合ファイル内容を確認する",
                            "タスクの作成日時と作成者を確認する",
                            "Zone.Identifier(ADS)でファイルの出所を確認する",
                        ],
                        status="DANGER",
                    ),
                )

            # LOLBinのみ
            return (
                "WARNING",
                f"LOLBin自動実行: {found_lolbin}",
                build_tutor_desc(
                    detection=(
                        f"タスクスケジューラにLOLBin「{found_lolbin}」が登録されています。\n"
                        f"タスク名: {task_name}\n"
                        f"コマンド: {command}"
                    ),
                    why_dangerous=(
                        "LOLBin（Living-off-the-Land Binary）はWindows標準ツールですが、"
                        "攻撃者がタスクスケジューラと組み合わせて悪用するケースがあります。"
                        "正規のシステム管理タスクで使用されることも多いため、"
                        "コマンドの内容と実行頻度の確認が必要です。"
                    ),
                    normal_vs_abnormal=(
                        "【正常】Windows Updateやシステムメンテナンスの管理タスク。"
                        "OS初期セットアップ時に自動作成されたタスク。\n"
                        "【異常】後から追加された不明なLOLBinタスク。\n"
                        "【判断基準】タスクの作成日時がOSインストール時か後追加か。"
                    ),
                    next_steps=[
                        "コマンドライン引数の全文を確認し正規の管理作業か判断する",
                        "タスクの作成日時がOS初期セットアップ時か確認する",
                        "不明なタスクは管理者に正当性を確認する",
                    ],
                    status="WARNING",
                ),
            )

        # --- Rule 3: 不審パスからの実行 ---
        for susp_path in self.suspicious_paths:
            if susp_path in cmd_lower:
                return (
                    "WARNING",
                    f"不審パスからの自動実行: {susp_path.strip(chr(92))}",
                    build_tutor_desc(
                        detection=(
                            f"不審なフォルダからプログラムが自動実行されるよう"
                            f"タスクスケジューラに登録されています。\n"
                            f"タスク名: {task_name}\n"
                            f"コマンド: {command}"
                        ),
                        why_dangerous=(
                            f"「{susp_path.strip(chr(92))}」等のユーザー書き込み可能"
                            "フォルダから自動実行されるプログラムは、"
                            "攻撃者がマルウェアを配置した可能性があります。"
                        ),
                        normal_vs_abnormal=(
                            "【正常】一時的なソフトウェアアップデータ。\n"
                            "【異常】恒久的なタスクにTemp/Publicパスが登録。\n"
                            "【判断基準】ファイルの署名と作成時期を確認。"
                        ),
                        next_steps=[
                            "指定パスのファイルが存在するか確認する",
                            "ファイルのデジタル署名を確認する",
                            "タスクの作成日時を確認する",
                        ],
                        status="WARNING",
                    ),
                )

        # --- Rule 4: 正常 ---
        return (
            "SAFE", "",
            build_tutor_desc(
                detection=(
                    f"タスクスケジューラに登録された自動実行エントリです。\n"
                    f"タスク名: {task_name}\n"
                    f"コマンド: {command}"
                ),
                why_dangerous="",
                normal_vs_abnormal=(
                    "コマンド内容に明らかな不審点は検出されませんでした。"
                    "正規のシステムタスクまたはソフトウェアのメンテナンスタスクと判断されます。"
                ),
                status="SAFE",
            ),
        )

    # ==========================================================
    # WMI イベントサブスクリプション解析
    # ==========================================================
    def _scan_wmi(self):
        wmi_list = []
        ps_cmd = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Get-WmiObject -Namespace root/subscription "
            "-Class CommandLineEventConsumer -ErrorAction SilentlyContinue | "
            "Select-Object Name, CommandLineTemplate | "
            "ConvertTo-Json -Compress"
        )

        try:
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                text=True, encoding='utf-8', errors='replace',
                creationflags=0x08000000, stderr=subprocess.DEVNULL,
            )

            if not output.strip():
                return wmi_list

            import json
            try:
                data = json.loads(output)
            except Exception:
                return wmi_list

            if isinstance(data, dict):
                data = [data]

            for entry in data:
                wmi_name = entry.get('Name', 'Unknown')
                wmi_cmd = entry.get('CommandLineTemplate', '')
                status, reason, desc = self._analyze_wmi(wmi_name, wmi_cmd)
                wmi_list.append({
                    "type": "WMI イベント監視",
                    "name": wmi_name,
                    "command": wmi_cmd,
                    "status": status,
                    "reason": reason,
                    "desc": desc,
                })
        except Exception:
            pass

        return wmi_list

    def _analyze_wmi(self, wmi_name, wmi_cmd):
        """WMIイベントサブスクリプションの危険度判定"""
        cmd_lower = wmi_cmd.lower()

        # 攻撃ツール検知
        for tool in self.attack_tools:
            tool_base = tool.replace('.exe', '')
            if (f'\\{tool}' in cmd_lower
                    or f'\\{tool_base}.exe' in cmd_lower
                    or f'/{tool}' in cmd_lower
                    or cmd_lower.startswith(tool)
                    or f' {tool}' in cmd_lower):
                return (
                    "DANGER",
                    f"WMI永続化+攻撃ツール: {tool}",
                    build_tutor_desc(
                        detection=(
                            f"WMIイベントサブスクリプションに攻撃ツール「{tool}」が"
                            f"登録されています。\n"
                            f"サブスクリプション名: {wmi_name}\n"
                            f"コマンド: {wmi_cmd}"
                        ),
                        why_dangerous=(
                            "WMIイベントサブスクリプションはファイルシステムに痕跡を残さず、"
                            "レジストリやWMIリポジトリ内にのみ存在する高度な永続化手法です。"
                            "セキュリティソフトの検知を回避しやすく、"
                            "APT攻撃グループが頻繁に使用します。"
                            "攻撃ツールと組み合わされている場合、侵害は深刻な段階にあります。"
                        ),
                        mitre_key="pers_wmi",
                        normal_vs_abnormal=(
                            "【正常】WMI + 攻撃ツールの組み合わせは"
                            "いかなる場合も正常ではありません。\n"
                            "【異常】100%異常。APTレベルの高度な攻撃。\n"
                            "【判断基準】即座にインシデント対応を開始すべき。"
                        ),
                        next_steps=[
                            "WMIサブスクリプションの全構成（Filter/Consumer/Binding）を確認する",
                            "Get-WmiObject -Namespace root/subscription -Class __EventFilter でトリガー条件を確認する",
                            "即座にサブスクリプションを無効化・削除する",
                            "同一手法が他のPCに展開されていないか調査する",
                        ],
                        status="DANGER",
                    ),
                )

        # 一般的なWMIサブスクリプション
        return (
            "DANGER",
            "WMIイベントサブスクリプション検知",
            build_tutor_desc(
                detection=(
                    f"WMIイベントサブスクリプション（永続化メカニズム）が検出されました。\n"
                    f"サブスクリプション名: {wmi_name}\n"
                    f"コマンド: {wmi_cmd}"
                ),
                why_dangerous=(
                    "WMIイベントサブスクリプションは特定の条件（OS起動、"
                    "ユーザーログオン、時間経過等）をトリガーとして"
                    "コマンドを自動実行する仕組みです。"
                    "正規のソフトウェアが使用するケースもありますが、"
                    "攻撃者が永続化に悪用するケースが非常に多く、"
                    "検知が難しいことから高度な攻撃で頻繁に使用されます。"
                ),
                mitre_key="pers_wmi",
                normal_vs_abnormal=(
                    "【正常】一部の正規ソフトウェア（SCCM等）がWMIサブスクリプションを使用。\n"
                    "【異常】不明なサブスクリプション名、"
                    "PowerShell/cmd/スクリプトを実行するもの。\n"
                    "【判断基準】サブスクリプション名とコマンドが"
                    "既知のソフトウェアに関連するか確認。"
                ),
                next_steps=[
                    "サブスクリプション名とコマンドが正規のソフトウェアに関連するか確認する",
                    "EventFilter（トリガー条件）を確認する",
                    "実行されるコマンドのファイルパスと内容を確認する",
                    "不明なサブスクリプションは削除を検討する",
                ],
                status="DANGER",
            ),
        )
