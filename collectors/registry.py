# -*- coding: utf-8 -*-
# collectors/registry.py - P35: 永続化レジストリ網羅チェック（30+箇所対応）
import winreg
import os
from utils.tutor_template import build_tutor_desc


class RegistryCollector:
    """レジストリ永続化メカニズム網羅解析
    カテゴリA: ログオン/スタートアップ (Run, RunOnce, Policies, Winlogon, ActiveSetup, BootExecute)
    カテゴリB: サービス登録 (Services) — Emotet, TrickBot等が多用
    カテゴリC: DLLインジェクション (AppInit, PrintMonitors, LSA, IFEO, NetworkProvider)
    カテゴリD: COM/シェル拡張 (BHO, ShellExtensions, ShellIconOverlay)
    カテゴリE: Office/アプリケーション (Office test, VBAWarnings)
    """

    def __init__(self):
        # ===== カテゴリA: 自動起動キー =====
        self.autorun_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            # グループポリシー経由
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            # RunServices (レガシーだが一部マルウェアが使用)
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
        ]

        # ===== 共通検知リスト =====
        self.attack_tools = [
            'mimikatz', 'psexec', 'cobalt', 'beacon', 'rubeus',
            'sharphound', 'bloodhound', 'lazagne', 'sliver',
            'chisel', 'ligolo', 'ngrok', 'netcat', 'nmap',
            'rclone', 'megasync', 'procdump', 'covenant',
            'empire', 'meterpreter', 'havoc', 'bruteratel',
            'sharpwmi', 'seatbelt', 'certify', 'whisker',
        ]

        self.lolbins = [
            'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
            'mshta', 'rundll32', 'regsvr32', 'certutil',
            'bitsadmin', 'msiexec', 'bash', 'installutil',
            'regasm', 'msbuild', 'cmstp', 'wmic', 'forfiles',
            'pcalua', 'explorer.exe /root',
        ]

        self.suspicious_args = [
            '-enc ', '-encodedcommand', '-nop', '-noprofile',
            '-windowstyle hidden', '-w hidden', '-ep bypass',
            '-executionpolicy bypass', 'base64', 'invoke-expression',
            'iex ', 'downloadstring', 'downloadfile', 'net.webclient',
            'http://', 'https://', 'frombase64string',
            'start-process', 'new-object', 'io.memorystream',
        ]

        self.suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\downloads\\',
            '\\perflogs\\', '\\programdata\\',
            '\\recycler\\', '\\$recycle.bin\\',
            '\\appdata\\roaming\\', '\\appdata\\local\\',
        ]

        # ===== Winlogon 期待値 =====
        self.winlogon_expected = {
            'shell': 'explorer.exe',
            'userinit': r'c:\windows\system32\userinit.exe,',
        }

        # ===== サービス解析用キャッシュ =====
        self._sig_cache = {}

    # ==============================================================
    # メインスキャン
    # ==============================================================
    def scan(self):
        results = []
        results.extend(self._scan_autorun())        # カテゴリA: Run/RunOnce等
        results.extend(self._scan_winlogon())        # カテゴリA: Winlogon Shell/Userinit
        results.extend(self._scan_active_setup())    # カテゴリA: Active Setup
        results.extend(self._scan_boot_execute())    # カテゴリA: BootExecute
        results.extend(self._scan_services())        # カテゴリB: Services ★Emotet
        results.extend(self._scan_ifeo())            # カテゴリC: IFEO Debugger
        results.extend(self._scan_appinit_dlls())    # カテゴリC: AppInit_DLLs
        results.extend(self._scan_print_monitors())  # カテゴリC: Print Monitors
        results.extend(self._scan_lsa())             # カテゴリC: LSA Packages
        results.extend(self._scan_network_provider())  # カテゴリC: NetworkProvider
        results.extend(self._scan_bho())             # カテゴリD: BHO
        results.extend(self._scan_shell_extensions()) # カテゴリD: Shell Extensions
        results.extend(self._scan_office())          # カテゴリE: Office

        priority = {"DANGER": 0, "WARNING": 1, "SAFE": 2, "INFO": 3}
        results.sort(key=lambda x: (priority.get(x.get("status", "INFO"), 9),
                                     x.get("entry", "")))
        return results

    # ==============================================================
    # カテゴリA: Run/RunOnce/Policies (既存拡張)
    # ==============================================================
    def _scan_autorun(self):
        results = []
        for hive, subkey in self.autorun_keys:
            results.extend(self._read_autorun_key(hive, subkey))
        return results

    def _read_autorun_key(self, hive, subkey):
        entries = []
        try:
            with winreg.OpenKey(hive, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        value_str = str(value)
                        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                        location = f"{hive_name}\\{subkey}"
                        status, reason, desc = self._analyze_autorun(
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

    def _analyze_autorun(self, entry_name, value, location):
        val_lower = value.lower()
        name_lower = entry_name.lower()

        # Rule 1: 攻撃ツール
        for tool in self.attack_tools:
            tb = tool.replace('.exe', '')
            if (f'\\{tool}' in val_lower or f'\\{tb}.exe' in val_lower
                    or f'/{tool}' in val_lower or val_lower.startswith(tool)
                    or tool in name_lower):
                return ("DANGER", f"攻撃ツール検知: {tool}",
                    build_tutor_desc(
                        detection=f"レジストリ自動起動キーに攻撃ツール「{tool}」が登録されています。\n場所: {location}\nエントリ名: {entry_name}\n値: {value}",
                        why_dangerous="レジストリの自動起動キーは、ユーザーログオン時に自動的にプログラムを実行する最も基本的な永続化手法です。攻撃ツールが登録されている場合、OS起動のたびに悪意のあるプログラムが自動実行されています。",
                        mitre_key="reg_attack_tool",
                        normal_vs_abnormal="【正常】攻撃ツールがRunキーに登録されることはいかなる場合も正常ではありません。\n【異常】100%異常です。即座に対応が必要です。",
                        next_steps=["該当レジストリエントリを即座に削除する","値に記載されたファイルパスのEXEを確保する","ファイルのハッシュ値をVirusTotalで検索する","同時刻帯に他の自動起動エントリが追加されていないか確認する"],
                        status="DANGER"))

        # Rule 2: LOLBin + 不審引数
        found_lolbin = None
        for lb in self.lolbins:
            if lb.replace('.exe', '') in val_lower:
                found_lolbin = lb
                break

        if found_lolbin:
            found_args = [a for a in self.suspicious_args if a in val_lower]
            if found_args:
                args_str = ', '.join(found_args[:3])
                return ("DANGER", f"LOLBin+不審引数: {found_lolbin} ({args_str})",
                    build_tutor_desc(
                        detection=f"レジストリ自動起動キーにLOLBin「{found_lolbin}」が不審な引数付きで登録されています。\n場所: {location}\nエントリ名: {entry_name}\n値: {value}\n検知引数: {args_str}",
                        why_dangerous="Windows標準ツールにBase64エンコード、非表示実行、ダウンロードコマンド等の不審な引数が組み合わされている場合、ファイルレス攻撃による永続化の可能性が非常に高いです。",
                        mitre_key="reg_lolbin_args",
                        normal_vs_abnormal="【正常】管理スクリプトで-noprofileを使用する場合はあるが、Runキーとの組み合わせは稀。\n【異常】-enc、downloadstring、iex等はほぼ確実に攻撃。",
                        next_steps=["Base64部分をデコードして実際のコマンドを確認する","URL/IPが含まれていればC2サーバーの可能性を調査する","該当レジストリエントリを即座に削除する"],
                        status="DANGER"))

            # LOLBin + 不審パス
            found_path = next((p for p in self.suspicious_paths if p in val_lower), None)
            if found_path:
                return ("DANGER", f"LOLBin+不審パス: {found_lolbin} ({found_path.strip(chr(92))})",
                    build_tutor_desc(
                        detection=f"LOLBin「{found_lolbin}」が不審なフォルダから自動起動されるよう登録されています。\n場所: {location}\nエントリ名: {entry_name}\n値: {value}",
                        why_dangerous=f"「{found_path.strip(chr(92))}」はユーザー権限で書き込めるフォルダです。正規の自動起動設定では通常これらのパスからスクリプトエンジンを呼び出しません。",
                        mitre_key="reg_lolbin_path",
                        normal_vs_abnormal="【正常】一部のインストーラーがTempを使用することがあるが、永続的なRunキー登録は通常しない。\n【異常】Temp/Public/ProgramDataからLOLBin起動は高リスク。",
                        next_steps=["指定パスのファイルが存在するか確認する","ファイル内容とデジタル署名を確認する","該当レジストリエントリの削除を検討する"],
                        status="DANGER"))

            # LOLBinのみ
            return ("WARNING", f"LOLBin自動起動: {found_lolbin}",
                build_tutor_desc(
                    detection=f"レジストリ自動起動キーにLOLBin「{found_lolbin}」が登録されています。\n場所: {location}\nエントリ名: {entry_name}\n値: {value}",
                    why_dangerous="LOLBinはWindows標準ツールですが、攻撃者がRunキーと組み合わせて悪用するケースがあります。コマンドの内容確認が必要です。",
                    normal_vs_abnormal="【正常】企業配布のログオンスクリプト、正規ソフトのrundll32呼び出し等。\n【異常】不明なエントリ名、見覚えのないコマンド引数。",
                    next_steps=["コマンドライン引数の全文を確認する","エントリ名から正規のソフトウェアか判断する"],
                    status="WARNING"))

        # Rule 3: 不審パス
        for sp in self.suspicious_paths:
            if sp in val_lower:
                return ("WARNING", f"不審パスからの自動起動: {sp.strip(chr(92))}",
                    build_tutor_desc(
                        detection=f"不審なフォルダからプログラムが自動起動されるようレジストリに登録されています。\n場所: {location}\nエントリ名: {entry_name}\n値: {value}",
                        why_dangerous=f"「{sp.strip(chr(92))}」等のユーザー書き込み可能フォルダから自動起動されるプログラムは、攻撃者がマルウェアを配置した可能性があります。",
                        normal_vs_abnormal="【正常】一時的なソフトウェアアップデータ。\n【異常】恒久的なRunキーにTemp/Publicパスが登録。",
                        next_steps=["指定パスのファイルが存在するか確認する","ファイルのデジタル署名を確認する","ハッシュ値をVirusTotalで検索する"],
                        status="WARNING"))

        # Rule 4: 正常
        return ("SAFE", "",
            build_tutor_desc(
                detection=f"レジストリ自動起動キーに登録されたエントリです。\n場所: {location}\nエントリ名: {entry_name}\n値: {value}",
                why_dangerous="",
                normal_vs_abnormal="コマンド内容に明らかな不審点は検出されませんでした。正規のソフトウェアによる自動起動設定と判断されます。",
                status="SAFE"))

    # ==============================================================
    # カテゴリA: Winlogon Shell / Userinit / Notify
    # ==============================================================
    def _scan_winlogon(self):
        results = []
        subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                for vname in ['Shell', 'Userinit', 'Notify']:
                    try:
                        value, _ = winreg.QueryValueEx(key, vname)
                        value_str = str(value).strip()
                        status, reason, desc = self._analyze_winlogon(vname, value_str)
                        results.append({
                            "location": f"HKLM\\{subkey}",
                            "entry": vname,
                            "value": value_str,
                            "status": status,
                            "reason": reason,
                            "desc": desc,
                        })
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    def _analyze_winlogon(self, vname, value):
        vname_lower = vname.lower()
        val_lower = value.lower().strip()
        location = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        if vname_lower == 'shell':
            # 正常: "explorer.exe" のみ
            if val_lower == 'explorer.exe':
                return ("SAFE", "",
                    build_tutor_desc(
                        detection=f"Winlogon Shellの値は正常です（explorer.exe）。\n場所: {location}\\Shell\n値: {value}",
                        why_dangerous="",
                        normal_vs_abnormal="Winlogon Shellが標準のexplorer.exeに設定されており、正常です。",
                        status="SAFE"))
            else:
                return ("DANGER", f"Winlogon Shell改変: {value}",
                    build_tutor_desc(
                        detection=f"Winlogon Shellの値がexplorer.exe以外に変更されています。\n場所: {location}\\Shell\n値: {value}",
                        why_dangerous="Winlogon Shellはユーザーログオン後に起動されるシェルプログラムを指定します。通常は「explorer.exe」のみです。この値が変更されている場合、ログオン時にマルウェアが自動起動します。Emotet, TrickBot, ランサムウェア等が改変に使用します。explorer.exeが含まれていても、カンマやスペースで区切って追加プログラムが指定されている場合は危険です。",
                        mitre_key="reg_winlogon",
                        normal_vs_abnormal="【正常】値が「explorer.exe」のみ。\n【異常】explorer.exe以外のプログラムが含まれている。カンマ区切りで複数プログラムが指定されている。\n【判断基準】explorer.exe以外の全てのパスを確認する。",
                        next_steps=["値をexplorer.exeのみに修正する","追加されたプログラムのパスを確認しファイルを確保する","ファイルのハッシュ値をVirusTotalで検索する","イベントログでレジストリ変更履歴を確認する"],
                        status="DANGER"))

        elif vname_lower == 'userinit':
            expected = r'c:\windows\system32\userinit.exe,'
            if val_lower.replace(' ', '') == expected.replace(' ', '') or val_lower.replace(' ', '') == expected.rstrip(',').replace(' ', ''):
                return ("SAFE", "",
                    build_tutor_desc(
                        detection=f"Winlogon Userinitの値は正常です。\n場所: {location}\\Userinit\n値: {value}",
                        why_dangerous="",
                        normal_vs_abnormal="Userinitが標準のuserinit.exeに設定されており、正常です。",
                        status="SAFE"))
            else:
                return ("DANGER", f"Winlogon Userinit改変: {value}",
                    build_tutor_desc(
                        detection=f"Winlogon Userinitにuserinit.exe以外のプログラムが追加されています。\n場所: {location}\\Userinit\n値: {value}",
                        why_dangerous="Userinitはログオン後、デスクトップ表示前に実行されるプログラムを指定します。通常は「C:\\Windows\\system32\\userinit.exe,」のみです。攻撃者はカンマ区切りで自分のマルウェアを追加し、ログオンのたびに自動実行させます。",
                        mitre_key="reg_winlogon",
                        normal_vs_abnormal="【正常】userinit.exeのみ。\n【異常】userinit.exe以外のパスが追加されている。",
                        next_steps=["値をuserinit.exeのみに修正する","追加されたプログラムを確認・確保する","ハッシュ値をVirusTotalで検索する"],
                        status="DANGER"))

        elif vname_lower == 'notify':
            if val_lower and val_lower != '0' and val_lower != '':
                return ("WARNING", f"Winlogon Notify DLL: {value}",
                    build_tutor_desc(
                        detection=f"Winlogon NotifyにDLLが指定されています。\n場所: {location}\\Notify\n値: {value}",
                        why_dangerous="Winlogon NotifyはWindows XP時代の永続化手法ですが、一部のマルウェアが今でもこのキーを作成します。正規のソフトウェアが使用することは現在ほぼありません。",
                        normal_vs_abnormal="【正常】現在のWindowsではほぼ使用されない。\n【異常】値が設定されていること自体が異常の可能性。",
                        next_steps=["指定されたDLLファイルを確認する","ファイルのデジタル署名を確認する"],
                        status="WARNING"))

        return ("SAFE", "", build_tutor_desc(
            detection=f"Winlogon {vname}の値を確認しました。\n値: {value}",
            why_dangerous="", normal_vs_abnormal="正常です。", status="SAFE"))

    # ==============================================================
    # カテゴリA: Active Setup
    # ==============================================================
    def _scan_active_setup(self):
        results = []
        subkey = r"SOFTWARE\Microsoft\Active Setup\Installed Components"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as base:
                idx = 0
                while True:
                    try:
                        clsid = winreg.EnumKey(base, idx)
                        idx += 1
                        try:
                            with winreg.OpenKey(base, clsid) as ckey:
                                try:
                                    stub, _ = winreg.QueryValueEx(ckey, "StubPath")
                                    stub_str = str(stub)
                                    if not stub_str.strip():
                                        continue
                                    status, reason, desc = self._analyze_active_setup(clsid, stub_str)
                                    results.append({
                                        "location": f"HKLM\\{subkey}\\{clsid}",
                                        "entry": f"ActiveSetup: {clsid}",
                                        "value": stub_str,
                                        "status": status,
                                        "reason": reason,
                                        "desc": desc,
                                    })
                                except OSError:
                                    continue
                        except OSError:
                            continue
                    except OSError:
                        break
        except OSError:
            pass
        return results

    def _analyze_active_setup(self, clsid, stub_path):
        val_lower = stub_path.lower()
        location = f"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{clsid}"

        for tool in self.attack_tools:
            if tool in val_lower:
                return ("DANGER", f"ActiveSetup攻撃ツール: {tool}",
                    build_tutor_desc(
                        detection=f"Active SetupのStubPathに攻撃ツール「{tool}」が設定されています。\n場所: {location}\nStubPath: {stub_path}",
                        why_dangerous="Active Setupはユーザーが初回ログオンした際に一度だけ実行されるメカニズムです。攻撃者はここにマルウェアを登録し、新規ユーザーのログオン時に横展開します。",
                        mitre_key="reg_active_setup",
                        normal_vs_abnormal="【正常】Microsoftやブラウザの初期セットアップ。\n【異常】攻撃ツールのパスが含まれている。",
                        next_steps=["該当Active Setupエントリを削除する","StubPathのファイルを確保する"],
                        status="DANGER"))

        for lb in self.lolbins:
            if lb.replace('.exe', '') in val_lower:
                found_args = [a for a in self.suspicious_args if a in val_lower]
                if found_args:
                    return ("DANGER", f"ActiveSetup LOLBin+不審引数: {lb}",
                        build_tutor_desc(
                            detection=f"Active SetupにLOLBin「{lb}」が不審な引数付きで登録されています。\n場所: {location}\nStubPath: {stub_path}",
                            why_dangerous="Active SetupのStubPathにLOLBinと不審な引数が組み合わされています。ユーザーログオン時にファイルレス攻撃が実行される可能性があります。",
                            mitre_key="reg_active_setup",
                            normal_vs_abnormal="【正常】Active SetupでLOLBin+不審引数は通常ありえない。\n【異常】ほぼ確実に攻撃。",
                            next_steps=["該当エントリを削除する","引数の内容をデコードして確認する"],
                            status="DANGER"))

        for sp in self.suspicious_paths:
            if sp in val_lower:
                return ("WARNING", f"ActiveSetup不審パス: {stub_path[:60]}",
                    build_tutor_desc(
                        detection=f"Active Setupに不審パスからのプログラムが登録されています。\n場所: {location}\nStubPath: {stub_path}",
                        why_dangerous="不審なフォルダからActive Setupで実行されるプログラムは、マルウェアの可能性があります。",
                        normal_vs_abnormal="【正常】Program Files等の標準パスからの実行。\n【異常】Temp/Public等からの実行。",
                        next_steps=["StubPathのファイルを確認する","デジタル署名を確認する"],
                        status="WARNING"))

        return ("SAFE", "", build_tutor_desc(
            detection=f"Active Setupエントリです。\n場所: {location}\nStubPath: {stub_path}",
            why_dangerous="", normal_vs_abnormal="正常なActive Setupエントリです。", status="SAFE"))

    # ==============================================================
    # カテゴリA: BootExecute
    # ==============================================================
    def _scan_boot_execute(self):
        results = []
        subkey = r"SYSTEM\CurrentControlSet\Control\Session Manager"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                try:
                    value, _ = winreg.QueryValueEx(key, "BootExecute")
                    if isinstance(value, list):
                        entries = value
                    elif isinstance(value, str):
                        entries = [value]
                    else:
                        entries = list(value) if value else []

                    for entry in entries:
                        entry_str = str(entry).strip()
                        if not entry_str:
                            continue
                        if entry_str.lower() == 'autocheck autochk *':
                            results.append({
                                "location": f"HKLM\\{subkey}",
                                "entry": "BootExecute",
                                "value": entry_str,
                                "status": "SAFE",
                                "reason": "",
                                "desc": build_tutor_desc(
                                    detection=f"BootExecuteの値は正常です（autocheck autochk *）。\n場所: HKLM\\{subkey}\\BootExecute\n値: {entry_str}",
                                    why_dangerous="",
                                    normal_vs_abnormal="OS標準のディスクチェックプログラムです。正常です。",
                                    status="SAFE"),
                            })
                        else:
                            results.append({
                                "location": f"HKLM\\{subkey}",
                                "entry": "BootExecute",
                                "value": entry_str,
                                "status": "DANGER",
                                "reason": f"BootExecute異常値: {entry_str[:50]}",
                                "desc": build_tutor_desc(
                                    detection=f"BootExecuteにOS標準以外のプログラムが設定されています。\n場所: HKLM\\{subkey}\\BootExecute\n値: {entry_str}",
                                    why_dangerous="BootExecuteはOSの最初期段階（Windowsカーネル起動直後）で実行されるプログラムを指定します。通常は「autocheck autochk *」のみです。ブートキットやルートキットがここを改変し、OS起動時にマルウェアを最優先で実行します。セーフモードでも実行されるため、非常に危険です。",
                                    mitre_key="reg_boot_execute",
                                    normal_vs_abnormal="【正常】「autocheck autochk *」のみ。\n【異常】それ以外の値が含まれている場合は即座に調査が必要。",
                                    next_steps=["値を「autocheck autochk *」のみに修正する","指定されたプログラムのファイルを確保する","オフラインブート（WinPE等）で調査する"],
                                    status="DANGER"),
                            })
                except OSError:
                    pass
        except OSError:
            pass
        return results

    # ==============================================================
    # カテゴリB: Services ★Emotet/TrickBot対策
    # ==============================================================
    def _scan_services(self):
        results = []
        subkey = r"SYSTEM\CurrentControlSet\Services"
        danger_count = 0
        warn_count = 0
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as base:
                idx = 0
                while True:
                    try:
                        svc_name = winreg.EnumKey(base, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(base, svc_name, 0,
                                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as skey:
                            try:
                                start_val, _ = winreg.QueryValueEx(skey, "Start")
                            except OSError:
                                continue
                            # Start: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
                            if start_val not in (0, 1, 2, 3):
                                continue
                            try:
                                img_path, _ = winreg.QueryValueEx(skey, "ImagePath")
                                img_str = str(img_path).strip()
                            except OSError:
                                continue
                            if not img_str:
                                continue

                            svc_type = 0
                            try:
                                svc_type, _ = winreg.QueryValueEx(skey, "Type")
                            except OSError:
                                pass

                            status, reason, desc = self._analyze_service(
                                svc_name, img_str, start_val, svc_type)

                            if status == "DANGER":
                                danger_count += 1
                            elif status == "WARNING":
                                warn_count += 1

                            # SAFE のサービスは数が多すぎるので除外
                            if status != "SAFE":
                                results.append({
                                    "location": f"HKLM\\{subkey}\\{svc_name}",
                                    "entry": f"サービス: {svc_name}",
                                    "value": img_str,
                                    "status": status,
                                    "reason": reason,
                                    "desc": desc,
                                })
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    def _analyze_service(self, svc_name, image_path, start_val, svc_type):
        val_lower = image_path.lower()
        name_lower = svc_name.lower()
        start_labels = {0: "Boot", 1: "System", 2: "自動", 3: "手動"}
        start_label = start_labels.get(start_val, str(start_val))
        location = f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}"

        # svchost.exe によるサービスは正常なものが多い
        if 'svchost.exe' in val_lower and '-k ' in val_lower:
            # svchost + 標準グループは基本的にSAFE
            return ("SAFE", "", "")

        # Rule 1: 攻撃ツール
        for tool in self.attack_tools:
            tb = tool.replace('.exe', '')
            if (f'\\{tool}' in val_lower or f'\\{tb}.exe' in val_lower
                    or tool in name_lower):
                return ("DANGER", f"サービスに攻撃ツール: {tool}",
                    build_tutor_desc(
                        detection=f"Windowsサービスに攻撃ツール「{tool}」が登録されています。\n場所: {location}\nImagePath: {image_path}\n起動種別: {start_label}",
                        why_dangerous="Windowsサービスはバックグラウンドで自動実行され、多くの場合SYSTEM権限で動作します。攻撃ツールがサービスとして登録されている場合、PC起動のたびに最高権限で悪意のあるプログラムが実行されます。Emotet, TrickBot, Ryukランサムウェア等はサービス登録を多用します。",
                        mitre_key="reg_service",
                        normal_vs_abnormal="【正常】攻撃ツールがサービスに登録されることは正常ではありません。\n【異常】100%異常。即座にインシデント対応が必要。",
                        next_steps=["sc stop でサービスを停止する","sc delete でサービスを削除する","ImagePathのファイルを確保しハッシュ値を取得する","イベントログ(System:7045)でサービス作成日時と作成者を確認する"],
                        status="DANGER"))

        # Rule 2: LOLBin経由サービス
        for lb in self.lolbins:
            if lb.replace('.exe', '') in val_lower:
                found_args = [a for a in self.suspicious_args if a in val_lower]
                if found_args:
                    return ("DANGER", f"サービスLOLBin+不審引数: {lb}",
                        build_tutor_desc(
                            detection=f"サービスのImagePathにLOLBin「{lb}」が不審な引数付きで設定されています。\n場所: {location}\nImagePath: {image_path}\n起動種別: {start_label}",
                            why_dangerous="LOLBin経由でスクリプトやダウンロードコマンドを実行するサービスは、ファイルレスマルウェアの典型的な永続化手法です。SYSTEM権限で実行されるため影響は甚大です。",
                            mitre_key="reg_service",
                            normal_vs_abnormal="【正常】LOLBin+不審引数がサービスに登録されることは通常ありえません。\n【異常】ほぼ確実に攻撃。",
                            next_steps=["サービスを停止・削除する","引数をデコードして実際のコマンドを確認する","イベントログ(System:7045)でサービス作成履歴を確認する"],
                            status="DANGER"))

        # Rule 3: 不審パスからのサービス
        for sp in self.suspicious_paths:
            if sp in val_lower:
                return ("DANGER", f"サービス不審パス: {sp.strip(chr(92))}",
                    build_tutor_desc(
                        detection=f"サービスのImagePathが不審なフォルダを指しています。\n場所: {location}\nサービス名: {svc_name}\nImagePath: {image_path}\n起動種別: {start_label}",
                        why_dangerous=f"「{sp.strip(chr(92))}」はユーザー権限で書き込めるフォルダです。正規のWindowsサービスはSystem32やProgram Files配下に存在するのが標準です。Emotetは%ProgramData%やTemp配下にランダム名のEXEを配置し、サービスとして登録することで永続化します。",
                        mitre_key="reg_service",
                        normal_vs_abnormal="【正常】正規のサービスはSystem32やProgram Files配下。\n【異常】Temp/ProgramData/Public/AppData配下のサービスは非常に危険。\n【判断基準】ファイルの署名と作成時期を確認。",
                        next_steps=["ImagePathのファイルが存在するか確認する","ファイルのデジタル署名を確認する","ハッシュ値をVirusTotalで検索する","サービスの作成日時をイベントログ(7045)で確認する"],
                        status="DANGER"))

        # Rule 4: 実体ファイルが存在しないサービス
        exe_path = self._extract_exe_path(image_path)
        if exe_path and not os.path.exists(exe_path):
            # ドライバ(Type 1,2)はシステムファイルなので除外
            if svc_type not in (1, 2):
                return ("WARNING", f"サービス実体不在: {svc_name}",
                    build_tutor_desc(
                        detection=f"サービスのImagePathが指すファイルが存在しません。\n場所: {location}\nサービス名: {svc_name}\nImagePath: {image_path}\n起動種別: {start_label}",
                        why_dangerous="サービスの実体ファイルが見つかりません。マルウェアが削除された残骸、またはファイルが移動/隠蔽されている可能性があります。アンチウイルスがマルウェア本体を削除したが、サービスのレジストリエントリが残っているケースが多いです。",
                        normal_vs_abnormal="【正常】ソフトウェアのアンインストール後に残ったエントリ。\n【異常】マルウェアの残骸の可能性。",
                        next_steps=["sc delete でサービスエントリを削除する","イベントログでサービス関連のエラーを確認する","同名のファイルが他の場所にないか検索する"],
                        status="WARNING"))

        # Rule 5: 非標準パスのサービス（System32/Program Files以外）
        if exe_path:
            exe_lower = exe_path.lower()
            standard_paths = [
                r'c:\windows', r'c:\program files', r'c:\program files (x86)',
                r'c:\programdata\microsoft',
            ]
            is_standard = any(exe_lower.startswith(sp) for sp in standard_paths)
            if not is_standard and os.path.exists(exe_path):
                return ("WARNING", f"非標準パスのサービス: {svc_name}",
                    build_tutor_desc(
                        detection=f"サービスのImagePathが標準外のフォルダにあります。\n場所: {location}\nサービス名: {svc_name}\nImagePath: {image_path}\n起動種別: {start_label}",
                        why_dangerous="正規のWindowsサービスやメジャーソフトウェアのサービスは、通常C:\\Windows配下またはProgram Files配下にインストールされます。それ以外のパスからサービスが実行されている場合、サードパーティソフトウェアまたはマルウェアの可能性があります。",
                        normal_vs_abnormal="【正常】サードパーティソフトウェア（例: D:\\App\\service.exe）。\n【異常】ランダムな名前のフォルダや一時フォルダからの実行。",
                        next_steps=["ファイルのデジタル署名を確認する","ファイル名とパスが既知のソフトウェアか確認する"],
                        status="WARNING"))

        return ("SAFE", "", "")

    def _extract_exe_path(self, image_path):
        """ImagePathからEXEパスを抽出"""
        path = image_path.strip()
        if path.startswith('"'):
            end = path.find('"', 1)
            if end > 0:
                return path[1:end]
        if path.startswith('\\SystemRoot\\'):
            path = path.replace('\\SystemRoot\\', r'C:\Windows\\', 1)
        if path.startswith('\\??\\'):
            path = path[4:]
        parts = path.split()
        if parts:
            candidate = parts[0]
            if os.path.exists(candidate):
                return candidate
            if candidate.lower().endswith('.exe'):
                return candidate
            # .sys ドライバも
            if candidate.lower().endswith('.sys'):
                return candidate
        return None

    # ==============================================================
    # カテゴリC: IFEO (Image File Execution Options) Debugger
    # ==============================================================
    def _scan_ifeo(self):
        results = []
        subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        # 特にStickyKeys攻撃で狙われるEXE
        critical_targets = [
            'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe',
            'narrator.exe', 'displayswitch.exe', 'atbroker.exe',
        ]
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as base:
                idx = 0
                while True:
                    try:
                        exe_name = winreg.EnumKey(base, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(base, exe_name, 0,
                                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as ekey:
                            try:
                                debugger, _ = winreg.QueryValueEx(ekey, "Debugger")
                                debugger_str = str(debugger).strip()
                                if not debugger_str:
                                    continue
                                is_critical = exe_name.lower() in critical_targets
                                status = "DANGER"
                                reason = f"IFEOデバッガ: {exe_name} → {debugger_str[:60]}"

                                if is_critical:
                                    desc_text = build_tutor_desc(
                                        detection=f"Image File Execution Options (IFEO)で「{exe_name}」にデバッガが設定されています。\n場所: HKLM\\{subkey}\\{exe_name}\nDebugger: {debugger_str}",
                                        why_dangerous=f"IFEOのDebugger値を設定すると、「{exe_name}」を実行しようとした時に代わりにデバッガプログラムが起動します。「{exe_name}」はアクセシビリティ機能で、ログオン画面から起動できます。攻撃者はこれをcmd.exeやマルウェアに差し替え、ログオン画面からSYSTEM権限のシェルを取得します（StickyKeys攻撃/T1546.008）。RDP経由の不正アクセスで頻繁に使用されます。",
                                        mitre_key="reg_ifeo",
                                        normal_vs_abnormal=f"【正常】{exe_name}にDebuggerが設定されることは正常ではありません。\n【異常】100%異常。バックドアの可能性が極めて高い。\n【判断基準】即座にインシデント対応を開始すべき。",
                                        next_steps=["Debugger値を即座に削除する","設定されたプログラムのファイルを確保する","RDPログオン履歴を確認する（イベントログSecurity:4624, Type10）","同一手法が他のアクセシビリティEXEに適用されていないか確認する"],
                                        status="DANGER")
                                else:
                                    desc_text = build_tutor_desc(
                                        detection=f"IFEOで「{exe_name}」にデバッガが設定されています。\n場所: HKLM\\{subkey}\\{exe_name}\nDebugger: {debugger_str}",
                                        why_dangerous="IFEOのDebugger値は、対象EXEの実行を別のプログラムにリダイレクトします。開発者のデバッグ目的で使用されることもありますが、マルウェアが正規プログラムの実行を妨害したり、代わりに自身を起動するために悪用するケースがあります。",
                                        mitre_key="reg_ifeo",
                                        normal_vs_abnormal="【正常】開発者がデバッガを一時的に設定する場合。\n【異常】本番環境でDebuggerが設定されているのは異常。",
                                        next_steps=["Debugger値の正当性を確認する","不明な場合はDebugger値を削除する","設定されたプログラムを確認する"],
                                        status="DANGER")

                                results.append({
                                    "location": f"HKLM\\{subkey}\\{exe_name}",
                                    "entry": f"IFEO: {exe_name}",
                                    "value": debugger_str,
                                    "status": status,
                                    "reason": reason,
                                    "desc": desc_text,
                                })
                            except OSError:
                                continue
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    # ==============================================================
    # カテゴリC: AppInit_DLLs
    # ==============================================================
    def _scan_appinit_dlls(self):
        results = []
        paths = [
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "LoadAppInit_DLLs"),
            (r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "LoadAppInit_DLLs"),
        ]
        for subkey, val_name, load_name in paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    try:
                        value, _ = winreg.QueryValueEx(key, val_name)
                        value_str = str(value).strip()
                        if not value_str:
                            continue
                        # LoadAppInit_DLLs が 0 なら無効
                        load_enabled = 1
                        try:
                            load_val, _ = winreg.QueryValueEx(key, load_name)
                            load_enabled = int(load_val)
                        except (OSError, ValueError):
                            pass

                        if load_enabled == 0:
                            results.append({
                                "location": f"HKLM\\{subkey}",
                                "entry": "AppInit_DLLs (無効)",
                                "value": value_str,
                                "status": "SAFE",
                                "reason": "",
                                "desc": build_tutor_desc(
                                    detection=f"AppInit_DLLsにDLLが設定されていますが、LoadAppInit_DLLsが0で無効化されています。\n場所: HKLM\\{subkey}\n値: {value_str}",
                                    why_dangerous="",
                                    normal_vs_abnormal="AppInit_DLLsは設定されていますが無効です。現時点では影響ありません。",
                                    status="SAFE"),
                            })
                        else:
                            results.append({
                                "location": f"HKLM\\{subkey}",
                                "entry": "AppInit_DLLs",
                                "value": value_str,
                                "status": "DANGER",
                                "reason": f"AppInit_DLLs有効: {value_str[:60]}",
                                "desc": build_tutor_desc(
                                    detection=f"AppInit_DLLsが有効化され、DLLが指定されています。\n場所: HKLM\\{subkey}\n値: {value_str}\nLoadAppInit_DLLs: {load_enabled}",
                                    why_dangerous="AppInit_DLLsに指定されたDLLは、GUIアプリケーション（User32.dllを読み込む全プロセス）に自動的にインジェクションされます。攻撃者はここにマルウェアDLLを登録し、あらゆるGUIプロセスにコードを注入します。キーロガー、バンキングトロイ、情報窃取マルウェア等が使用する手法です。",
                                    mitre_key="reg_appinit",
                                    normal_vs_abnormal="【正常】一部のセキュリティソフトやIMEが使用する場合がある（非常に稀）。\n【異常】AppInit_DLLsが有効で不明なDLLが指定されている場合は高リスク。\n【判断基準】指定されたDLLが既知のセキュリティソフトか確認。",
                                    next_steps=["指定されたDLLファイルを確認する","DLLのデジタル署名を確認する","不明な場合はLoadAppInit_DLLsを0に設定して無効化する","ハッシュ値をVirusTotalで検索する"],
                                    status="DANGER"),
                            })
                    except OSError:
                        continue
            except OSError:
                continue
        return results

    # ==============================================================
    # カテゴリC: Print Monitors
    # ==============================================================
    def _scan_print_monitors(self):
        results = []
        subkey = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
        known_monitors = [
            'appmon.dll', 'localspl.dll', 'tcpmon.dll', 'usbmon.dll',
            'wsdmon.dll', 'apmonui.dll', 'pjlmon.dll', 'lprmon.dll',
            'redmonnt.dll', 'mfilemon.dll',
        ]
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as base:
                idx = 0
                while True:
                    try:
                        mon_name = winreg.EnumKey(base, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(base, mon_name, 0,
                                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as mkey:
                            try:
                                driver, _ = winreg.QueryValueEx(mkey, "Driver")
                                driver_str = str(driver).strip()
                                if not driver_str:
                                    continue
                                if driver_str.lower() in known_monitors:
                                    continue  # 既知の正規モニター → スキップ
                                # 不明なPrint Monitor DLL
                                results.append({
                                    "location": f"HKLM\\{subkey}\\{mon_name}",
                                    "entry": f"PrintMonitor: {mon_name}",
                                    "value": driver_str,
                                    "status": "WARNING",
                                    "reason": f"不明なPrint Monitor DLL: {driver_str}",
                                    "desc": build_tutor_desc(
                                        detection=f"不明なPrint Monitor DLLが登録されています。\n場所: HKLM\\{subkey}\\{mon_name}\nDriver: {driver_str}",
                                        why_dangerous="Print Monitor DLLはSpoolerサービス（SYSTEM権限）によって読み込まれます。APTグループ（Turla等）が永続化にPrint Monitorを悪用するケースが報告されています。正規のプリンタードライバーもここに登録されますが、不明なDLLは調査が必要です。",
                                        mitre_key="reg_print_monitor",
                                        normal_vs_abnormal="【正常】プリンタードライバーの既知DLL。\n【異常】System32以外のパスのDLL、不明な名前のDLL。",
                                        next_steps=["DLLファイルの場所を確認する（通常System32配下）","DLLのデジタル署名を確認する","ハッシュ値をVirusTotalで検索する"],
                                        status="WARNING"),
                                })
                            except OSError:
                                continue
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    # ==============================================================
    # カテゴリC: LSA Authentication/Security Packages
    # ==============================================================
    def _scan_lsa(self):
        results = []
        subkey = r"SYSTEM\CurrentControlSet\Control\Lsa"
        known_packages = [
            'msv1_0', 'kerberos', 'schannel', 'wdigest', 'tspkg',
            'pku2u', 'cloudap', 'negoextender', 'negossp',
            '"', '',  # 空文字やクォートを除外
        ]
        checks = [
            ("Authentication Packages", "LSA認証パッケージ"),
            ("Security Packages", "LSAセキュリティパッケージ"),
        ]
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                for val_name, label in checks:
                    try:
                        value, _ = winreg.QueryValueEx(key, val_name)
                        if isinstance(value, list):
                            packages = value
                        elif isinstance(value, str):
                            packages = [p.strip() for p in value.split('\0') if p.strip()]
                        else:
                            packages = list(value) if value else []

                        for pkg in packages:
                            pkg_str = str(pkg).strip().lower()
                            if not pkg_str or pkg_str in known_packages:
                                continue
                            # mimilib.dll (Mimikatz SSP)
                            is_mimikatz = 'mimilib' in pkg_str or 'memssp' in pkg_str
                            if is_mimikatz:
                                results.append({
                                    "location": f"HKLM\\{subkey}",
                                    "entry": f"{label}: {pkg}",
                                    "value": str(pkg),
                                    "status": "DANGER",
                                    "reason": f"Mimikatz SSP検知: {pkg}",
                                    "desc": build_tutor_desc(
                                        detection=f"LSAパッケージにMimikatzのSSP（{pkg}）が検出されました。\n場所: HKLM\\{subkey}\\{val_name}\n値: {pkg}",
                                        why_dangerous="MimikatzのSSP（Security Support Provider）モジュール「mimilib.dll」は、LSASSプロセスに読み込まれ、全てのログオンパスワードを平文でファイルに記録します。これはクレデンシャルダンプの永続化手法で、APT攻撃で頻繁に使用されます。",
                                        mitre_key="reg_lsa",
                                        normal_vs_abnormal="【正常】mimilib/memsspがLSAパッケージに含まれることは正常ではありません。\n【異常】100%異常。パスワード窃取が進行中。",
                                        next_steps=["即座にLSAパッケージからmimilib/memsspを削除する","kiwi.logやmimilsa.logファイルを確認する","全ユーザーのパスワードを変更する","LSASSメモリダンプでクレデンシャル漏洩を確認する"],
                                        status="DANGER"),
                                })
                            else:
                                results.append({
                                    "location": f"HKLM\\{subkey}",
                                    "entry": f"{label}: {pkg}",
                                    "value": str(pkg),
                                    "status": "WARNING",
                                    "reason": f"不明なLSAパッケージ: {pkg}",
                                    "desc": build_tutor_desc(
                                        detection=f"LSAパッケージに不明なエントリが含まれています。\n場所: HKLM\\{subkey}\\{val_name}\n値: {pkg}",
                                        why_dangerous="LSA認証/セキュリティパッケージはLSASSプロセスに読み込まれるDLLを指定します。攻撃者はここにカスタムDLLを追加し、ログオン認証情報を傍受します。正規のセキュリティソフト（スマートカード認証等）が使用する場合もあります。",
                                        mitre_key="reg_lsa",
                                        normal_vs_abnormal="【正常】既知のパッケージ（msv1_0, kerberos, schannel等）。スマートカード等のセキュリティソフト。\n【異常】不明なパッケージ名。",
                                        next_steps=["パッケージ名に対応するDLLを確認する","DLLのデジタル署名を確認する","不明な場合はセキュリティチームに報告する"],
                                        status="WARNING"),
                                })
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    # ==============================================================
    # カテゴリC: NetworkProvider Order
    # ==============================================================
    def _scan_network_provider(self):
        results = []
        subkey = r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"
        known_providers = [
            'lanmanworkstation', 'rdpnp', 'webclient', 'vmhgfs',
            'p9np', 'sshfs', 'nfsrdr',
        ]
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                try:
                    value, _ = winreg.QueryValueEx(key, "ProviderOrder")
                    providers = [p.strip() for p in str(value).split(',') if p.strip()]
                    for prov in providers:
                        if prov.lower() not in known_providers:
                            results.append({
                                "location": f"HKLM\\{subkey}",
                                "entry": f"NetworkProvider: {prov}",
                                "value": prov,
                                "status": "WARNING",
                                "reason": f"不明なNetworkProvider: {prov}",
                                "desc": build_tutor_desc(
                                    detection=f"不明なNetworkProviderが登録されています。\n場所: HKLM\\{subkey}\\ProviderOrder\n値: {prov}",
                                    why_dangerous="NetworkProviderはネットワーク認証時にDLLが読み込まれる仕組みです。攻撃者はここにカスタムDLLを追加し、ネットワーク認証のクレデンシャル（ユーザー名/パスワード）を傍受します。NPPSpyやNPLogonNotifyを利用した攻撃が知られています。",
                                    mitre_key="reg_network_provider",
                                    normal_vs_abnormal="【正常】LanmanWorkstation, RDPNP等の既知プロバイダー。\n【異常】不明なプロバイダー名。",
                                    next_steps=["プロバイダー名に対応するサービスキーを確認する","該当DLLのデジタル署名を確認する"],
                                    status="WARNING"),
                            })
                except OSError:
                    pass
        except OSError:
            pass
        return results

    # ==============================================================
    # カテゴリD: Browser Helper Objects (BHO)
    # ==============================================================
    def _scan_bho(self):
        results = []
        subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as base:
                idx = 0
                while True:
                    try:
                        clsid = winreg.EnumKey(base, idx)
                        idx += 1
                    except OSError:
                        break
                    # CLSIDからDLLパスを取得
                    dll_path = self._resolve_clsid(clsid)
                    if dll_path:
                        for sp in self.suspicious_paths:
                            if sp in dll_path.lower():
                                results.append({
                                    "location": f"HKLM\\{subkey}\\{clsid}",
                                    "entry": f"BHO: {clsid}",
                                    "value": dll_path,
                                    "status": "DANGER",
                                    "reason": f"BHO不審パス: {dll_path[:60]}",
                                    "desc": build_tutor_desc(
                                        detection=f"Browser Helper Object(BHO)が不審なパスのDLLを参照しています。\n場所: HKLM\\{subkey}\\{clsid}\nDLL: {dll_path}",
                                        why_dangerous="BHOはInternet Explorer/Edgeに読み込まれるDLLプラグインです。バンキングトロイ（Zeus, Emotet等）はBHOとしてDLLを登録し、ブラウザのHTTP通信を傍受・改変してオンラインバンキングの認証情報を窃取します。",
                                        mitre_key="reg_bho",
                                        normal_vs_abnormal="【正常】Adobe, Microsoft等の既知のBHO。\n【異常】Temp/AppData等の不審パスからのDLL。",
                                        next_steps=["DLLファイルのデジタル署名を確認する","BHOエントリを削除する","ハッシュ値をVirusTotalで検索する"],
                                        status="DANGER"),
                                })
                                break
                        else:
                            # 不審パスではないが、BHOが存在すること自体を記録
                            results.append({
                                "location": f"HKLM\\{subkey}\\{clsid}",
                                "entry": f"BHO: {clsid}",
                                "value": dll_path,
                                "status": "SAFE",
                                "reason": "",
                                "desc": build_tutor_desc(
                                    detection=f"BHOが登録されています。\nCLSID: {clsid}\nDLL: {dll_path}",
                                    why_dangerous="",
                                    normal_vs_abnormal="既知の正規BHOと判断されます。",
                                    status="SAFE"),
                            })
        except OSError:
            pass
        return results

    def _resolve_clsid(self, clsid):
        """CLSIDからInprocServer32のDLLパスを取得"""
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,
                                f"CLSID\\{clsid}\\InprocServer32", 0,
                                winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "")
                return str(value).strip()
        except OSError:
            return None

    # ==============================================================
    # カテゴリD: Shell Extensions
    # ==============================================================
    def _scan_shell_extensions(self):
        results = []
        # ShellIconOverlayIdentifiers のチェック
        subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as base:
                idx = 0
                while True:
                    try:
                        name = winreg.EnumKey(base, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(base, name, 0, winreg.KEY_READ) as nkey:
                            value, _ = winreg.QueryValueEx(nkey, "")
                            clsid = str(value).strip()
                            dll_path = self._resolve_clsid(clsid)
                            if dll_path:
                                for sp in self.suspicious_paths:
                                    if sp in dll_path.lower():
                                        results.append({
                                            "location": f"HKLM\\{subkey}\\{name}",
                                            "entry": f"ShellOverlay: {name}",
                                            "value": dll_path,
                                            "status": "WARNING",
                                            "reason": f"不審パスのShellOverlay: {dll_path[:60]}",
                                            "desc": build_tutor_desc(
                                                detection=f"Shell Icon OverlayのDLLが不審なパスにあります。\n場所: HKLM\\{subkey}\\{name}\nCLSID: {clsid}\nDLL: {dll_path}",
                                                why_dangerous="ShellIconOverlayIdentifiersはExplorerプロセスにDLLを読み込ませます。攻撃者はここにマルウェアDLLを登録し、Explorer起動時に自動的にコードを実行します。",
                                                normal_vs_abnormal="【正常】OneDrive, Dropbox等のクラウドストレージ。\n【異常】不明なDLLや不審パスのDLL。",
                                                next_steps=["DLLのデジタル署名を確認する","DLLのハッシュ値をVirusTotalで検索する"],
                                                status="WARNING"),
                                        })
                                        break
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    # ==============================================================
    # カテゴリE: Office永続化
    # ==============================================================
    def _scan_office(self):
        results = []
        # Office Test\Special\Perf (APT29等が使用)
        office_versions = ['16.0', '15.0', '14.0', '12.0']
        for ver in office_versions:
            subkey = "SOFTWARE\\Microsoft\\Office test\\Special\\Perf"
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0,
                                    winreg.KEY_READ) as key:
                    try:
                        value, _ = winreg.QueryValueEx(key, "")
                        value_str = str(value).strip()
                        if value_str:
                            results.append({
                                "location": f"HKCU\\{subkey}",
                                "entry": "Office Test Perf DLL",
                                "value": value_str,
                                "status": "DANGER",
                                "reason": f"Office Test永続化: {value_str[:60]}",
                                "desc": build_tutor_desc(
                                    detection=f"Office Test\\Special\\PerfにDLLが設定されています。\n場所: HKCU\\{subkey}\n値: {value_str}",
                                    why_dangerous="Office Test\\Special\\Perfレジストリキーは、Office アプリケーション（Word, Excel, Outlook等）起動時にDLLを読み込ませる隠れた機能です。APT29（Cozy Bear）等の国家支援グループがこの手法を使用しています。正規のソフトウェアがこのキーを使用することはほぼありません。",
                                    mitre_key="reg_office_test",
                                    normal_vs_abnormal="【正常】このキーが設定されていること自体が異常です。\n【異常】100%異常。APTレベルの攻撃の可能性。",
                                    next_steps=["レジストリキーを即座に削除する","指定されたDLLを確保する","Office起動履歴とDLL読み込みログを確認する","全PCで同じキーが設定されていないか調査する"],
                                    status="DANGER"),
                            })
                    except OSError:
                        continue
            except OSError:
                continue

        # VBAWarnings (マクロセキュリティ無効化チェック)
        for ver in office_versions:
            for app in ['Word', 'Excel', 'PowerPoint']:
                subkey = f"SOFTWARE\\Microsoft\\Office\\{ver}\\{app}\\Security"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0,
                                        winreg.KEY_READ) as key:
                        try:
                            vba_warn, _ = winreg.QueryValueEx(key, "VBAWarnings")
                            vba_val = int(vba_warn)
                            if vba_val == 1:  # 1 = マクロ全有効
                                results.append({
                                    "location": f"HKCU\\{subkey}",
                                    "entry": f"VBAWarnings ({app} {ver})",
                                    "value": str(vba_val),
                                    "status": "WARNING",
                                    "reason": f"{app}マクロセキュリティ無効化",
                                    "desc": build_tutor_desc(
                                        detection=f"{app} {ver}のマクロセキュリティが無効化されています（VBAWarnings=1）。\n場所: HKCU\\{subkey}\n値: {vba_val}",
                                        why_dangerous="VBAWarnings=1は「すべてのマクロを有効にする」設定です。この状態では、悪意のあるWord/Excelファイルを開いただけでマクロが自動実行されます。Emotetの主な感染経路はマクロ付きOfficeファイルです。攻撃者がこの値を事前に変更し、マクロ実行の警告を無効化している可能性があります。",
                                        mitre_key="reg_office_macro",
                                        normal_vs_abnormal="【正常】通常は2（警告付き無効）か4（マクロ無効）。\n【異常】1（全有効）は危険。意図的に設定されていない限り異常。",
                                        next_steps=["VBAWarningsを2以上に設定する","グループポリシーでマクロを制御する","最近開いたOfficeファイルを確認する"],
                                        status="WARNING"),
                                })
                        except (OSError, ValueError):
                            continue
                except OSError:
                    continue

        return results
