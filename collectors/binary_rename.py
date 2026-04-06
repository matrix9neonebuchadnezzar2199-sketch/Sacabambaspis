# -*- coding: utf-8 -*-
# collectors/binary_rename.py - P43: バイナリリネーム検知 (Velociraptor BinaryRename移植)
# 実行中プロセスのファイル名とPEヘッダのOriginalFilename/InternalNameを比較し、
# リネームされた攻撃ツール・LOLBinを検出する
import os
import psutil

try:
    from utils.tutor_template import build_tutor_desc
except ImportError:
    def build_tutor_desc(**kwargs):
        return kwargs.get('detection', '')

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


class BinaryRenameCollector:
    def __init__(self):
        # Velociraptor Windows.Detection.BinaryRename テーブル移植
        # (filename, internal_name, original_filename, description, note)
        # filename=ANY → どんなファイル名でも検知（攻撃ツール）
        self.rename_table = [
            # === システムツール（リネーム悪用） ===
            ("cmd.exe",        "cmd",              "Cmd.Exe",              "Windows Command Processor"),
            ("powershell.exe", "POWERSHELL",       "PowerShell.EXE",      "Windows PowerShell"),
            ("certutil.exe",   "CertUtil.exe",     "CertUtil.exe",        "CertUtil"),
            ("cscript.exe",    "cscript.exe",      "cscript.exe",         "Console Based Script Host"),
            ("wscript.exe",    "wscript.exe",      "wscript.exe",         "Windows Based Script Host"),
            ("mshta.exe",      "MSHTA.EXE",        "MSHTA.EXE",          "HTML Application Host"),
            ("rundll32.exe",   "rundll",           "RUNDLL32.EXE",        "Windows Rundll32"),
            ("regsvr32.exe",   "REGSVR32",         "REGSVR32.EXE",       "Microsoft Register Server"),
            ("msiexec.exe",    "msiexec",          "msiexec.exe",         "Windows Installer"),
            ("cmstp.exe",      "CMSTP",            "CMSTP.EXE",          "Connection Manager Profile Installer"),
            ("wmic.exe",       "wmic.exe",         "wmic.exe",            "WMI Commandline Utility"),
            ("net.exe",        "net.exe",          "net.exe",             "Net Command"),
            ("net1.exe",       "net1.exe",         "net1.exe",            "Net1 Command"),
            ("netsh.exe",      "netsh.exe",        "netsh.exe",           "Network Shell"),
            ("wevtutil.exe",   "wevtutil.exe",     "wevtutil.exe",        "Eventing Command Line Utility"),
            ("nltest.exe",     "nltestrk.exe",     "nltestrk.exe",        "Logon Server Test Utility"),
            ("dsquery.exe",    "dsquery.exe",      "dsquery.exe",         "AD DS/LDS Query Utility"),
            ("nbtstat.exe",    "nbtinfo.exe",      "nbtinfo.exe",         "TCP/IP NetBios Information"),
            ("qprocess.exe",   "qprocess",         "qprocess.exe",        "Query Process Utility"),
            ("qwinsta.exe",    "qwinsta",          "qwinsta.exe",         "Query Session Utility"),
            ("7z.exe",         "7z",               "7z.exe",              "7-Zip Console"),
            # === 攻撃ツール（ANY = ファイル名問わず検知） ===
            ("ANY", "nc",              "nc.exe",              "NetCat"),
            ("ANY", "AdFind.exe",      "AdFind.exe",          "Joeware ADFind"),
            ("ANY", "rclone",          "rclone.exe",          "Rsync for cloud storage"),
            ("ANY", "MEGAsync.exe",    "MEGAsync.exe",        "MEGAsync"),
            ("ANY", "mimikatz",        "mimikatz.exe",        "mimikatz"),
            ("ANY", "ProcDump",        "procdump",            "Sysinternals ProcDump"),
            ("ANY", "",                "psexec.c",            "Sysinternals PSExec"),
            ("ANY", "",                "",                    "AnyDesk"),
            ("ANY", "",                "",                    "Ammyy Admin"),
            ("ANY", "ProcessHacker.exe","ProcessHacker.exe",  "Process Hacker"),
            ("ANY", "ChromePass",      "ChromePass",          "Chrome Password Recovery"),
            ("ANY", "",                "netscan.exe",         "Network Scanner"),
            ("ANY", "WKV",             "",                    "WirelessKeyView"),
            ("ANY", "rdpv.exe",        "rdpv.exe",            "RDP Password Recovery"),
            ("ANY", "RemCom",          "RemCom.exe",          "Remote Command Executor"),
            ("ANY", "",                "winscp.com",          "WinSCP Console"),
            ("ANY", "winscp",          "winscp.exe",          "WinSCP"),
            ("ANY", "iepv",            "iepv.exe",            "IE Passwords Viewer"),
            ("ANY", "VNCPassView",     "VNCPassView.exe",     "VNC Password Viewer"),
            ("ANY", "PCHunter",        "PCHunter.exe",        "PCHunter"),
            ("ANY", "Massscan_GUI.exe","Massscan_GUI.exe",    "Masscan GUI"),
            ("ANY", "PowerTool.exe",   "PowerTool.exe",       "Anti-rootkit Tool"),
            ("ANY", "BulletsPassView", "BulletsPassView.exe", "BulletsPassView"),
            ("ANY", "WinLister",       "WinLister.exe",       "WinLister"),
            ("ANY", "NirCmd",          "NirCmd.exe",          "NirCmd"),
            ("ANY", "NSudo",           "NSudo.exe",           "NSudo"),
            ("ANY", "Defender Control","Defender Control",    "Windows Defender Control"),
            # === リモートアクセス ===
            ("plink.exe",  "Plink",  "Plink",  "SSH/Telnet Client"),
            ("pscp.exe",   "PSCP",   "PSCP",   "SCP/SFTP Client"),
            ("psftp.exe",  "PSFTP",  "PSFTP",  "Interactive SFTP Client"),
            ("psexec.exe", "PsExec", "psexec.c","Sysinternals PSExec"),
            ("psexec64.exe","PsExec","psexec.exe","Sysinternals PSExec 64-bit"),
            ("winrar.exe", "WinRAR", "WinRAR.exe","WinRAR Archiver"),
        ]

        # 高危険度ツール（ANY かつ攻撃専用）
        self.hardcore_tools = {
            'mimikatz', 'nc', 'netcat', 'adFind', 'rclone', 'megasync',
            'procdump', 'psexec', 'remcom', 'processhacker', 'pchunter',
            'powertool', 'chromepass', 'wirelesskeyview', 'vncpassview',
            'iepv', 'rdpv', 'bulletspassview', 'nircmd', 'nsudo',
            'defender control', 'masscan'
        }

        # 信頼パス（誤検知抑制）
        self._trusted_dirs = [
            'c:\\windows\\system32\\',
            'c:\\windows\\syswow64\\',
            'c:\\program files\\',
            'c:\\program files (x86)\\',
        ]

    def scan(self):
        if not HAS_PEFILE:
            return [{
                'status': 'INFO',
                'exe_name': '-',
                'exe_path': '-',
                'original_name': '-',
                'internal_name': '-',
                'current_name': '-',
                'description': '-',
                'reason': 'pefile未インストール: pip install pefile',
                'desc': 'PEヘッダ解析ライブラリが見つかりません',
                'source': 'BinaryRename',
                'pid': 0,
            }]

        results = []
        seen_paths = set()

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info['name'] or ''
                exe_path = proc.info['exe'] or ''

                if not exe_path or not os.path.isfile(exe_path):
                    continue
                if exe_path.lower() in seen_paths:
                    continue
                seen_paths.add(exe_path.lower())

                pe_info = self._read_pe_version(exe_path)
                if not pe_info:
                    continue

                match = self._check_rename(name, exe_path, pe_info)
                if match:
                    results.append(match)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return results

    def _read_pe_version(self, exe_path):
        """PEヘッダからVersionInformationを読み取る"""
        try:
            pe = pefile.PE(exe_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
            )

            info = {}
            if hasattr(pe, 'FileInfo'):
                for fi_list in pe.FileInfo:
                    for fi in fi_list:
                        if hasattr(fi, 'StringTable'):
                            for st in fi.StringTable:
                                for k, v in st.entries.items():
                                    info[k.decode('utf-8', errors='replace')] = v.decode('utf-8', errors='replace')
            pe.close()
            return info if info else None
        except Exception:
            return None

    def _check_rename(self, current_name, exe_path, pe_info):
        """リネーム検知ロジック"""
        current_lower = current_name.lower()
        path_lower = exe_path.lower()

        orig = pe_info.get('OriginalFilename', '').strip()
        internal = pe_info.get('InternalName', '').strip()
        company = pe_info.get('CompanyName', '').strip()
        description = pe_info.get('FileDescription', '').strip()

        orig_lower = orig.lower()
        internal_lower = internal.lower()

        for expected_fn, exp_internal, exp_original, desc_note in self.rename_table:
            exp_fn_l = expected_fn.lower()
            exp_int_l = exp_internal.lower() if exp_internal else ''
            exp_orig_l = exp_original.lower() if exp_original else ''

            matched_pe = False
            # 完全一致 or 拡張子除去後の完全一致（部分一致による誤検知防止）
            orig_base = orig_lower.replace('.exe', '').replace('.dll', '')
            internal_base = internal_lower.replace('.exe', '').replace('.dll', '')
            exp_orig_base = exp_orig_l.replace('.exe', '').replace('.dll', '').replace('.c', '')
            exp_int_base = exp_int_l.replace('.exe', '').replace('.dll', '')

            if exp_orig_base and (exp_orig_base == orig_base or exp_orig_l == orig_lower):
                matched_pe = True
            elif exp_int_base and (exp_int_base == internal_base or exp_int_l == internal_lower):
                matched_pe = True

            if not matched_pe:
                continue

            # ANY = 攻撃ツール → ファイル名問わず報告
            if exp_fn_l == 'any':
                is_hardcore = any(h in internal_lower or h in orig_lower
                                 for h in self.hardcore_tools)
                status = 'DANGER' if is_hardcore else 'WARNING'
                reason = f'攻撃ツール検知: {desc_note} (PE: {orig or internal})'

                return self._build_result(
                    status=status,
                    current_name=current_name,
                    exe_path=exe_path,
                    original=orig,
                    internal=internal,
                    description=description,
                    company=company,
                    reason=reason,
                    desc_note=desc_note,
                    rename_type='攻撃ツール',
                    mitre_key='binrename_attack_tool',
                    pid=0,
                )

            # システムツールのリネーム検知
            if exp_fn_l != current_lower:
                # 信頼パスにある場合はスキップ（正規のWindowsコンポーネント）
                if any(path_lower.startswith(d) for d in self._trusted_dirs):
                    continue

                reason = f'バイナリリネーム: {desc_note} が "{current_name}" にリネーム (本来: {expected_fn})'

                return self._build_result(
                    status='DANGER',
                    current_name=current_name,
                    exe_path=exe_path,
                    original=orig,
                    internal=internal,
                    description=description,
                    company=company,
                    reason=reason,
                    desc_note=desc_note,
                    rename_type='LOLBinリネーム',
                    mitre_key='binrename_lolbin',
                    pid=0,
                )

        return None

    def _build_result(self, status, current_name, exe_path, original, internal,
                      description, company, reason, desc_note, rename_type, mitre_key, pid):
        detection_text = f'{rename_type}検知: "{current_name}" (元: {original or internal})'
        if rename_type == '攻撃ツール':
            why_text = (
                f'{desc_note} のPEヘッダ情報が検出されました。'
                f'攻撃者がファイル名を変更して正規ツールに偽装している可能性があります。'
                f'T1036.003 (Masquerading: Rename System Utilities) に該当します。'
            )
        else:
            why_text = (
                f'Windows標準ツール "{original or internal}" が "{current_name}" にリネームされています。'
                f'攻撃者はEDR/ログ監視を回避するためにシステムツールをリネームして実行します。'
                f'T1036.003 (Masquerading: Rename System Utilities) に該当します。'
            )

        normal_text = f'正規の {original or internal} は本来のファイル名で実行される'
        abnormal_text = f'"{current_name}" という名前で {desc_note} が実行されている'

        next_steps = [
            f'ファイルパス "{exe_path}" を確認し、正規の場所か検証',
            'ファイルハッシュを VirusTotal で検索',
            'プロセスの親プロセスと起動コマンドラインを確認',
            '同時期のイベントログ (Event ID 4688) を確認',
        ]

        normal_vs = f'正常: {normal_text} / 異常: {abnormal_text}'
        full_desc = build_tutor_desc(
            detection=detection_text,
            why_dangerous=why_text,
            mitre_key=mitre_key,
            normal_vs_abnormal=normal_vs,
            next_steps=next_steps,
        )

        return {
            'status': status,
            'exe_name': current_name,
            'exe_path': exe_path,
            'original_name': original or '-',
            'internal_name': internal or '-',
            'current_name': current_name,
            'description': description or '-',
            'company': company or '-',
            'rename_type': rename_type,
            'reason': reason,
            'desc': full_desc,
            'source': 'BinaryRename',
            'pid': pid,
            'artifact': exe_path,
            'mitre': 'T1036.003',
        }