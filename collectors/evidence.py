# -*- coding: utf-8 -*-
# collectors/evidence.py - P36: 実行痕跡解析（5大アーティファクト対応）
# UserAssist / Prefetch / ShimCache / Amcache / BAM
import os
import re
import struct
import ctypes
import ctypes.wintypes
import winreg
import subprocess
from datetime import datetime
from utils.tutor_template import build_tutor_desc

try:
    from utils.signature import verify_signature, is_trusted_signer, is_hardcore_tool, extract_signer_name, clear_cache, batch_verify_signatures
except ImportError:
    verify_signature = None
    clear_cache = None
    batch_verify_signatures = None

    def is_trusted_signer(_signer):
        return False

    def is_hardcore_tool(_name):
        return False

    def extract_signer_name(_signer):
        return ''

try:
    from utils.ioc_database import (
        AMCACHE_SHA256_MAX_BYTES,
        check_sha1_ioc,
        check_sha256_ioc,
        compute_file_sha256,
        should_read_file_for_sha256_ioc,
    )
except ImportError:
    check_sha1_ioc = None
    check_sha256_ioc = None
    compute_file_sha256 = None
    should_read_file_for_sha256_ioc = None


class EvidenceCollector:
    """実行痕跡解析 - フォレンジック5大アーティファクト
    1. UserAssist  — エクスプローラ経由の実行履歴（レジストリ）
    2. Prefetch    — プログラム起動キャッシュ（ファイルシステム）
    3. ShimCache   — アプリ互換性キャッシュ（レジストリバイナリ）
    4. Amcache     — アプリ実行記録+SHA1ハッシュ（レジストリハイブ）
    5. BAM/DAM     — バックグラウンド実行記録（レジストリ）
    """

    def __init__(self):
        self.attack_tools = [
            'mimikatz', 'psexec', 'paexec', 'cobalt', 'beacon',
            'rubeus', 'seatbelt', 'sharphound', 'bloodhound',
            'lazagne', 'procdump', 'nanodump', 'safetykatz',
            'sharpwmi', 'covenant', 'sliver', 'brute', 'crack',
            'hashcat', 'john', 'hydra', 'nmap', 'masscan',
            'chisel', 'ligolo', 'ngrok', 'frp', 'netcat', 'nc.exe',
            'plink', 'socat', 'rclone', 'megasync',
            'advanced_ip_scanner', 'angry_ip', 'nbtscan',
            'empire', 'meterpreter', 'havoc', 'bruteratel',
        ]

        self.lolbins = [
            'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
            'mshta', 'rundll32', 'regsvr32', 'certutil',
            'bitsadmin', 'msiexec', 'wmic', 'msconfig',
            'installutil', 'regasm', 'regsvcs', 'msbuild',
            'cmstp', 'esentutl', 'expand', 'extrac32',
            'makecab', 'replace', 'xwizard', 'msdt',
        ]

        self.recon_tools = [
            'whoami', 'systeminfo', 'ipconfig', 'net.exe', 'net1.exe',
            'nltest', 'dsquery', 'csvde', 'ldifde',
            'quser', 'qwinsta', 'query', 'klist',
            'tasklist', 'taskkill', 'sc.exe', 'schtasks',
            'reg.exe', 'arp.exe', 'route', 'tracert',
            'netstat', 'nslookup', 'ping.exe',
        ]

        self.suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\downloads\\',
            '\\perflogs\\', '\\programdata\\',
            '\\recycler\\', '\\$recycle.bin\\',
            '\\windows\\debug\\', '\\windows\\temp\\',
        ]

    # ==============================================================
    # メインスキャン
    # ==============================================================
    def scan(self):
        if clear_cache:
            clear_cache()  # 署名キャッシュリセット

        # Phase 1: 全サブスキャンを実行（署名検証なし）
        # Phase 2: 結果からユニークパスを収集しバッチ署名検証
        # Phase 3: 署名結果を反映

        # まず署名検証を無効化して高速スキャン
        import utils.signature as _sig_mod
        _orig_verify = _sig_mod.verify_signature
        _sig_mod.verify_signature = None
        global verify_signature
        _bk = verify_signature
        verify_signature = None

        evidence = []
        evidence.extend(self._scan_userassist())
        evidence.extend(self._scan_prefetch())
        evidence.extend(self._scan_shimcache())
        evidence.extend(self._scan_amcache())
        evidence.extend(self._scan_bam())

        # 署名検証を復元
        _sig_mod.verify_signature = _orig_verify
        verify_signature = _bk

        # 信頼パスリスト
        _trusted_dirs = [
            'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
            'c:\\program files\\', 'c:\\program files (x86)\\',
            'c:\\windows\\winsxs\\', 'c:\\windows\\microsoft.net\\',
            'c:\\windows\\servicing\\', 'c:\\windows\\immersivecontrolpanel\\',
            'c:\\windows\\systemapps\\',
            'c:\\windows\\uus\\',
            'c:\\windows\\temp\\',
            'c:\\windows\\installer\\',
            'c:\\windows\\softwaredistribution\\',
        ]

        # 既知アプリパターン（署名検証スキップ対象）
        _known_apps = {
            'chrome': 'Google Chrome',
            'msedge': 'Microsoft Edge',
            'firefox': 'Mozilla Firefox',
            'code': 'Visual Studio Code',
            'discord': 'Discord',
            'slack': 'Slack',
            'teams': 'Microsoft Teams',
            'spotify': 'Spotify',
            'steam': 'Steam',
            'onedrive': 'Microsoft OneDrive',
            'dropbox': 'Dropbox',
            'zoom': 'Zoom',
            'git': 'Git',
            'node': 'Node.js',
            'python': 'Python',
            'java': 'Java',
            'notepad++': 'Notepad++',
            'vlc': 'VLC Media Player',
            '7z': '7-Zip',
            'winrar': 'WinRAR',
            'docker': 'Docker',
            'vmware': 'VMware',
            'virtualbox': 'VirtualBox',
            'obs': 'OBS Studio',
            'gimp': 'GIMP',
            'audacity': 'Audacity',
            'vscode': 'VS Code',
            'powershell': 'PowerShell',
            'windowsterminal': 'Windows Terminal',
            'explorer': 'Windows Explorer',
            'svchost': 'Windows Service Host',
            'taskhostw': 'Windows Task Host',
            'runtimebroker': 'Runtime Broker',
            'searchhost': 'Windows Search',
            'startmenuexperiencehost': 'Start Menu',
            'shellexperiencehost': 'Shell Experience',
            'applicationframehost': 'App Frame Host',
            'systemsettings': 'System Settings',
            'securityhealthsystray': 'Windows Security',
            'widgets': 'Windows Widgets',
            'phoneexperiencehost': 'Phone Link',
            'gamebar': 'Xbox Game Bar',
            'msteams': 'Microsoft Teams',
        }

        _known_app_paths = [
            ('\\appdata\\local\\google\\chrome\\', 'Google Chrome'),
            ('\\appdata\\local\\microsoft\\edge\\', 'Microsoft Edge'),
            ('\\appdata\\local\\discord\\', 'Discord'),
            ('\\appdata\\local\\slack\\', 'Slack'),
            ('\\appdata\\local\\programs\\microsoft vs code\\', 'VS Code'),
            ('\\appdata\\local\\programs\\python\\', 'Python'),
            ('\\appdata\\local\\gitkraken\\', 'GitKraken'),
            ('\\appdata\\local\\spotify\\', 'Spotify'),
            ('\\appdata\\local\\zoom\\', 'Zoom'),
            ('\\appdata\\local\\teams\\', 'Microsoft Teams'),
            ('\\appdata\\local\\docker\\', 'Docker'),
            ('\\appdata\\local\\packages\\', 'Windows Store App'),
            ('\\steam\\', 'Steam'),
            ('\\windowsapps\\', 'Windows Store App'),
            ('\\appdata\\local\\docker\\', 'Docker'),
            ('\\appdata\\local\\temp\\dockerdesktop', 'Docker Desktop'),
            ('\\.docker\\', 'Docker'),
            ('\\appdata\\local\\gitkraken\\', 'GitKraken'),
            ('\\appdata\\local\\postman\\', 'Postman'),
            ('\\appdata\\local\\obsidian\\', 'Obsidian'),
            ('\\appdata\\local\\notion\\', 'Notion'),
            ('\\appdata\\roaming\\zoom\\', 'Zoom'),
            ('\\tool\\', 'User Tools'),
        ]

        # ユニークパスを収集（信頼パスは署名検証スキップ）
        untrusted_paths = set()
        trusted_path_set = set()
        for item in evidence:
            art = item.get('artifact', '')
            if not art:
                continue
            art_lower = art.lower()
            if any(art_lower.startswith(d) for d in _trusted_dirs):
                trusted_path_set.add(art)
            else:
                # 既知アプリパスチェック
                _matched_app = None
                for _pat, _app_name in _known_app_paths:
                    if _pat in art_lower:
                        _matched_app = _app_name
                        break
                if not _matched_app:
                    _bn = os.path.basename(art_lower).replace('.exe', '')
                    _matched_app = _known_apps.get(_bn)

                if _matched_app:
                    trusted_path_set.add(art)  # 既知アプリも信頼扱い
                elif art.startswith('\\\\'):
                    trusted_path_set.add(art)  # UNCパスは署名検証スキップ
                elif not art_lower.endswith('.exe'):
                    trusted_path_set.add(art)  # 非EXEは署名検証不要
                else:
                    if item.get('source') != 'Amcache' and os.path.isfile(art):
                        untrusted_paths.add(art)

        # バッチ署名検証（不審パスのみ）
        if batch_verify_signatures and untrusted_paths:
            batch_verify_signatures(list(untrusted_paths))

        # 署名結果を各アイテムに反映
        for item in evidence:
            art = item.get('artifact', '')
            if not art:
                continue
            art_lower = art.lower()

            # 信頼パス or 既知アプリ → 署名検証不要
            _is_unc = art.startswith('\\\\')
            _is_non_exe = not art_lower.endswith('.exe')
            _is_trusted_dir = _is_unc or _is_non_exe or any(art_lower.startswith(d) for d in _trusted_dirs)
            _matched_known = None
            if not _is_trusted_dir:
                for _pat, _app_name in _known_app_paths:
                    if _pat in art_lower:
                        _matched_known = _app_name
                        break
                if not _matched_known:
                    _bn = os.path.basename(art_lower).replace('.exe', '')
                    _matched_known = _known_apps.get(_bn)

            if _is_trusted_dir or _matched_known:
                _skip_reason = _matched_known or '信頼パス'
                item['sig_status'] = 'TrustedPath'
                item['sig_signer'] = _skip_reason
                if _is_unc:
                    item['trust_detail'] = f'UNCネットワークパス | {art}'
                elif _is_non_exe:
                    item['trust_detail'] = f'非EXEファイル | {art}'
                elif _matched_known:
                    item['trust_detail'] = f'既知アプリ: {_matched_known} | {art}'
                else:
                    item['trust_detail'] = f'信頼ディレクトリ | {art}'
                basename = os.path.basename(art_lower).replace('.exe', '')
                if not is_hardcore_tool(basename) and item.get('status') in ('WARNING', 'INFO'):
                    item['status'] = 'SAFE'
                    item['reason'] = f'信頼リスト除外: {_skip_reason} | {art}'
                continue

            # 不審パス → 署名検証結果を反映
            if verify_signature:
                sig_status, sig_signer = verify_signature(art)
                sig_org = extract_signer_name(sig_signer)
                sig_trusted = (sig_status == 'Valid' and is_trusted_signer(sig_signer))
                item['sig_status'] = sig_status
                item['sig_signer'] = sig_org

                if sig_trusted and item.get('status') in ('WARNING', 'INFO'):
                    basename = os.path.basename(art_lower).replace('.exe', '')
                    if not is_hardcore_tool(basename):
                        item['status'] = 'SAFE'
                        item['reason'] = f"正規署名済み: {sig_org}"

        return evidence

    # ==============================================================
    # 共通: 実行パス解析
    # ==============================================================

    def _is_trusted_path(self, path_lower):
        """Layer 2: 信頼パスかどうか判定"""
        trusted_dirs = [
            'c:\\windows\\system32\\',
            'c:\\windows\\syswow64\\',
            'c:\\program files\\',
            'c:\\program files (x86)\\',
            'c:\\windows\\winsxs\\',
            'c:\\windows\\microsoft.net\\',
        ]
        return any(path_lower.startswith(d) for d in trusted_dirs)

    def _analyze_exe_path(self, exe_path, source_name, extra_info="", verify_signature_flag=True):
        """実行パスから危険度を判定（Layer 1-3: 完全一致 + 信頼パス + 署名検証）"""
        # Performance: skip network paths (UNC) entirely
        if exe_path.startswith('\\\\') or exe_path.startswith('//'):
            basename_quick = os.path.basename(exe_path).lower().replace('.exe', '')
            for tool in self.attack_tools:
                if tool.replace('.exe', '') == basename_quick:
                    return ('DANGER', f'攻撃ツール検知: {tool}', f'ネットワークパス: {exe_path}', '', '')
            return ('INFO', '実行痕跡', f'{source_name}: {exe_path}', '', '')
        
        path_lower = exe_path.lower()
        basename = os.path.basename(path_lower).replace('.exe', '')

        sig_status = ''
        sig_signer = ''
        sig_org = ''
        sig_trusted = False

        # Layer 3: 署名検証（ファイルが存在する場合のみ）
        if verify_signature_flag and verify_signature and os.path.isfile(exe_path):
            sig_status, sig_signer = verify_signature(exe_path)
            sig_org = extract_signer_name(sig_signer)
            sig_trusted = (sig_status == 'Valid' and is_trusted_signer(sig_signer))

        # Layer 1: 攻撃ツール（完全一致）
        for tool in self.attack_tools:
            tb = tool.replace('.exe', '')
            if tb == basename or f'\\{tool}' in path_lower or f'\\{tb}.exe' in path_lower:
                if is_hardcore_tool(tb) or not sig_trusted:
                    return ("DANGER", f"攻撃ツール検知: {tool}",
                        build_tutor_desc(
                            detection=(
                                f"{source_name}に攻撃ツール「{tool}」の実行痕跡が残っています。\n"
                                f"パス: {exe_path}\n{extra_info}"
                            ),
                            why_dangerous=(
                                f"{source_name}はOSが自動的に記録する実行履歴です。"
                                f"攻撃ツール「{tool}」がこのPCで実行されたことを意味します。"
                                "攻撃者がツールのEXEファイルを削除しても、この痕跡は残ります。"
                                "つまり「消えたマルウェア」の実行証拠です。"
                            ),
                            mitre_key="evid_attack_tool",
                            normal_vs_abnormal=(
                                "【正常】攻撃ツールの実行痕跡が存在することは正常ではありません。\n"
                                "【異常】100%異常です。インシデント対応が必要です。"
                            ),
                            next_steps=[
                                "該当パスにファイルがまだ存在するか確認する",
                                "存在する場合ハッシュ値をVirusTotalで検索する",
                                "他のアーティファクト（Prefetch, BAM等）で実行時刻を特定する",
                                "イベントログ(4688)で実行者とコマンドラインを確認する",
                            ],
                            status="DANGER"),
                        sig_status, sig_org)
                else:
                    return ("SAFE",
                        f"攻撃ツール名一致だが正規署名済み: {sig_org}",
                        f"ファイル名が攻撃ツール「{tool}」と一致しますが、"
                        f"正規の署名({sig_org})が確認されたため安全と判定しました。",
                        sig_status, sig_org)

        # Layer 2: LOLBin + 不審パス
        found_lolbin = None
        for lb in self.lolbins:
            if lb.replace('.exe', '') == basename:
                found_lolbin = lb
                break

        suspicious_path = False
        for sp in self.suspicious_paths:
            if sp in path_lower:
                suspicious_path = True
                break

        if found_lolbin and suspicious_path:
            if sig_trusted:
                return ("INFO",
                    f"LOLBin({found_lolbin}) 不審パスだが署名済み: {sig_org}",
                    f"LOLBin「{found_lolbin}」が不審なパスで検出されましたが、"
                    f"正規署名({sig_org})が確認されました。念のため確認を推奨します。",
                    sig_status, sig_org)
            return ("WARNING", f"LOLBin不審実行: {found_lolbin}",
                build_tutor_desc(
                    detection=(
                        f"{source_name}でLOLBin「{found_lolbin}」が不審なパスから実行された痕跡です。\n"
                        f"パス: {exe_path}\n{extra_info}"
                    ),
                    why_dangerous=(
                        "LOLBin（Living Off the Land Binary）は正規のWindows標準ツールですが、"
                        "攻撃者が悪用することがあります。特に通常と異なるパスからの実行は疑わしいです。"
                    ),
                    mitre_key="evid_lolbin",
                    next_steps=[
                        "実行パスが正規のSystem32以外か確認する",
                        "同時刻のイベントログ(4688)でコマンドライン引数を確認する",
                        "親プロセスを特定し正当な実行チェーンか検証する",
                    ],
                    status="WARNING"),
                sig_status, sig_org)

        # Layer 2b: 信頼パス + 署名済み → SAFE
        if self._is_trusted_path(path_lower) and sig_trusted:
            return ("SAFE", f"正規署名済み: {sig_org}",
                f"{source_name}の実行痕跡です。正規の署名({sig_org})と"
                f"信頼されたパスが確認されたため、安全と判定しました。",
                sig_status, sig_org)

        # Layer 2c: 信頼パス内だが未署名
        if self._is_trusted_path(path_lower) and not sig_trusted:
            if sig_status == 'NotFound':
                return ("INFO", "信頼パス（ファイル削除済み）",
                    f"{source_name}の実行痕跡です。信頼パス内ですがファイルが"
                    f"既に削除されているため署名を確認できませんでした。",
                    sig_status, sig_org)
            return ("INFO", f"信頼パス（署名未確認: {sig_status}）",
                f"{source_name}の実行痕跡です。信頼パス内ですが"
                f"署名の検証結果は「{sig_status}」でした。",
                sig_status, sig_org)

        # Rule 3: 偵察コマンド
        for rc in self.recon_tools:
            if rc == basename:
                return ("INFO", f"偵察コマンド: {rc}",
                    build_tutor_desc(
                        detection=f"{source_name}で偵察コマンド「{rc}」の実行痕跡が見つかりました。",
                        why_dangerous="偵察コマンドは正規利用もありますが、攻撃者が情報収集に使うこともあります。",
                        mitre_key="evid_recon",
                        next_steps=["同時刻の他コマンド実行を確認する", "実行者アカウントを特定する"],
                        status="INFO"),
                    sig_status, sig_org)

        # デフォルト: 署名があればSAFE、なければINFO
        if sig_trusted:
            return ("SAFE", f"正規署名済み: {sig_org}",
                f"正規の署名({sig_org})が確認されました。",
                sig_status, sig_org)

        return ("INFO", "実行痕跡",
            f"{source_name}に実行痕跡が記録されています。",
            sig_status, sig_org)

    def _scan_userassist(self):
        results = []
        sub_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as ua_key:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(ua_key, idx)
                        idx += 1
                    except OSError:
                        break
                    count_path = r"{}\Count".format(guid)
                    try:
                        full_path = sub_key + "\\" + count_path
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, full_path) as count_key:
                            num_values = winreg.QueryInfoKey(count_key)[1]
                            for i in range(num_values):
                                try:
                                    name, value, _ = winreg.EnumValue(count_key, i)
                                    decoded = self._rot13(name)
                                    timestamp_str = self._parse_userassist_timestamp(value)
                                    run_count = self._parse_userassist_runcount(value)
                                    extra = f"実行回数: {run_count}回"
                                    if timestamp_str:
                                        extra += f"\n最終実行: {timestamp_str}"
                                    result = self._analyze_exe_path(decoded, "UserAssist (レジストリ)", extra)
                                    if len(result) == 5:
                                        status, reason, desc, sig_st, sig_name = result
                                    else:
                                        status, reason, desc = result
                                        sig_st = ""
                                        sig_name = ""
                                    if status == "SAFE":
                                        continue
                                    results.append({
                                        "source": "UserAssist",
                                        "artifact": decoded,
                                        "detail": f"実行回数: {run_count}",
                                        "time": timestamp_str,
                                        "status": status,
                                        'sig_status': sig_st,
                                        'sig_signer': sig_name,
                                        "reason": reason,
                                        "desc": desc,
                                    })
                                except OSError:
                                    continue
                    except OSError:
                        continue
        except OSError:
            pass
        return results

    def _rot13(self, text):
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _parse_userassist_timestamp(self, raw_value):
        try:
            if isinstance(raw_value, bytes) and len(raw_value) >= 68:
                low = struct.unpack_from('<I', raw_value, 60)[0]
                high = struct.unpack_from('<I', raw_value, 64)[0]
                ft = (high << 32) | low
                if ft > 0:
                    ts = (ft - 116444736000000000) / 10000000
                    dt = datetime.fromtimestamp(ts)
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
        return ""

    def _parse_userassist_runcount(self, raw_value):
        try:
            if isinstance(raw_value, bytes) and len(raw_value) >= 8:
                return struct.unpack_from('<I', raw_value, 4)[0]
        except Exception:
            pass
        return 0

    # ==============================================================
    # 2a. Prefetch ヘルパー (P45: 深層解析)
    # ==============================================================

    # ERR-P45-001: Prefetch MAM圧縮解凍
    def _decompress_prefetch(self, filepath):
        """Prefetchファイルを読み込み、MAM圧縮なら解凍して返す。失敗時はNone。"""
        try:
            with open(filepath, 'rb') as f:
                buf = f.read()
        except (PermissionError, OSError):
            return None

        if len(buf) < 8:
            return None

        # MAM圧縮判定（先頭4バイト = b'MAM' + bytes([4])）
        if buf[:4] == b'MAM' + bytes([4]):
            return self._mam_decompress(buf)

        # 非圧縮: Prefetchシグネチャ確認
        sig = struct.unpack_from('<I', buf, 0)[0]
        if sig in (0x11, 0x17, 0x1A, 0x1E, 0x1F):
            return buf

        # バージョンフィールドがオフセット0にない古い形式
        # SCCA シグネチャ確認 (offset 4-7)
        if len(buf) >= 8 and buf[4:8] == b'SCCA':
            return buf

        return None

    # ERR-P45-002: MAM (Xpress Huffman) 解凍
    def _mam_decompress(self, buf):
        """Windows API RtlDecompressBufferEx でMAM圧縮を解凍する。"""
        try:
            # MAMヘッダ: 4byte sig + 4byte uncompressed_size
            if len(buf) < 8:
                return None
            uncompressed_size = struct.unpack_from('<I', buf, 4)[0]
            compressed_data = buf[8:]

            ntdll = ctypes.windll.ntdll

            # COMPRESSION_FORMAT_XPRESS_HUFF = 4
            COMPRESSION_FORMAT_XPRESS_HUFF = 4

            # RtlGetCompressionWorkSpaceSize
            workspace_size = ctypes.c_ulong(0)
            fragment_size = ctypes.c_ulong(0)
            status = ntdll.RtlGetCompressionWorkSpaceSize(
                COMPRESSION_FORMAT_XPRESS_HUFF,
                ctypes.byref(workspace_size),
                ctypes.byref(fragment_size)
            )
            if status != 0:
                return None

            workspace = ctypes.create_string_buffer(workspace_size.value)
            output_buf = ctypes.create_string_buffer(uncompressed_size)
            final_size = ctypes.c_ulong(0)

            # RtlDecompressBufferEx
            status = ntdll.RtlDecompressBufferEx(
                COMPRESSION_FORMAT_XPRESS_HUFF,
                output_buf,
                uncompressed_size,
                compressed_data,
                len(compressed_data),
                ctypes.byref(final_size),
                workspace
            )
            if status != 0:
                return None

            return output_buf.raw[:final_size.value]
        except Exception:
            return None

    # ERR-P45-003: Prefetchヘッダパース
    def _parse_prefetch_header(self, data):
        """Prefetchバイナリからヘッダ情報を抽出する。"""
        result = {
            'version': 0, 'version_label': '', 'exe_name': '',
            'run_count': 0, 'last_run_time': '',
            'run_times': [], 'file_strings_offset': 0,
            'file_strings_size': 0,
        }

        if not data or len(data) < 84:
            return result

        # バージョン判定
        version = struct.unpack_from('<I', data, 0)[0]
        # SCCA形式: offset 0-3がバージョンでない場合、offset 4-7がSCCA
        if data[4:8] == b'SCCA':
            version = struct.unpack_from('<I', data, 0)[0]

        version_map = {
            17: 'WinXP (v17)',
            23: 'Vista/7 (v23)',
            26: 'Win8/8.1 (v26)',
            30: 'Win10/11 (v30)',
            31: 'Win11 (v31)',
        }
        result['version'] = version
        result['version_label'] = version_map.get(version, f'Unknown (v{version})')

        # 実行ファイル名（offset 16、60バイト、UTF-16LE）
        try:
            raw_name = data[16:76]
            exe_name = raw_name.decode('utf-16-le', errors='ignore').split('\\x00')[0]
            result['exe_name'] = exe_name
        except Exception:
            pass

        # ファイル名文字列テーブル情報
        try:
            if version == 17:
                result['file_strings_offset'] = struct.unpack_from('<I', data, 100)[0]
                result['file_strings_size'] = struct.unpack_from('<I', data, 104)[0]
            elif version == 23:
                result['file_strings_offset'] = struct.unpack_from('<I', data, 116)[0]
                result['file_strings_size'] = struct.unpack_from('<I', data, 120)[0]
            elif version in (26, 30):
                # v26/v30: RunCount at 208, LastRunTime x8 at 176
                result['run_count'] = struct.unpack_from('<I', data, 208)[0]
                run_times = []
                for idx in range(8):
                    offset = 176 + (idx * 8)
                    if offset + 8 <= len(data):
                        ft = struct.unpack_from('<Q', data, offset)[0]
                        ts = self._filetime_to_str(ft)
                        if ts:
                            run_times.append(ts)
                result['run_times'] = run_times
                result['last_run_time'] = run_times[0] if run_times else ''

            elif version == 31:
                # v31 (Win11): RunCount at 200, LastRunTime x8 at 128
                result['run_count'] = struct.unpack_from('<I', data, 200)[0]
                run_times = []
                for idx in range(8):
                    offset = 128 + (idx * 8)
                    if offset + 8 <= len(data):
                        ft = struct.unpack_from('<Q', data, offset)[0]
                        ts = self._filetime_to_str(ft)
                        if ts:
                            run_times.append(ts)
                result['run_times'] = run_times
                result['last_run_time'] = run_times[0] if run_times else ''

        except Exception:
            pass

        return result

    # ERR-P45-004: FILETIME→文字列変換
    def _filetime_to_str(self, ft):
        """Windows FILETIME (100ns since 1601-01-01) を文字列に変換。"""
        if ft == 0 or ft > 0x7FFFFFFFFFFFFFFF:
            return ''
        try:
            # FILETIME epoch: 1601-01-01, Unix epoch差: 11644473600秒
            timestamp = (ft - 116444736000000000) / 10000000
            if timestamp < 0 or timestamp > 4102444800:  # 2100年まで
                return ''
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (OSError, ValueError, OverflowError):
            return ''

    # ERR-P45-005: ロード済みファイルリスト抽出
    def _extract_loaded_files(self, data, pf_info):
        """Prefetch内のファイル名テーブルからロード済みファイルを抽出。"""
        loaded = []
        offset = pf_info.get('file_strings_offset', 0)
        size = pf_info.get('file_strings_size', 0)

        if offset == 0 or size == 0 or offset + size > len(data):
            return loaded

        try:
            raw = data[offset:offset + size]
            # UTF-16LEのヌル終端文字列リスト
            text = raw.decode('utf-16-le', errors='ignore')
            files = [f.strip() for f in text.split('\\x00') if f.strip()]

            suspicious_dirs = [
                '\\\\temp\\\\', '\\\\tmp\\\\', '\\\\appdata\\\\local\\\\temp\\\\',
                '\\\\users\\\\public\\\\', '\\\\downloads\\\\',
                '\\\\perflogs\\\\', '\\\\.bin\\\\',
                '\\\\programdata\\\\',
            ]

            for fpath in files:
                fl = fpath.lower()
                is_suspicious = any(sd in fl for sd in suspicious_dirs)
                is_dll = fl.endswith('.dll') or fl.endswith('.ocx') or fl.endswith('.drv')
                if is_suspicious and is_dll:
                    loaded.append(fpath)

        except Exception:
            pass

        return loaded

    # ==============================================================
    # 2. Prefetch 解析
    # ==============================================================
    def _scan_prefetch(self):
        results = []
        prefetch_dir = r"C:\Windows\Prefetch"
        if not os.path.exists(prefetch_dir):
            results.append({
                "source": "Prefetch",
                "artifact": "Prefetchフォルダ不在",
                "detail": "",
                "time": "",
                "status": "WARNING",
                "reason": "Prefetchが無効化されている可能性",
                "desc": build_tutor_desc(
                    detection='C:\\Windows\\Prefetch フォルダが存在しません。',
                    why_dangerous=(
                        'Prefetchはプログラムの起動を高速化するためのキャッシュで、'
                        '実行されたプログラム名が自動的に記録されます。'
                        '攻撃者が証拠隠滅のためにPrefetchを無効化・削除することがあります。'
                    ),
                    normal_vs_abnormal=(
                        '【正常】C:\\Windows\\Prefetch が存在し.pfファイルが多数格納されている。\n'
                        '【異常】フォルダが存在しない、または空である。'
                    ),
                    next_steps=[
                        'レジストリのPrefetchParameters\\EnablePrefetcherの値を確認する',
                        'Volume Shadow Copyから過去のPrefetchファイルを復元する',
                    ],
                    status="WARNING"),
            })
            return results

        try:
            for filename in os.listdir(prefetch_dir):
                if not filename.upper().endswith('.PF'):
                    continue
                filepath = os.path.join(prefetch_dir, filename)

                # ファイルシステムのmtime（フォールバック用）
                try:
                    mtime = os.path.getmtime(filepath)
                    dt = datetime.fromtimestamp(mtime)
                    dt_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    dt_str = ''

                exe_name = re.sub(r'-[A-F0-9]{8}\.pf$', '', filename, flags=re.IGNORECASE)

                # P45: Prefetchバイナリ深層解析
                pf_info = None
                run_count = 0
                last_run = ''
                run_times_str = ''
                pf_version = ''
                loaded_suspicious = ''

                pf_data = self._decompress_prefetch(filepath)
                if pf_data:
                    pf_info = self._parse_prefetch_header(pf_data)
                    if pf_info:
                        run_count = pf_info.get('run_count', 0)
                        last_run = pf_info.get('last_run_time', '')
                        run_times_list = pf_info.get('run_times', [])
                        run_times_str = ', '.join(run_times_list) if run_times_list else ''
                        pf_version = pf_info.get('version_label', '')

                        # ロード済みファイルの不審DLL検出
                        suspicious_files = self._extract_loaded_files(pf_data, pf_info)
                        if suspicious_files:
                            loaded_suspicious = '; '.join(suspicious_files[:10])
                            if len(suspicious_files) > 10:
                                loaded_suspicious += f' ...他{len(suspicious_files)-10}件'

                # 時刻: ヘッダのLastRunTimeを優先、なければmtime
                display_time = last_run if last_run else dt_str

                extra = f'Prefetchファイル: {filename}'
                if display_time:
                    extra += f'\\n最終実行: {display_time}'
                if run_count > 0:
                    extra += f'\\n実行回数: {run_count}回'
                if pf_version:
                    extra += f'\\nPFバージョン: {pf_version}'
                if loaded_suspicious:
                    extra += f'\\n不審DLL: {loaded_suspicious}'

                result = self._analyze_exe_path(exe_name, 'Prefetch (実行キャッシュ)', extra)
                if len(result) == 5:
                    status, reason, desc, sig_st, sig_name = result
                else:
                    status, reason, desc = result
                    sig_st = ''
                    sig_name = ''
                if status == 'SAFE':
                    continue

                entry = {
                    'source': 'Prefetch',
                    'artifact': exe_name,
                    'detail': filename,
                    'time': display_time,
                    'status': status,
                    'sig_status': sig_st,
                    'sig_signer': sig_name,
                    'reason': reason,
                    'desc': desc,
                    # P45追加フィールド
                    'run_count': run_count,
                    'last_run_time': last_run,
                    'run_times': run_times_str,
                    'pf_version': pf_version,
                    'loaded_files_suspicious': loaded_suspicious,
                }
                results.append(entry)

        except PermissionError:
            results.append({
                "source": "Prefetch",
                "artifact": "アクセス拒否",
                "detail": "",
                "time": "",
                "status": "WARNING",
                "reason": "Prefetchフォルダのアクセスが拒否されました",
                "desc": build_tutor_desc(
                    detection='Prefetchフォルダへのアクセスが拒否されました。',
                    why_dangerous='管理者権限で再実行してください。',
                    status="WARNING"),
            })
        return results

    # ==============================================================
    # 3. ShimCache (AppCompatCache) 解析
    # ==============================================================
    def _scan_shimcache(self):
        results = []
        subkey = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                value, _ = winreg.QueryValueEx(key, "AppCompatCache")
                if isinstance(value, bytes):
                    entries = self._parse_shimcache(value)
                    for entry in entries:
                        exe_path = entry.get('path', '')
                        timestamp = entry.get('timestamp', '')
                        extra = f"ShimCacheエントリ順序: {entry.get('position', '?')}"
                        if timestamp:
                            extra += f"\n最終更新: {timestamp}"

                        result = self._analyze_exe_path(exe_path, "ShimCache (AppCompatCache)", extra)
                        if len(result) == 5:
                            status, reason, desc, sig_st, sig_name = result
                        else:
                            status, reason, desc = result
                            sig_st = ""
                            sig_name = ""
                        if status == "SAFE":
                            continue
                        results.append({
                            "source": "ShimCache",
                            "artifact": exe_path,
                            "detail": f"順序: {entry.get('position', '?')}",
                            "time": timestamp,
                            "status": status,
                            'sig_status': sig_st,
                            'sig_signer': sig_name,
                            "reason": reason,
                            "desc": desc,
                        })
        except OSError:
            pass
        except Exception as e:
            results.append({
                "source": "ShimCache",
                "artifact": "解析エラー",
                "detail": str(e)[:100],
                "time": "",
                "status": "INFO",
                "reason": "ShimCache解析中にエラー",
                "desc": build_tutor_desc(
                    detection=f'ShimCache(AppCompatCache)の解析中にエラーが発生しました。\nエラー: {str(e)[:100]}',
                    why_dangerous='',
                    normal_vs_abnormal='管理者権限で再実行してください。',
                    status="INFO"),
            })
        return results

    def _parse_shimcache(self, data):
        """Windows 10+ ShimCache バイナリ解析"""
        entries = []
        try:
            # Windows 10 format: header "10ts" (0x30747331)
            # Each entry: signature(4) + unknown(4) + data_size(4) + path_size(2) + path(unicode) + ...
            offset = 0
            header_sig = data[0:4]

            if header_sig == b'10ts':
                # Windows 10 format
                offset = 48  # skip header
                position = 0
                while offset < len(data) - 12:
                    try:
                        sig = data[offset:offset+4]
                        if sig != b'10ts':
                            break
                        entry_size = struct.unpack_from('<I', data, offset + 8)[0]
                        path_size = struct.unpack_from('<H', data, offset + 12)[0]
                        if path_size <= 0 or path_size > 2000:
                            break
                        path_bytes = data[offset + 14: offset + 14 + path_size]
                        try:
                            exe_path = path_bytes.decode('utf-16-le').rstrip('\x00')
                        except Exception:
                            offset += max(entry_size, 1)
                            continue

                        # Timestamp: 8 bytes after path
                        ts_offset = offset + 14 + path_size
                        timestamp = ""
                        if ts_offset + 8 <= len(data):
                            try:
                                ft = struct.unpack_from('<Q', data, ts_offset)[0]
                                if ft > 0 and ft < 0x7FFFFFFFFFFFFFFF:
                                    ts = (ft - 116444736000000000) / 10000000
                                    if 946684800 < ts < 2000000000:  # 2000-2033
                                        dt = datetime.fromtimestamp(ts)
                                        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                            except Exception:
                                pass

                        position += 1
                        entries.append({
                            'path': exe_path,
                            'timestamp': timestamp,
                            'position': position,
                        })

                        offset += max(entry_size, 14 + path_size + 8)
                        if position >= 1024:  # safety limit
                            break
                    except Exception:
                        break
            else:
                # Fallback: try to extract unicode paths directly
                entries = self._parse_shimcache_fallback(data)

        except Exception:
            entries = self._parse_shimcache_fallback(data)

        return entries

    def _parse_shimcache_fallback(self, data):
        """フォールバック: バイナリからUnicodeパスを直接抽出"""
        entries = []
        # Look for patterns like \Device\HarddiskVolume or C:\
        try:
            text = data.decode('utf-16-le', errors='ignore')
            matches = re.findall(
                r'[A-Za-z]:\\[^\x00\r\n]{4,200}\.(?:exe|dll|sys)',
                text, re.IGNORECASE)
            seen = set()
            pos = 0
            for m in matches:
                m_clean = m.strip()
                if m_clean.lower() not in seen:
                    seen.add(m_clean.lower())
                    pos += 1
                    entries.append({
                        'path': m_clean,
                        'timestamp': '',
                        'position': pos,
                    })
                    if pos >= 500:
                        break
        except Exception:
            pass
        return entries

    # ==============================================================
    # 4. Amcache 解析
    # ==============================================================
    def _scan_amcache(self):
        """Amcache解析 - VSSコピー + python-registry によるオフラインパース"""
        results = []
        amcache_path = r'C:\Windows\appcompat\Programs\Amcache.hve'

        if not os.path.exists(amcache_path):
            return results

        # python-registry import
        try:
            from Registry import Registry
        except ImportError:
            return results

        temp_dir = os.environ.get('TEMP', r'C:\Windows\Temp')
        temp_hive = os.path.join(temp_dir, 'amcache_saca.hve')

        # ERR-P46-010: VSSからAmcache.hveをコピー
        copied = self._copy_amcache_via_vss(amcache_path, temp_hive)
        if not copied:
            # VSSフォールバック: 直接コピー試行
            try:
                import shutil
                shutil.copy2(amcache_path, temp_hive)
                copied = os.path.exists(temp_hive)
            except Exception:
                pass
        if not copied:
            return results

        try:
            reg = Registry.Registry(temp_hive)

            # InventoryApplicationFile 解析
            try:
                inv_key = reg.open('Root\\InventoryApplicationFile')
                for sk in inv_key.subkeys():
                    lower_path = ''
                    sha1 = ''
                    publisher = ''
                    link_date = ''

                    for v in sk.values():
                        vname = v.name()
                        if vname == 'LowerCaseLongPath':
                            lower_path = str(v.value())
                        elif vname == 'FileId':
                            sha1_raw = str(v.value())
                            if sha1_raw.startswith('0000'):
                                sha1 = sha1_raw[4:]
                            else:
                                sha1 = sha1_raw
                        elif vname == 'Publisher':
                            publisher = str(v.value())
                        elif vname == 'LinkDate':
                            link_date = str(v.value())
                        elif vname == 'ProgramId':
                            str(v.value())

                    if not lower_path:
                        continue

                    extra = ''
                    if sha1:
                        extra += 'SHA1: ' + sha1 + '\\n'

                    # P46: IOC（SHA1 は Amcache 既定、ファイル実体が取れる場合は SHA256 も照合）
                    ioc_hit = None
                    if check_sha1_ioc and sha1:
                        ioc_hit = check_sha1_ioc(sha1)
                        if ioc_hit:
                            extra += 'IOC一致(SHA1): ' + ioc_hit['name'] + ' (' + ioc_hit['category_jp'] + ')\\n'
                            extra += 'MITRE: ' + ioc_hit['mitre'] + ' | 深刻度: ' + ioc_hit['severity'] + '\\n'

                    # SHA256 IOC が登録されている場合のみディスク読み（全エントリで全ファイル読みするとスキャンが事実上停止する）
                    if (
                        not ioc_hit
                        and compute_file_sha256
                        and check_sha256_ioc
                        and should_read_file_for_sha256_ioc
                        and should_read_file_for_sha256_ioc()
                        and os.path.isfile(lower_path)
                    ):
                        try:
                            if os.path.getsize(lower_path) <= AMCACHE_SHA256_MAX_BYTES:
                                s256 = compute_file_sha256(lower_path)
                                extra += 'SHA256: ' + s256 + '\\n'
                                ioc_hit = check_sha256_ioc(s256)
                                if ioc_hit:
                                    extra += 'IOC一致(SHA256): ' + ioc_hit['name'] + ' (' + ioc_hit['category_jp'] + ')\\n'
                                    extra += 'MITRE: ' + ioc_hit['mitre'] + ' | 深刻度: ' + ioc_hit['severity'] + '\\n'
                        except Exception:
                            pass

                    if publisher:
                        extra += '発行者: ' + publisher + '\\n'
                    if link_date:
                        extra += 'リンク日: ' + link_date

                    result = self._analyze_exe_path(lower_path, 'Amcache (実行記録+ハッシュ)', extra, verify_signature_flag=False)
                    if len(result) == 5:
                        status, reason, desc, sig_st, sig_name = result
                    else:
                        status, reason, desc = result
                        sig_st = ''
                        sig_name = ''

                    # P46: IOCマッチでDANGER昇格
                    if ioc_hit:
                        status = 'DANGER'
                        reason = 'IOC一致: ' + ioc_hit['name'] + ' (' + ioc_hit['category_jp'] + ')'

                    if status == 'SAFE':
                        continue

                    results.append({
                        'source': 'Amcache',
                        'artifact': lower_path,
                        'detail': ('SHA1: ' + sha1) if sha1 else sk.name(),
                        'time': link_date,
                        'status': status,
                        'sig_status': sig_st,
                        'sig_signer': sig_name,
                        'reason': reason,
                        'desc': desc,
                        'sha1': sha1,
                        'ioc_match': ioc_hit.get('name', '') if ioc_hit else '',
                        'ioc_category': ioc_hit.get('category_jp', '') if ioc_hit else '',
                        'ioc_mitre': ioc_hit.get('mitre', '') if ioc_hit else '',
                        'ioc_severity': ioc_hit.get('severity', '') if ioc_hit else '',
                    })
            except Exception:
                pass

            # File キー（旧形式）も解析
            try:
                file_key = reg.open('Root\\File')
                for vol_key in file_key.subkeys():
                    for entry_key in vol_key.subkeys():
                        fpath = ''
                        sha1_f = ''
                        for v in entry_key.values():
                            if v.name() == '15':  # FullPath
                                fpath = str(v.value())
                            elif v.name() == '101':  # SHA1
                                sha1_raw = str(v.value())
                                if sha1_raw.startswith('0000'):
                                    sha1_f = sha1_raw[4:]
                                else:
                                    sha1_f = sha1_raw
                        if not fpath:
                            continue
                        ioc_hit_f = None
                        if check_sha1_ioc and sha1_f:
                            ioc_hit_f = check_sha1_ioc(sha1_f)
                        result = self._analyze_exe_path(fpath, 'Amcache (File)', '', verify_signature=False)
                        if len(result) == 5:
                            status, reason, desc, sig_st, sig_name = result
                        else:
                            status, reason, desc = result
                            sig_st = ''
                            sig_name = ''
                        if ioc_hit_f:
                            status = 'DANGER'
                            reason = 'IOC一致: ' + ioc_hit_f['name']
                        if status != 'SAFE':
                            results.append({
                                'source': 'Amcache',
                                'artifact': fpath,
                                'detail': ('SHA1: ' + sha1_f) if sha1_f else entry_key.name(),
                                'time': '',
                                'status': status,
                                'sig_status': sig_st,
                                'sig_signer': sig_name,
                                'reason': reason,
                                'desc': desc,
                                'sha1': sha1_f,
                                'ioc_match': ioc_hit_f.get('name', '') if ioc_hit_f else '',
                                'ioc_category': ioc_hit_f.get('category_jp', '') if ioc_hit_f else '',
                                'ioc_mitre': ioc_hit_f.get('mitre', '') if ioc_hit_f else '',
                                'ioc_severity': ioc_hit_f.get('severity', '') if ioc_hit_f else '',
                            })
            except Exception:
                pass

        except Exception:
            pass
        finally:
            try:
                if os.path.exists(temp_hive):
                    os.remove(temp_hive)
            except Exception:
                pass

        return results

    # ERR-P46-011: VSSからAmcache.hveをコピー
    def _copy_amcache_via_vss(self, src_path, dest_path):
        """Volume Shadow Copyからファイルをコピーする"""
        try:
            r = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True, timeout=30, text=True,
                creationflags=0x08000000)
            shadow_path = None
            for line in r.stdout.split('\n'):
                if '\\\\?\\GLOBALROOT' in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        sp = parts[1].strip()
                        if sp.startswith('\\\\'):
                            shadow_path = sp
            if not shadow_path:
                return False
            if not shadow_path.endswith('\\'):
                shadow_path += '\\'
            # src_pathからドライブレターを除去してVSSパスに変換
            rel_path = src_path[3:] if len(src_path) > 3 and src_path[1] == ':' else src_path
            vss_src = shadow_path + rel_path
            subprocess.run(
                ['cmd', '/c', 'copy', '/Y', vss_src, dest_path],
                capture_output=True, timeout=30,
                creationflags=0x08000000)
            return os.path.exists(dest_path)
        except Exception:
            return False

    # ==============================================================
    # 5. BAM/DAM (Background Activity Moderator) 解析
    # ==============================================================
    def _scan_bam(self):
        results = []
        # BAM State
        bam_paths = [
            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
            r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
            r"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
            r"SYSTEM\CurrentControlSet\Services\dam\UserSettings",
        ]

        for bam_path in bam_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as bam_key:
                    # SID サブキーを列挙
                    sid_idx = 0
                    while True:
                        try:
                            sid = winreg.EnumKey(bam_key, sid_idx)
                            sid_idx += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(bam_key, sid, 0,
                                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as sid_key:
                                num_values = winreg.QueryInfoKey(sid_key)[1]
                                for i in range(num_values):
                                    try:
                                        name, value, _ = winreg.EnumValue(sid_key, i)
                                        # BAMのキー名がEXEパス
                                        if not name or '\\' not in name:
                                            continue
                                        # 値はFILETIME（8バイト）
                                        timestamp = ""
                                        if isinstance(value, bytes) and len(value) >= 8:
                                            try:
                                                ft = struct.unpack_from('<Q', value, 0)[0]
                                                if ft > 0 and ft < 0x7FFFFFFFFFFFFFFF:
                                                    ts = (ft - 116444736000000000) / 10000000
                                                    if 946684800 < ts < 2000000000:
                                                        dt = datetime.fromtimestamp(ts)
                                                        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                                            except Exception:
                                                pass

                                        # \Device\HarddiskVolume → C:\ に変換
                                        exe_path = name
                                        if exe_path.startswith('\\Device\\HarddiskVolume'):
                                            exe_path = self._device_to_drive(exe_path)

                                        extra = f"SID: {sid}"
                                        if timestamp:
                                            extra += f"\n最終実行: {timestamp}"

                                        result = self._analyze_exe_path(exe_path, "BAM/DAM (実行記録)", extra)
                                        if len(result) == 5:
                                            status, reason, desc, sig_st, sig_name = result
                                        else:
                                            status, reason, desc = result
                                            sig_st = ""
                                            sig_name = ""
                                        if status == "SAFE":
                                            continue
                                        results.append({
                                            "source": "BAM/DAM",
                                            "artifact": exe_path,
                                            "detail": f"SID: {sid[:20]}...",
                                            "time": timestamp,
                                            "status": status,
                                            'sig_status': sig_st,
                                            'sig_signer': sig_name,
                                            "reason": reason,
                                            "desc": desc,
                                        })
                                    except OSError:
                                        continue
                        except OSError:
                            continue
            except OSError:
                continue

        return results

    def _device_to_drive(self, device_path):
        """\\Device\\HarddiskVolumeN\\... → C:\\... に変換"""
        try:
            # ドライブレターのマッピングを取得
            for letter in 'CDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    try:
                        # 簡易変換: Volume1→C:, Volume2→D: 等（概算）
                        pass
                    except Exception:
                        pass
            # フォールバック: Volume番号でC:として扱う
            match = re.match(r'\\Device\\HarddiskVolume\d+\\(.+)', device_path)
            if match:
                return f"C:\\{match.group(1)}"
        except Exception:
            pass
        return device_path