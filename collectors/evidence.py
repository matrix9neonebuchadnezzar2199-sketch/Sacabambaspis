# -*- coding: utf-8 -*-
# collectors/evidence.py - P36: 実行痕跡解析（5大アーティファクト対応）
# UserAssist / Prefetch / ShimCache / Amcache / BAM
import os
import re
import struct
import winreg
import subprocess
import json
from datetime import datetime, timedelta, timezone
from utils.tutor_template import build_tutor_desc


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
        evidence = []
        evidence.extend(self._scan_userassist())
        evidence.extend(self._scan_prefetch())
        evidence.extend(self._scan_shimcache())
        evidence.extend(self._scan_amcache())
        evidence.extend(self._scan_bam())
        return evidence

    # ==============================================================
    # 共通: 実行パス解析
    # ==============================================================
    def _analyze_exe_path(self, exe_path, source_name, extra_info=""):
        """実行パスから危険度を判定（全アーティファクト共通ロジック）"""
        path_lower = exe_path.lower()
        basename = os.path.basename(path_lower).replace('.exe', '')

        # Rule 1: 攻撃ツール
        for tool in self.attack_tools:
            tb = tool.replace('.exe', '')
            if tb in basename or f'\\{tool}' in path_lower or f'\\{tb}.exe' in path_lower:
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
                            "【異常】100%異常です。インシデント対応が必要です。\n"
                            "【判断基準】攻撃ツールの実行痕跡は誤検知の可能性が極めて低い。"
                        ),
                        next_steps=[
                            "該当パスにファイルがまだ存在するか確認する",
                            "存在する場合ハッシュ値をVirusTotalで検索する",
                            "他のアーティファクト（Prefetch, BAM等）で実行時刻を特定する",
                            "イベントログ(4688)で実行者とコマンドラインを確認する",
                        ],
                        status="DANGER"))

        # Rule 2: LOLBin + 不審パス
        found_lolbin = None
        for lb in self.lolbins:
            if lb.replace('.exe', '') in basename:
                found_lolbin = lb
                break
        if found_lolbin:
            for sp in self.suspicious_paths:
                if sp in path_lower:
                    return ("WARNING", f"LOLBin不審パス: {found_lolbin}",
                        build_tutor_desc(
                            detection=(
                                f"{source_name}にLOLBin「{found_lolbin}」が不審パスから"
                                f"実行された痕跡があります。\nパス: {exe_path}\n{extra_info}"
                            ),
                            why_dangerous=(
                                f"LOLBin（Windows標準ツール）が不審なフォルダから実行されています。"
                                "攻撃者がスクリプトファイルを配置し、LOLBin経由で実行した可能性があります。"
                            ),
                            normal_vs_abnormal=(
                                "【正常】LOLBinはSystem32等の標準パスから実行される。\n"
                                "【異常】Temp/Public/AppData等の不審パスからの実行。"
                            ),
                            next_steps=[
                                "実行されたスクリプトやファイルの内容を確認する",
                                "イベントログ(4104)でPowerShellの実行内容を確認する",
                            ],
                            status="WARNING"))

        # Rule 3: 偵察コマンド
        for recon in self.recon_tools:
            rb = recon.replace('.exe', '')
            if rb in basename:
                return ("WARNING", f"偵察コマンド: {recon}",
                    build_tutor_desc(
                        detection=(
                            f"{source_name}に偵察コマンド「{recon}」の実行痕跡があります。\n"
                            f"パス: {exe_path}\n{extra_info}"
                        ),
                        why_dangerous=(
                            "偵察コマンドは攻撃者が侵入後にネットワーク構成やアカウント情報を"
                            "収集するために使用します。単体では正常な管理作業の可能性もありますが、"
                            "短時間に複数の偵察コマンドが実行されている場合は攻撃の可能性があります。"
                        ),
                        normal_vs_abnormal=(
                            "【正常】管理者がトラブルシューティングで使用。\n"
                            "【異常】短時間に複数の偵察コマンドが連続実行。\n"
                            "【判断基準】同時刻帯の他のアーティファクトと照合する。"
                        ),
                        next_steps=[
                            "同時刻帯に他の偵察コマンドの痕跡がないか確認する",
                            "イベントログ(4688)でコマンドライン引数を確認する",
                        ],
                        status="WARNING"))

        # Rule 4: 不審パスからの実行
        for sp in self.suspicious_paths:
            if sp in path_lower:
                return ("WARNING", f"不審パスからの実行: {sp.strip(chr(92))}",
                    build_tutor_desc(
                        detection=(
                            f"{source_name}に不審なフォルダからプログラムが実行された"
                            f"痕跡があります。\nパス: {exe_path}\n{extra_info}"
                        ),
                        why_dangerous=(
                            f"「{sp.strip(chr(92))}」はユーザー権限で書き込めるフォルダです。"
                            "正規のプログラムはProgram FilesやSystem32から実行されるのが標準です。"
                            "マルウェアはこれらの一時フォルダに配置されて実行されることが多いです。"
                        ),
                        normal_vs_abnormal=(
                            "【正常】インストーラーやアップデータが一時的に使用。\n"
                            "【異常】見覚えのないEXEが不審パスから実行されている。"
                        ),
                        next_steps=[
                            "該当パスにファイルがまだ存在するか確認する",
                            "ファイルのデジタル署名を確認する",
                            "ハッシュ値をVirusTotalで検索する",
                        ],
                        status="WARNING"))

        # Rule 5: 正常
        return ("SAFE", "", "")

    # ==============================================================
    # 1. UserAssist 解析
    # ==============================================================
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
                                    status, reason, desc = self._analyze_exe_path(
                                        decoded, "UserAssist (レジストリ)", extra)
                                    if status == "SAFE":
                                        continue
                                    results.append({
                                        "source": "UserAssist",
                                        "artifact": decoded,
                                        "detail": f"実行回数: {run_count}",
                                        "time": timestamp_str,
                                        "status": status,
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
                try:
                    mtime = os.path.getmtime(filepath)
                    dt = datetime.fromtimestamp(mtime)
                    dt_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    dt_str = ""

                exe_name = re.sub(r'-[A-F0-9]{8}\.pf$', '', filename, flags=re.IGNORECASE)
                extra = f"Prefetchファイル: {filename}"
                if dt_str:
                    extra += f"\n最終更新: {dt_str}"

                status, reason, desc = self._analyze_exe_path(
                    exe_name, "Prefetch (実行キャッシュ)", extra)
                if status == "SAFE":
                    continue
                results.append({
                    "source": "Prefetch",
                    "artifact": exe_name,
                    "detail": filename,
                    "time": dt_str,
                    "status": status,
                    "reason": reason,
                    "desc": desc,
                })
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

                        status, reason, desc = self._analyze_exe_path(
                            exe_path, "ShimCache (AppCompatCache)", extra)
                        if status == "SAFE":
                            continue
                        results.append({
                            "source": "ShimCache",
                            "artifact": exe_path,
                            "detail": f"順序: {entry.get('position', '?')}",
                            "time": timestamp,
                            "status": status,
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
        pattern = rb'(?:[A-Z]:\\[^\x00]{4,200}\.(?:exe|dll|sys))'
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
        results = []
        amcache_path = r"C:\Windows\appcompat\Programs\Amcache.hve"

        if not os.path.exists(amcache_path):
            return results

        # Amcache.hveはロックされているのでesentutlでコピー
        temp_dir = os.environ.get('TEMP', r'C:\Windows\Temp')
        temp_hive = os.path.join(temp_dir, 'amcache_copy.hve')

        try:
            # esentutlでコピー
            subprocess.run(
                ['esentutl', '/y', amcache_path, '/d', temp_hive],
                capture_output=True, timeout=30,
                creationflags=0x08000000)
        except Exception:
            # esentutl失敗時はregコマンドで直接読み取り試行
            return self._scan_amcache_registry(results)

        if not os.path.exists(temp_hive):
            return self._scan_amcache_registry(results)

        try:
            # reg loadでハイブをマウント
            hive_key = "HKLM\\TEMP_AMCACHE"
            subprocess.run(
                ['reg', 'load', hive_key, temp_hive],
                capture_output=True, timeout=15,
                creationflags=0x08000000)

            try:
                # InventoryApplicationFile を列挙
                inv_path = r"TEMP_AMCACHE\Root\InventoryApplicationFile"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inv_path, 0,
                                        winreg.KEY_READ) as inv_key:
                        idx = 0
                        while True:
                            try:
                                app_name = winreg.EnumKey(inv_key, idx)
                                idx += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(inv_key, app_name) as app_key:
                                    lower_path = ""
                                    sha1 = ""
                                    publisher = ""
                                    link_date = ""
                                    try:
                                        v, _ = winreg.QueryValueEx(app_key, "LowerCaseLongPath")
                                        lower_path = str(v)
                                    except OSError:
                                        pass
                                    try:
                                        v, _ = winreg.QueryValueEx(app_key, "FileId")
                                        sha1_raw = str(v)
                                        if sha1_raw.startswith("0000"):
                                            sha1 = sha1_raw[4:]
                                        else:
                                            sha1 = sha1_raw
                                    except OSError:
                                        pass
                                    try:
                                        v, _ = winreg.QueryValueEx(app_key, "Publisher")
                                        publisher = str(v)
                                    except OSError:
                                        pass
                                    try:
                                        v, _ = winreg.QueryValueEx(app_key, "LinkDate")
                                        link_date = str(v)
                                    except OSError:
                                        pass

                                    if not lower_path:
                                        continue

                                    extra = ""
                                    if sha1:
                                        extra += f"SHA1: {sha1}\n"
                                    if publisher:
                                        extra += f"発行者: {publisher}\n"
                                    if link_date:
                                        extra += f"リンク日: {link_date}"

                                    status, reason, desc = self._analyze_exe_path(
                                        lower_path, "Amcache (実行記録+ハッシュ)", extra)
                                    if status == "SAFE":
                                        continue
                                    results.append({
                                        "source": "Amcache",
                                        "artifact": lower_path,
                                        "detail": f"SHA1: {sha1}" if sha1 else app_name,
                                        "time": link_date,
                                        "status": status,
                                        "reason": reason,
                                        "desc": desc,
                                    })
                            except OSError:
                                continue
                except OSError:
                    pass

                # File キーも試行 (古い形式)
                file_path = r"TEMP_AMCACHE\Root\File"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, file_path, 0,
                                        winreg.KEY_READ) as file_key:
                        fidx = 0
                        while True:
                            try:
                                vol = winreg.EnumKey(file_key, fidx)
                                fidx += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(file_key, vol) as vol_key:
                                    eidx = 0
                                    while True:
                                        try:
                                            entry_id = winreg.EnumKey(vol_key, eidx)
                                            eidx += 1
                                        except OSError:
                                            break
                                        try:
                                            with winreg.OpenKey(vol_key, entry_id) as ekey:
                                                fpath = ""
                                                try:
                                                    v, _ = winreg.QueryValueEx(ekey, "15")  # FullPath
                                                    fpath = str(v)
                                                except OSError:
                                                    pass
                                                if not fpath:
                                                    continue
                                                status, reason, desc = self._analyze_exe_path(
                                                    fpath, "Amcache (File)", "")
                                                if status != "SAFE":
                                                    results.append({
                                                        "source": "Amcache",
                                                        "artifact": fpath,
                                                        "detail": entry_id,
                                                        "time": "",
                                                        "status": status,
                                                        "reason": reason,
                                                        "desc": desc,
                                                    })
                                        except OSError:
                                            continue
                            except OSError:
                                continue
                except OSError:
                    pass

            finally:
                # ハイブをアンロード
                subprocess.run(
                    ['reg', 'unload', hive_key],
                    capture_output=True, timeout=15,
                    creationflags=0x08000000)
        except Exception:
            pass
        finally:
            # 一時ファイル削除
            try:
                if os.path.exists(temp_hive):
                    os.remove(temp_hive)
            except Exception:
                pass

        return results

    def _scan_amcache_registry(self, results):
        """Amcacheハイブコピー失敗時のフォールバック: PowerShellで直接読み取り"""
        try:
            ps_cmd = (
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                "$items = @(); "
                "try { "
                "  $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Default'); "
                "  $amKey = $hive.OpenSubKey('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags\\Amcache'); "
                "  if ($amKey) { "
                "    foreach ($sub in $amKey.GetSubKeyNames()) { "
                "      $sk = $amKey.OpenSubKey($sub); "
                "      if ($sk) { "
                "        $p = $sk.GetValue(''); "
                "        if ($p) { $items += $p } "
                "      } "
                "    } "
                "  } "
                "} catch {} "
                "$items | ConvertTo-Json -Compress"
            )
            output = subprocess.check_output(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                text=True, encoding='utf-8', errors='replace',
                timeout=30, creationflags=0x08000000,
                stderr=subprocess.DEVNULL)
            if output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, str):
                        data = [data]
                    for path in data:
                        if path:
                            status, reason, desc = self._analyze_exe_path(
                                str(path), "Amcache (Fallback)", "")
                            if status != "SAFE":
                                results.append({
                                    "source": "Amcache",
                                    "artifact": str(path),
                                    "detail": "PowerShell fallback",
                                    "time": "",
                                    "status": status,
                                    "reason": reason,
                                    "desc": desc,
                                })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return results

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

                                        status, reason, desc = self._analyze_exe_path(
                                            exe_path, "BAM/DAM (実行記録)", extra)
                                        if status == "SAFE":
                                            continue
                                        results.append({
                                            "source": "BAM/DAM",
                                            "artifact": exe_path,
                                            "detail": f"SID: {sid[:20]}...",
                                            "time": timestamp,
                                            "status": status,
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
                        ps_cmd = f"(Get-Partition -DriveLetter {letter}).DiskNumber"
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
