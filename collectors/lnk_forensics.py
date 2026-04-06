# -*- coding: utf-8 -*-
# collectors/lnk_forensics.py - P44: LNKファイル不審属性解析 (Velociraptor Windows.Forensics.Lnk移植)
# Recent/Startup/Desktop の .lnk ファイルを解析し、30種以上の不審属性を自動判定
import os
import struct
import glob
import re
from datetime import datetime
from utils.tutor_template import build_tutor_desc
from utils import threat_lists as _tl


class LnkForensicsCollector:
    def __init__(self):
        self.target_globs = [
            os.path.expandvars(r'%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\*.lnk'),
            os.path.expandvars(r'%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk'),
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk',
            os.path.expandvars(r'%USERPROFILE%\Desktop\*.lnk'),
        ]
        users_root = os.path.join(os.environ.get('SystemDrive', 'C:') + os.sep, 'Users')
        if os.path.isdir(users_root):
            skip = {'public', 'default', 'default user', 'all users', 'desktop.ini'}
            for entry in os.listdir(users_root):
                if entry.lower() in skip or not entry:
                    continue
                home = os.path.join(users_root, entry)
                if not os.path.isdir(home):
                    continue
                self.target_globs.append(
                    os.path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent', '*.lnk')
                )
                self.target_globs.append(
                    os.path.join(
                        home,
                        'AppData',
                        'Roaming',
                        'Microsoft',
                        'Windows',
                        'Start Menu',
                        'Programs',
                        'Startup',
                        '*.lnk',
                    )
                )
                self.target_globs.append(os.path.join(home, 'Desktop', '*.lnk'))

        # 不審引数パターン (Velociraptor SusArgRegex移植)
        self.sus_arg_re = re.compile(
            r'\\AppData\\|\\Users\\Public\\|\\Temp\\|comspec|&cd&echo'
            r'| -NoP | -W Hidden | [-/]decode'
            r'| -e.* (JAB|SUVYI|SQBFAFgA|aWV4I|aQBlAHgA)'
            r'|start\s*[\\/]b|\.downloadstring\(|\.downloadfile\(|iex',
            re.IGNORECASE
        )

        # 危険なターゲットEXE (Velociraptor RiskyExe移植)
        self.risky_exe_re = re.compile(
            r'\\(cmd|powershell|cscript|wscript|rundll32|regsvr32|mshta|wmic|conhost)\.exe$',
            re.IGNORECASE
        )

        # 不審ホスト名 (Velociraptor SusHostnameRegex移植)
        self.sus_hostname_re = re.compile(r'^(Win-|Desktop-|Commando$)', re.IGNORECASE)

        # VM MACアドレスプレフィックス
        self.vm_mac_re = re.compile(
            r'^(00:50:56|00:0C:29|00:05:69|00:1C:14|08:00:27|52:54:00|00:21:F6|00:15:5D)',
            re.IGNORECASE
        )

        # ShowCommand定数
        self.SHOW_COMMANDS = {1: 'SHOWNORMAL', 3: 'SHOWMAXIMIZED', 7: 'SHOWMINNOACTIVE'}

        # ローカルホスト名（誤検知除外用）
        import socket
        self._local_hostname = socket.gethostname().lower()

        self.SUS_SIZE = 20000
        self.SUS_ARG_SIZE = 250

    def scan(self):
        results = []
        seen = set()

        for pattern in self.target_globs:
            for lnk_path in glob.glob(pattern):
                if lnk_path.lower() in seen:
                    continue
                seen.add(lnk_path.lower())

                try:
                    parsed = self._parse_lnk(lnk_path)
                    if not parsed:
                        continue

                    suspicious = self._analyze_suspicious(parsed, lnk_path)
                    if suspicious:
                        results.append(suspicious)
                except Exception:
                    continue

        return results

    def _parse_lnk(self, lnk_path):
        """LNKファイルをバイナリパースする"""
        try:
            with open(lnk_path, 'rb') as f:
                data = f.read()
        except (PermissionError, OSError):
            return None

        if len(data) < 76:
            return None

        # ShellLinkHeader (76 bytes)
        header_size = struct.unpack_from('<I', data, 0)[0]
        if header_size != 0x4C:
            return None

        link_flags = struct.unpack_from('<I', data, 20)[0]
        file_attrs = struct.unpack_from('<I', data, 24)[0]
        creation_time = self._filetime_to_dt(struct.unpack_from('<Q', data, 28)[0])
        access_time = self._filetime_to_dt(struct.unpack_from('<Q', data, 36)[0])
        write_time = self._filetime_to_dt(struct.unpack_from('<Q', data, 44)[0])
        file_size = struct.unpack_from('<I', data, 52)[0]
        show_command = struct.unpack_from('<I', data, 60)[0]

        result = {
            'lnk_path': lnk_path,
            'lnk_name': os.path.basename(lnk_path),
            'lnk_size': len(data),
            'link_flags': link_flags,
            'file_attrs': file_attrs,
            'creation_time': creation_time,
            'access_time': access_time,
            'write_time': write_time,
            'target_size': file_size,
            'show_command': self.SHOW_COMMANDS.get(show_command, str(show_command)),
            'target_path': '',
            'arguments': '',
            'working_dir': '',
            'icon_location': '',
            'relative_path': '',
            'name_string': '',
            'tracker_hostname': '',
            'tracker_mac': '',
        }

        offset = 76

        # LinkTargetIDList
        has_id_list = link_flags & 0x01
        if has_id_list and offset + 2 <= len(data):
            id_list_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2 + id_list_size

        # LinkInfo
        has_link_info = link_flags & 0x02
        if has_link_info and offset + 4 <= len(data):
            link_info_size = struct.unpack_from('<I', data, offset)[0]
            if link_info_size > 0:
                # LocalBasePathを抽出
                if offset + 16 <= len(data):
                    li_flags = struct.unpack_from('<I', data, offset + 8)[0]
                    if li_flags & 0x01:  # VolumeIDAndLocalBasePath
                        lbp_offset = struct.unpack_from('<I', data, offset + 16)[0]
                        if lbp_offset > 0:
                            abs_offset = offset + lbp_offset
                            if abs_offset < len(data):
                                end = data.index(b'\x00', abs_offset) if b'\x00' in data[abs_offset:] else len(data)
                                result['target_path'] = data[abs_offset:end].decode('ascii', errors='replace')
                offset += link_info_size

        # StringData (unicode)
        is_unicode = link_flags & 0x80
        enc = 'utf-16-le' if is_unicode else 'ascii'
        char_size = 2 if is_unicode else 1

        string_fields = [
            ('has', 0x04, 'name_string'),
            ('has', 0x08, 'relative_path'),
            ('has', 0x10, 'working_dir'),
            ('has', 0x20, 'arguments'),
            ('has', 0x40, 'icon_location'),
        ]

        for _, flag_bit, field_name in string_fields:
            if link_flags & flag_bit:
                if offset + 2 > len(data):
                    break
                count = struct.unpack_from('<H', data, offset)[0]
                offset += 2
                byte_len = count * char_size
                if offset + byte_len <= len(data):
                    raw = data[offset:offset + byte_len]
                    try:
                        result[field_name] = raw.decode(enc, errors='replace')
                    except Exception:
                        result[field_name] = ''
                offset += byte_len

        # ExtraData - TrackerDataBlock
        self._parse_extra_data(data, offset, result)

        return result

    def _parse_extra_data(self, data, offset, result):
        """ExtraDataブロックからTrackerDataBlockを解析"""
        while offset + 8 <= len(data):
            block_size = struct.unpack_from('<I', data, offset)[0]
            if block_size < 4:
                break
            if offset + block_size > len(data):
                break

            block_sig = struct.unpack_from('<I', data, offset + 4)[0]

            # TrackerDataBlock signature = 0xA0000003
            if block_sig == 0xA0000003 and block_size >= 96:
                # MachineID at offset+16, 16 bytes null-terminated ASCII
                machine_raw = data[offset + 16:offset + 32]
                null_idx = machine_raw.find(b'\x00')
                if null_idx >= 0:
                    machine_raw = machine_raw[:null_idx]
                result['tracker_hostname'] = machine_raw.decode('ascii', errors='replace')

                # MAC address at offset+32+16 = offset+48 (in DROID volume ID)
                # Actually MAC is at the end of the new object ID (offset+80, 6 bytes)
                if offset + 86 <= len(data):
                    mac_bytes = data[offset + 80:offset + 86]
                    result['tracker_mac'] = ':'.join(f'{b:02X}' for b in mac_bytes)

            offset += block_size

    def _filetime_to_dt(self, ft):
        """Windows FILETIME → datetime string"""
        if ft == 0:
            return ''
        try:
            ts = (ft - 116444736000000000) / 10000000
            if ts < 0 or ts > 4102444800:
                return ''
            return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        except (OSError, OverflowError, ValueError):
            return ''

    def _analyze_suspicious(self, parsed, lnk_path):
        """Velociraptor の30種以上の不審属性チェックを移植"""
        flags = []
        severity = 'INFO'

        lnk_dir = lnk_path.lower()
        target = parsed.get('target_path', '')
        args = parsed.get('arguments', '')
        name_str = parsed.get('name_string', '')
        hostname = parsed.get('tracker_hostname', '')
        mac = parsed.get('tracker_mac', '')

        # 1. 大きなLNKファイル
        if parsed['lnk_size'] > self.SUS_SIZE:
            flags.append('大容量LNK')

        # 2. Startupフォルダに配置（単体ではINFO、他フラグ併用でWARNING）
        is_startup = '\\startup\\' in lnk_dir
        if is_startup:
            flags.append('Startupフォルダ')

        # 3. 隠しウィンドウ実行
        if parsed['show_command'] == 'SHOWMINNOACTIVE':
            flags.append('隠しウィンドウ実行')
            severity = max_severity(severity, 'DANGER')

        # 4. 危険なターゲットEXE
        if target and self.risky_exe_re.search(target):
            flags.append(f'危険ターゲット: {os.path.basename(target)}')
            severity = max_severity(severity, 'WARNING')

        # 5. 引数の不審パターン
        if args and self.sus_arg_re.search(args):
            flags.append('不審な引数パターン')
            severity = max_severity(severity, 'DANGER')

        # 6. 巨大引数
        if len(args) > self.SUS_ARG_SIZE:
            flags.append(f'巨大引数 ({len(args)}文字)')
            severity = max_severity(severity, 'WARNING')

        # 7. 引数にBase64
        b64_re = re.compile(r'[A-Za-z0-9+/=]{40,}')
        if args and b64_re.search(args):
            flags.append('Base64エンコード検知')
            severity = max_severity(severity, 'DANGER')

        # 8. 引数にHTTP URL
        if args and re.search(r'https?://', args, re.IGNORECASE):
            flags.append('HTTP URL in 引数')
            severity = max_severity(severity, 'WARNING')

        # 9. 引数にUNCパス
        if args and re.search(r'\\\\[^\\]', args):
            flags.append('UNCパス in 引数')
            severity = max_severity(severity, 'WARNING')

        # 10. 引数にチック (バッククォート)
        if args and '`' in args:
            flags.append('バッククォート in 引数')
            severity = max_severity(severity, 'WARNING')

        # 11. 引数に環境変数
        if args and re.search(r'%[^%]+%|\$env:', args, re.IGNORECASE):
            flags.append('環境変数 in 引数')

        # 12. 引数に難読化文字
        if args and re.search(r'[\?\!\~\@]', args):
            flags.append('難読化文字 in 引数')

        # 13. 引数に先頭スペース
        if args and args.startswith('   '):
            flags.append('先頭スペース (難読化)')
            severity = max_severity(severity, 'WARNING')

        # 14. Name文字列に改行
        if name_str and '\n' in name_str:
            flags.append('Name文字列に改行')

        # 15. 不審ホスト名 (TrackerData) ※ローカルホスト名は除外
        if hostname and self.sus_hostname_re.search(hostname):
            if hostname.lower() != self._local_hostname:
                flags.append(f'不審ホスト名: {hostname}')
                severity = max_severity(severity, 'WARNING')

        # 16. VM内で作成 (MACプレフィックス)
        if mac and self.vm_mac_re.search(mac):
            flags.append(f'VM作成: {mac}')

        # 17. タイムスタンプ異常（CreationTime が 0）
        if parsed.get('creation_time') == '' and parsed.get('write_time') != '':
            flags.append('作成時刻ゼロ (タイムスタンプ改ざん疑い)')
            severity = max_severity(severity, 'WARNING')

        # 18. relative_path: threat_lists.SUSPICIOUS_PATH_FRAGMENTS と整合
        rp = parsed.get('relative_path', '')
        if rp and _tl.path_contains_suspicious_fragment(rp.replace("/", "\\").lower()):
            flags.append('不審パス断片を含む相対パス')
            severity = max_severity(severity, 'WARNING')

        # Startupフォルダ単体はINFO、他フラグ併用ならWARNING以上に昇格
        if is_startup and len(flags) > 1:
            severity = max_severity(severity, 'WARNING')
        elif is_startup and len(flags) == 1 and severity == 'INFO':
            severity = 'INFO'

        # フラグなし → スキップ（正常）
        if not flags:
            return None

        # 結果構築
        flag_str = ', '.join(flags)
        reason = f'LNK不審属性: {flag_str}'

        mitre_key = 'lnk_startup' if '\\startup\\' in lnk_dir else 'lnk_suspicious'

        detection = f'LNKファイル "{parsed["lnk_name"]}" に不審属性を検出: {flag_str}'
        why = (
            'LNKファイルは攻撃の初期侵入手段として多用されます。'
            'フィッシングメールの添付やUSBドロップで配布され、'
            'PowerShellやcmd.exeを隠しウィンドウで実行するものが典型的です。'
        )
        normal_vs = (
            f'正常: アプリケーションへの標準ショートカット / '
            f'異常: {flag_str}'
        )
        next_steps = [
            f'LNKファイル "{lnk_path}" の作成日時とアクセス日時を確認',
            f'ターゲット "{target}" が正規のアプリケーションか検証',
            '引数にエンコード文字列があれば Base64 デコードして内容を確認',
            '同時期のイベントログ (Event ID 4688/4104) で関連プロセスを確認',
        ]

        desc = build_tutor_desc(
            detection=detection,
            why_dangerous=why,
            mitre_key=mitre_key,
            normal_vs_abnormal=normal_vs,
            next_steps=next_steps,
        )

        return {
            'status': severity,
            'lnk_name': parsed['lnk_name'],
            'lnk_path': lnk_path,
            'target_path': target or '-',
            'arguments': args[:200] if args else '-',
            'working_dir': parsed.get('working_dir', '-') or '-',
            'show_command': parsed['show_command'],
            'creation_time': parsed.get('creation_time', '-') or '-',
            'access_time': parsed.get('access_time', '-') or '-',
            'write_time': parsed.get('write_time', '-') or '-',
            'tracker_hostname': hostname or '-',
            'tracker_mac': mac or '-',
            'suspicious_flags': flag_str,
            'reason': reason,
            'desc': desc,
            'source': 'LNK Forensics',
            'artifact': lnk_path,
            'mitre': 'T1547.001' if '\\startup\\' in lnk_dir else 'T1204.002',
        }


def max_severity(current, new):
    order = {'INFO': 0, 'WARNING': 1, 'DANGER': 2}
    return new if order.get(new, 0) > order.get(current, 0) else current