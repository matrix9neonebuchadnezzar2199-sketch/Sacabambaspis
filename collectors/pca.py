# -*- coding: utf-8 -*-
# collectors/pca.py - P8+P16: Program Compatibility Assistant 解析
# 手順書 §4.3 準拠: 削除済みツールの実行証跡を取得
# ERR-PCA-001〜003: PCA解析エラー系
import os
from datetime import datetime
from utils.tutor_template import build_tutor_desc


class PCACollector:
    def __init__(self):
        self.pca_path = r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"
        self.pca_general_path = r"C:\Windows\appcompat\pca\PcaGeneralDb0.txt"

        self.suspicious_paths = [
            'users\\public', '\\temp', '\\appdata\\local\\temp',
            '\\downloads', 'recycle.bin', '\\perflogs',
            '\\programdata', '\\music', '\\videos',
        ]

        self.suspicious_tools = [
            'mimikatz', 'lazagne', 'psexec', 'procdump',
            'rubeus', 'sharphound', 'bloodhound', 'covenant',
            'cobalt', 'beacon', 'meterpreter', 'nmap',
            'netcat', 'nc.exe', 'nc64.exe', 'wce.exe',
            'pwdump', 'fgdump', 'gsecdump', 'secretsdump',
            'crackmapexec', 'impacket', 'chisel', 'plink',
            'putty', 'winscp', 'rclone', 'megacmd',
            'winrar', '7z.exe', 'rar.exe',
        ]

    def scan(self):
        results = []
        results.extend(self._parse_pca_file(self.pca_path, "PcaAppLaunchDic"))
        results.extend(self._parse_pca_file(self.pca_general_path, "PcaGeneralDb"))
        return sorted(results, key=lambda x: x.get('timestamp', ''), reverse=True)

    def _parse_pca_file(self, filepath, source_name):
        """PCAログファイルを解析"""
        entries = []
        if not os.path.exists(filepath):
            return []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split('|')
                    if len(parts) >= 2:
                        exe_path = parts[0].strip()
                        timestamp_raw = parts[1].strip() if len(parts) > 1 else ''
                    else:
                        exe_path = line
                        timestamp_raw = ''

                    timestamp = self._parse_timestamp(timestamp_raw)
                    exe_name = os.path.basename(exe_path).lower()
                    status, reason, desc = self._analyze_entry(exe_path, exe_name)
                    file_exists = os.path.exists(exe_path)
                    existence_note = "ファイル存在" if file_exists else "ファイル削除済み"

                    entries.append({
                        "source": source_name,
                        "artifact": exe_path,
                        "exe_name": exe_name,
                        "timestamp": timestamp,
                        "file_exists": file_exists,
                        "existence": existence_note,
                        "status": status,
                        "reason": reason,
                        "desc": desc,
                        "is_self": False,
                    })

        except PermissionError:
            pass
        except Exception:
            pass
        return entries

    def _analyze_entry(self, exe_path, exe_name):
        """実行痕跡を解析し、脅威レベルを判定"""
        path_lower = exe_path.lower()
        file_exists = os.path.exists(exe_path)

        # 1. 既知の攻撃ツール名との照合
        for tool in self.suspicious_tools:
            if tool in exe_name:
                return (
                    "DANGER",
                    f"攻撃ツール検知: {tool}",
                    build_tutor_desc(
                        detection=(
                            f"攻撃で使用される既知のツール「{tool}」の実行痕跡が"
                            f"PCAログに記録されています。\n"
                            f"パス: {exe_path}\n"
                            f"ファイル状態: {'存在' if file_exists else '削除済み'}"
                        ),
                        why_dangerous=(
                            f"「{tool}」は侵入テスト/攻撃に使用されるツールです。"
                            "PCA(Program Compatibility Assistant)はWindows 11 22H2以降で"
                            "アプリケーションの実行履歴を自動記録します。"
                            "攻撃者はツール使用後にファイルを削除して証拠隠滅を図りますが、"
                            "PCAログには痕跡が残り続けます。"
                            "Prefetchファイルより長期間保持される傾向があり、"
                            "フォレンジック上非常に価値の高いアーティファクトです。"
                        ),
                        mitre_key="pca_attack_tool",
                        normal_vs_abnormal=(
                            "【正常】社内で承認されたペネトレーションテスト中にのみ使用。"
                            "テスト期間・ツール使用が事前に承認されている場合。\n"
                            "【異常】予定外の攻撃ツール実行痕跡は侵害の強い証拠。"
                            "特にファイルが削除済みの場合、攻撃者が証拠隠滅を図った可能性大。\n"
                            "【判断基準】セキュリティチームに承認済みテストか確認。"
                            "削除済みなら攻撃者による証拠隠滅の可能性が極めて高い。"
                        ),
                        next_steps=[
                            "ファイルが存在する場合、ハッシュ値を取得しVirusTotalで検索する",
                            "削除済みの場合、Prefetch/AmCache等で同名ファイルの追加痕跡を探す",
                            "実行時間帯の前後で不審なネットワーク通信がなかったか確認する",
                            "「イベントログ」タブで同時刻のログオン・プロセス作成を確認する",
                            "「永続化」タブで同時期に登録された自動起動がないか確認する",
                        ],
                        status="DANGER",
                    ),
                )

        # 2. 不審なパスからの実行
        for bad_path in self.suspicious_paths:
            if bad_path in path_lower:
                return (
                    "WARNING",
                    f"不審パスからの実行: {bad_path}",
                    build_tutor_desc(
                        detection=(
                            f"不審なフォルダから実行されたプログラムの痕跡です。\n"
                            f"パス: {exe_path}\n"
                            f"ファイル状態: {'存在' if file_exists else '削除済み'}\n"
                            f"該当パターン: {bad_path}"
                        ),
                        why_dangerous=(
                            f"「{bad_path}」はユーザー権限で書き込みが可能なフォルダです。"
                            "マルウェアはC:\\Windows\\System32等の保護されたフォルダではなく、"
                            "Temp、Downloads、Users\\Public、ProgramData等に展開されます。"
                            "正規のソフトウェアはProgram Files配下にインストールされるのが標準です。"
                        ),
                        mitre_key="pca_suspicious_path",
                        normal_vs_abnormal=(
                            "【正常】インストーラーがTempフォルダで一時展開する場合、"
                            "ユーザーがDownloadsから直接実行する場合（自覚がある場合）。\n"
                            "【異常】見覚えのないexeがTemp/Public/ProgramDataで実行された場合。"
                            "特にファイルが削除済みの場合は攻撃ツールの痕跡の可能性。\n"
                            "【判断基準】自分でダウンロード・実行した記憶があるか？"
                        ),
                        next_steps=[
                            "ファイルが存在する場合、プロパティでデジタル署名を確認する",
                            "実行時期がインシデント発生時期と一致するか確認する",
                            "「ADS追跡」タブで同名ファイルのダウンロード元を確認する",
                        ],
                        status="WARNING",
                    ),
                )

        # 3. 正常
        return (
            "SAFE",
            "",
            build_tutor_desc(
                detection=(
                    f"プログラムの実行痕跡がPCAログに記録されています。\n"
                    f"パス: {exe_path}"
                ),
                why_dangerous="",
                normal_vs_abnormal=(
                    "正規のインストール先(Program Files等)から実行されたプログラムです。"
                    "不審な点は検出されませんでした。"
                ),
                status="SAFE",
            ),
        )

    def _parse_timestamp(self, raw):
        """複数のタイムスタンプ形式に対応"""
        if not raw:
            return "Unknown"
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(raw[:19], fmt)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, IndexError):
                continue
        try:
            filetime = int(raw)
            timestamp = (filetime - 116444736000000000) / 10000000
            if timestamp > 0:
                dt = datetime.fromtimestamp(timestamp)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError):
            pass
        return raw[:30]
