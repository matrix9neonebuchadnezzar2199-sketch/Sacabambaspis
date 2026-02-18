# -*- coding: utf-8 -*-
# collectors/ads.py - P8+P16: Zone.Identifier (Alternate Data Streams) 解析
# 手順書 §5 ステップ2 準拠: ダウンロード元URL追跡
# ERR-ADS-001〜003: ADS解析エラー系
import os
import glob
from utils.tutor_template import build_tutor_desc


class ADSCollector:
    def __init__(self):
        self.scan_dirs = []
        user_profile = os.environ.get('USERPROFILE', '')
        if user_profile:
            self.scan_dirs = [
                os.path.join(user_profile, 'Downloads'),
                os.path.join(user_profile, 'Desktop'),
                os.path.join(user_profile, 'Documents'),
                os.path.join(user_profile, 'AppData', 'Local', 'Temp'),
            ]
        self.scan_dirs.extend([
            r'C:\Users\Public',
            r'C:\Users\Public\Downloads',
            r'C:\Users\Public\Music',
            r'C:\Users\Public\Videos',
        ])

        self.target_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.msi', '.scr', '.hta', '.wsf', '.jar',
            '.zip', '.rar', '.7z', '.iso', '.img',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.lnk',
        ]

        self.zone_names = {
            '0': 'ローカルPC',
            '1': 'イントラネット',
            '2': '信頼済みサイト',
            '3': 'インターネット',
            '4': '制限付きサイト',
        }

    def scan(self):
        results = []
        for scan_dir in self.scan_dirs:
            if not os.path.exists(scan_dir):
                continue
            results.extend(self._scan_directory(scan_dir))

        results.sort(key=lambda x: (
            0 if x['status'] == 'DANGER' else (1 if x['status'] == 'WARNING' else 2),
            x.get('timestamp', '')
        ), reverse=False)
        return results[:200]

    def _scan_directory(self, directory):
        """指定ディレクトリ内のファイルのZone.Identifierを解析"""
        entries = []
        try:
            for root, dirs, files in os.walk(directory):
                depth = root.replace(directory, '').count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue

                for filename in files:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in self.target_extensions:
                        continue

                    filepath = os.path.join(root, filename)
                    ads_path = filepath + ':Zone.Identifier'

                    try:
                        if not os.path.exists(filepath):
                            continue

                        ads_data = self._read_ads(ads_path)
                        if not ads_data:
                            continue

                        zone_id = ads_data.get('ZoneId', '')
                        referrer_url = ads_data.get('ReferrerUrl', '')
                        host_url = ads_data.get('HostUrl', '')

                        try:
                            file_stat = os.stat(filepath)
                            file_size = file_stat.st_size
                            file_mtime = os.path.getmtime(filepath)
                            from datetime import datetime
                            timestamp = datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        except OSError:
                            file_size = 0
                            timestamp = 'Unknown'

                        status, reason, desc = self._analyze_ads(
                            filename, filepath, zone_id, referrer_url, host_url
                        )
                        zone_name = self.zone_names.get(zone_id, f'不明(Zone:{zone_id})')

                        entries.append({
                            "source": "Zone.Identifier (ADS)",
                            "artifact": filename,
                            "filepath": filepath,
                            "zone_id": zone_id,
                            "zone_name": zone_name,
                            "referrer_url": referrer_url or '(なし)',
                            "host_url": host_url or '(なし)',
                            "file_size": f"{file_size / 1024:.1f} KB" if file_size else 'Unknown',
                            "timestamp": timestamp,
                            "status": status,
                            "reason": reason,
                            "desc": desc,
                            "is_self": False,
                        })

                    except (PermissionError, OSError):
                        # ERR-ADS-002
                        continue

        except PermissionError:
            # ERR-ADS-001
            pass
        except Exception:
            # ERR-ADS-003
            pass
        return entries

    def _read_ads(self, ads_path):
        """Zone.Identifier ADSを読み取ってパース"""
        try:
            with open(ads_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (FileNotFoundError, PermissionError, OSError):
            return None
        if not content.strip():
            return None
        data = {}
        for line in content.split('\n'):
            line = line.strip()
            if '=' in line:
                key, _, value = line.partition('=')
                data[key.strip()] = value.strip()
        return data if data else None

    def _analyze_ads(self, filename, filepath, zone_id, referrer_url, host_url):
        """Zone.Identifierの情報を解析して脅威レベルを判定"""
        ext = os.path.splitext(filename)[1].lower()

        # 実行可能ファイルがインターネットからダウンロード
        if zone_id in ('3', '4'):
            if ext in ('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1',
                       '.vbs', '.js', '.hta', '.wsf', '.msi'):
                return (
                    "DANGER",
                    f"インターネットからの実行ファイル (Zone:{zone_id})",
                    build_tutor_desc(
                        detection=(
                            f"実行可能ファイル「{filename}」がインターネット(Zone:{zone_id})から"
                            f"ダウンロードされています。\n"
                            f"ダウンロード元: {host_url or '不明'}\n"
                            f"参照元: {referrer_url or '不明'}\n"
                            f"保存先: {filepath}"
                        ),
                        why_dangerous=(
                            "インターネットからダウンロードされた実行ファイルは"
                            "マルウェアの最も一般的な侵入経路です。"
                            "フィッシングメールのリンク、改ざんされたWebサイト、"
                            "偽のソフトウェアアップデートなどを通じて配布されます。"
                            "Zone.Identifierはダウンロード元の記録であり、"
                            "ファイルの出所を追跡する重要な証拠です。"
                        ),
                        mitre_key="ads_inet_exe",
                        normal_vs_abnormal=(
                            "【正常】自分で意図的にダウンロードした既知のソフトウェア"
                            "（公式サイトから取得、ハッシュ値を確認済み）。\n"
                            "【異常】見覚えのないファイル名、ランダムな文字列のファイル名、"
                            "不審なURL(短縮URL、無料ホスティング等)からのダウンロード。"
                            "Temp/Public等の共有フォルダへの保存。\n"
                            "【判断基準】自分がダウンロードした記憶があるか？"
                            "ダウンロード元URLは信頼できるドメインか？"
                        ),
                        next_steps=[
                            "ファイルのハッシュ値(SHA-256)を取得し、VirusTotalで検索する",
                            f"ダウンロード元URL「{host_url or '不明'}」の評判を確認する",
                            "「永続化」タブでこのファイルが自動起動に登録されていないか確認する",
                            "「プロセス」タブでこのファイルが現在実行中でないか確認する",
                            "「ネットワーク」タブでこのファイルの外部通信を確認する",
                        ],
                        status="DANGER",
                    ),
                )

            # アーカイブファイル
            if ext in ('.zip', '.rar', '.7z', '.iso', '.img'):
                return (
                    "WARNING",
                    f"インターネットからのアーカイブ (Zone:{zone_id})",
                    build_tutor_desc(
                        detection=(
                            f"アーカイブファイル「{filename}」がインターネットからダウンロードされています。\n"
                            f"ダウンロード元: {host_url or '不明'}\n"
                            f"保存先: {filepath}"
                        ),
                        why_dangerous=(
                            "攻撃者はマルウェアをZIP/RAR内に隠して配布します。"
                            "特にISO/IMGファイルはWindowsでダブルクリックするとマウントされ、"
                            "内部の実行ファイルにはMark-of-the-Web(MOTW)が付与されないため、"
                            "SmartScreenのブロックを回避できます。"
                            "パスワード付きZIPはセキュリティソフトのスキャンも回避します。"
                        ),
                        mitre_key="ads_inet_archive",
                        normal_vs_abnormal=(
                            "【正常】業務で使用するソフトウェアのZIP配布、"
                            "自分で作成したアーカイブのバックアップ。\n"
                            "【異常】メールで受信したパスワード付きZIP、"
                            "見覚えのないISO/IMGファイル、"
                            "ダウンロード直後に展開・実行された形跡がある場合。\n"
                            "【判断基準】このアーカイブの入手経路と目的を説明できるか？"
                        ),
                        next_steps=[
                            "アーカイブ内に実行ファイル(.exe/.dll/.bat等)が含まれていないか確認する",
                            "ダウンロード時期がインシデント発生時期と一致するか確認する",
                            "ISO/IMGの場合、マウント痕跡（イベントログ）を確認する",
                        ],
                        status="WARNING",
                    ),
                )

            # Officeファイル
            if ext in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'):
                return (
                    "WARNING",
                    f"インターネットからのOfficeファイル (Zone:{zone_id})",
                    build_tutor_desc(
                        detection=(
                            f"Officeファイル「{filename}」がインターネットからダウンロードされています。\n"
                            f"参照元: {referrer_url or '不明'}\n"
                            f"保存先: {filepath}"
                        ),
                        why_dangerous=(
                            "Officeファイルにはマクロ（VBA）が埋め込まれている可能性があります。"
                            "「コンテンツの有効化」をクリックすると悪意のあるマクロが実行され、"
                            "マルウェアのダウンロードやバックドアの設置が行われます。"
                            "近年はOffice365のProtected Viewにより保護されますが、"
                            "ユーザーが保護を解除するソーシャルエンジニアリングも多発しています。"
                        ),
                        mitre_key="ads_inet_office",
                        normal_vs_abnormal=(
                            "【正常】業務で受信した既知の送信者からのOffice文書。\n"
                            "【異常】不明な送信者からの添付ファイル、"
                            "「マクロを有効にしてください」等の指示が文書内にある場合、"
                            ".doc/.xls（旧形式）は.docx/.xlsxより危険度が高い。\n"
                            "【判断基準】送信者は信頼できるか？マクロを有効化したか？"
                        ),
                        next_steps=[
                            "ファイルを開いた後に不審なプロセスが起動していないか確認する",
                            "「プロセス」タブでWINWORD.EXE/EXCEL.EXEの子プロセスを確認する",
                            "「イベントログ」タブでマクロ実行(4104: PowerShell)の痕跡を確認する",
                        ],
                        status="WARNING",
                    ),
                )

            # PDF/LNKファイル
            if ext in ('.pdf', '.lnk'):
                return (
                    "WARNING",
                    f"インターネットからの{ext}ファイル (Zone:{zone_id})",
                    build_tutor_desc(
                        detection=(
                            f"ファイル「{filename}」がインターネットからダウンロードされています。\n"
                            f"ダウンロード元: {host_url or '不明'}\n"
                            f"保存先: {filepath}"
                        ),
                        why_dangerous=(
                            "PDFファイルにはJavaScriptや埋め込みオブジェクトが含まれる場合があり、"
                            "脆弱なPDFリーダーでの開封時にコード実行される可能性があります。"
                            "LNKファイル（ショートカット）は任意のコマンドを実行でき、"
                            "PowerShellダウンローダーの起動に悪用されるケースが急増しています。"
                            if ext == '.pdf' else
                            "LNKファイル（ショートカット）はアイコンを偽装でき、"
                            "ダブルクリックで任意のコマンド（PowerShell等）を実行できます。"
                            "近年のフィッシング攻撃ではLNKが主要な初期侵入手段です。"
                        ),
                        normal_vs_abnormal=(
                            "【正常】自分がダウンロードしたPDF文書。\n"
                            "【異常】メール添付のLNKファイルは高確率で悪意あり。"
                            "PDFを開いた直後にPowerShellやcmd.exeが起動した場合は攻撃。\n"
                            "【判断基準】LNKファイルのダウンロードは原則として異常。"
                        ),
                        next_steps=[
                            "LNKの場合: プロパティ→リンク先でコマンドを確認する",
                            "PDFの場合: Adobe Reader等を最新版にアップデートして開く",
                            "開封直後に新しいプロセスが起動していないか確認する",
                        ],
                        status="WARNING",
                    ),
                )

        # Zone 0-2 または不明: SAFE
        return "SAFE", "", ""
