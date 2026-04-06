# -*- coding: utf-8 -*-
# collectors/wsl.py - P8+P16: Windows Subsystem for Linux 検知
# 手順書 §4.4 準拠: WSL経由の攻撃活動を検知
# ERR-WSL-001〜004: WSL検知エラー系
import os
import glob
import subprocess
from datetime import datetime
from utils.tutor_template import build_tutor_desc


class WSLCollector:
    def __init__(self):
        self.local_appdata = os.environ.get('LOCALAPPDATA', '')
        self.user_profile = os.environ.get('USERPROFILE', '')

        self.known_distros = [
            'CanonicalGroupLimited.Ubuntu',
            'CanonicalGroupLimited.Ubuntu20.04onWindows',
            'CanonicalGroupLimited.Ubuntu22.04LTS',
            'CanonicalGroupLimited.Ubuntu24.04LTS',
            'TheDebianProject.DebianGNULinux',
            'KaliLinux',
            'SUSE',
            'openSUSE',
            'WhitewaterFoundryLtd',
        ]

        self.suspicious_commands = [
            'curl ', 'wget ', 'python -c', 'python3 -c',
            'nc ', 'ncat ', 'netcat ',
            'nmap ', 'masscan ',
            '/dev/tcp/', '/dev/udp/',
            'base64 -d', 'base64 --decode',
            'chmod +x', 'chmod 777',
            '/tmp/', 'mkfifo',
            'reverse', 'shell', 'bind',
            'ssh -R', 'ssh -L', 'ssh -D',
            'socat ', 'cryptsetup',
            'dd if=', 'tcpdump',
            'iptables', 'passwd',
        ]

    def scan(self):
        results = []
        wsl_installed = self._check_wsl_installed()
        results.append(wsl_installed)

        if wsl_installed['status'] != 'SAFE' or wsl_installed.get('wsl_found'):
            results.extend(self._find_distros())
            results.extend(self._find_vhdx_files())
            results.extend(self._analyze_wsl_history())
            results.extend(self._check_vmmem())

        return results

    def _check_wsl_installed(self):
        """WSLのインストール状態を確認"""
        try:
            result = subprocess.run(
                ['wsl', '--status'],
                capture_output=True, text=True, timeout=10,
                creationflags=0x08000000,
                encoding='utf-8', errors='ignore'
            )
            output = result.stdout + result.stderr

            if 'Windows Subsystem for Linux' in output or result.returncode == 0:
                return {
                    "source": "WSL Status",
                    "artifact": "WSLがインストールされています",
                    "detail": output[:300].strip(),
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "status": "WARNING",
                    "reason": "WSL環境が有効",
                    "desc": build_tutor_desc(
                        detection=(
                            "このPCにWindows Subsystem for Linux (WSL)が"
                            "インストールされています。"
                        ),
                        why_dangerous=(
                            "WSL2はLinux仮想マシンを内蔵しており、"
                            "Windows側のアンチウイルスやEDRの検知を回避する"
                            "攻撃経路として悪用される可能性があります"
                            "（Living off the Land with WSL）。"
                            "WSL内のファイルシステム(ext4.vhdx)は通常の"
                            "Windowsツールでは直接スキャンできず、"
                            "攻撃者がマルウェアやツールを隠す場所として最適です。"
                            "また、WSL内からWindowsファイルシステムへの"
                            "アクセスも可能なため、データ窃取の経路にもなります。"
                        ),
                        mitre_key="wsl_installed",
                        normal_vs_abnormal=(
                            "【正常】開発者がLinux環境を業務で使用している場合。"
                            "Docker Desktop利用時にWSL2が必要な場合。\n"
                            "【異常】非開発者のPCにWSLがインストールされている場合。"
                            "WSLのインストール時期がインシデント前後の場合。"
                            "KaliLinuxディストリビューションが入っている場合は要注意。\n"
                            "【判断基準】このPCのユーザーがWSLを業務で使用しているか確認。"
                        ),
                        next_steps=[
                            "このPCのユーザーがWSLを業務で使用しているか確認する",
                            "以下のWSL関連の検知結果（ディストリ、履歴等）を確認する",
                            "使用していない場合、不正インストールの可能性を調査する",
                            "KaliLinuxが入っていれば攻撃目的の可能性が高い",
                        ],
                        status="WARNING",
                    ),
                    "wsl_found": True,
                    "is_self": False,
                }
            else:
                return {
                    "source": "WSL Status",
                    "artifact": "WSLは未インストール",
                    "detail": "WSLが検出されませんでした",
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "status": "SAFE",
                    "reason": "",
                    "desc": build_tutor_desc(
                        detection="WSLはこのPCにインストールされていません。",
                        why_dangerous="",
                        normal_vs_abnormal=(
                            "WSL未インストールのため、WSL経由の攻撃リスクはありません。"
                        ),
                        status="SAFE",
                    ),
                    "wsl_found": False,
                    "is_self": False,
                }
        except FileNotFoundError:
            return {
                "source": "WSL Status",
                "artifact": "WSLは未インストール",
                "detail": "wslコマンドが見つかりません",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "status": "SAFE",
                "reason": "",
                "desc": build_tutor_desc(
                    detection="WSLはこのPCにインストールされていません（wslコマンド未検出）。",
                    why_dangerous="",
                    normal_vs_abnormal="WSL未インストールのためリスクなし。",
                    status="SAFE",
                ),
                "wsl_found": False,
                "is_self": False,
            }
        except Exception:
            return {
                "source": "WSL Status",
                "artifact": "WSL確認エラー",
                "detail": "WSLのステータス確認中にエラーが発生しました",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "status": "SAFE",
                "reason": "",
                "desc": "",
                "wsl_found": False,
                "is_self": False,
            }

    def _find_distros(self):
        """インストール済みディストリビューションを検出"""
        results = []
        try:
            result = subprocess.run(
                ['wsl', '--list', '--verbose'],
                capture_output=True, text=True, timeout=10,
                creationflags=0x08000000,
                encoding='utf-8', errors='ignore'
            )
            output = result.stdout.strip()
            if output:
                lines = [line.strip() for line in output.split('\n') if line.strip()]
                for line in lines[1:]:
                    if not line or 'NAME' in line.upper():
                        continue
                    is_default = line.startswith('*')
                    line_clean = line.lstrip('* ').strip()
                    parts = line_clean.split()
                    if parts:
                        distro_name = parts[0]
                        state = parts[1] if len(parts) > 1 else 'Unknown'
                        version = parts[2] if len(parts) > 2 else 'Unknown'

                        is_kali = 'kali' in distro_name.lower()

                        results.append({
                            "source": "WSL Distro",
                            "artifact": f"{distro_name} ({'デフォルト' if is_default else '追加'})",
                            "detail": f"状態: {state}, WSLバージョン: {version}",
                            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "status": "DANGER" if is_kali else "WARNING",
                            "reason": f"WSLディストリビューション検出: {distro_name}",
                            "desc": build_tutor_desc(
                                detection=(
                                    f"WSLディストリビューション「{distro_name}」が"
                                    f"インストールされています。\n"
                                    f"状態: {state}, WSLバージョン: {version}, "
                                    f"{'デフォルト' if is_default else '追加'}ディストリ"
                                ),
                                why_dangerous=(
                                    "Kali Linuxはペネトレーションテスト専用OSであり、"
                                    "攻撃ツールが多数プリインストールされています。"
                                    "業務上の正当な理由がなければ侵害の強い証拠です。"
                                    if is_kali else
                                    "WSLディストリビューションが存在します。"
                                    "Running状態の場合、現在アクティブに使用されており、"
                                    "WSL内での活動はWindows側の監視ツールから見えにくいため、"
                                    "攻撃者に悪用される可能性があります。"
                                ),
                                mitre_key="wsl_distro",
                                normal_vs_abnormal=(
                                    "【正常】開発者がUbuntu等を開発用途で使用している場合。\n"
                                    "【異常】Kali Linux、Parrot OS等のセキュリティ特化ディストリ。"
                                    "非開発者のPCでの検出。インシデント前後にインストールされた場合。\n"
                                    "【判断基準】ユーザーの業務内容とディストリの種類が一致するか。"
                                ),
                                next_steps=[
                                    "このディストリビューションが業務で必要か確認する",
                                    "Running状態の場合、WSL内の活動内容を確認する",
                                    "bash_historyの検知結果を合わせて確認する",
                                ],
                                status="DANGER" if is_kali else "WARNING",
                            ),
                            "is_self": False,
                        })
        except Exception:
            pass
        return results

    def _find_vhdx_files(self):
        """ext4.vhdx ファイルを検索"""
        results = []
        if not self.local_appdata:
            return results

        search_patterns = [
            os.path.join(self.local_appdata, 'Packages', '*',
                         'LocalState', 'ext4.vhdx'),
            os.path.join(self.local_appdata, 'Docker', 'wsl', '*',
                         'ext4.vhdx'),
        ]

        for pattern in search_patterns:
            for vhdx_path in glob.glob(pattern):
                try:
                    size_mb = os.path.getsize(vhdx_path) / (1024 * 1024)
                    mtime = datetime.fromtimestamp(
                        os.path.getmtime(vhdx_path)
                    ).strftime('%Y-%m-%d %H:%M:%S')

                    is_large = size_mb > 2000

                    results.append({
                        "source": "WSL VDisk",
                        "artifact": os.path.basename(
                            os.path.dirname(os.path.dirname(vhdx_path))),
                        "detail": (f"パス: {vhdx_path}\n"
                                   f"サイズ: {size_mb:.0f} MB\n"
                                   f"最終更新: {mtime}"),
                        "timestamp": mtime,
                        "status": "DANGER" if is_large else "WARNING",
                        "reason": f"WSL仮想ディスク検出 ({size_mb:.0f}MB)",
                        "desc": build_tutor_desc(
                            detection=(
                                f"WSL2の仮想ディスクファイル(ext4.vhdx)が検出されました。\n"
                                f"サイズ: {size_mb:.0f} MB, 最終更新: {mtime}\n"
                                f"パス: {vhdx_path}"
                            ),
                            why_dangerous=(
                                "このファイル内にLinuxファイルシステムが格納されています。"
                                "Windows側のアンチウイルスはVHDX内部をスキャンできないため、"
                                "攻撃者はここにマルウェア、攻撃ツール、窃取データを配置し、"
                                "検知を回避できます。"
                                + (f" サイズが{size_mb:.0f}MBと非常に大きく、"
                                   "大量のツールやデータが含まれている可能性があります。"
                                   if is_large else "")
                            ),
                            mitre_key="wsl_vhdx",
                            normal_vs_abnormal=(
                                "【正常】開発用途で数百MB〜1GB程度のext4.vhdxは一般的。"
                                "Docker利用時は数GBになることもあります。\n"
                                "【異常】非開発者のPCで大きなVHDX。"
                                "最終更新がインシデント前後の場合。\n"
                                "【判断基準】ユーザーのWSL使用状況とファイルサイズが妥当か。"
                            ),
                            next_steps=[
                                "サイズが異常に大きい場合、WSL内のファイル一覧を確認する",
                                "WSL内の /tmp と /root を確認し不審ファイルを探す",
                                "WSL内の .bash_history を確認する（履歴解析結果を参照）",
                            ],
                            status="DANGER" if is_large else "WARNING",
                        ),
                        "is_self": False,
                    })
                except OSError:
                    continue

        return results

    def _analyze_wsl_history(self):
        """WSLのbash_historyを解析"""
        results = []
        if not self.user_profile:
            return results

        wsl_paths = [r'\\wsl$', r'\\wsl.localhost']

        for wsl_root in wsl_paths:
            try:
                if not os.path.exists(wsl_root):
                    continue
                for distro in os.listdir(wsl_root):
                    history_paths = [
                        os.path.join(wsl_root, distro, 'root',
                                     '.bash_history'),
                        os.path.join(wsl_root, distro, 'home', '*',
                                     '.bash_history'),
                    ]
                    for pattern in history_paths:
                        for hist_file in glob.glob(pattern):
                            suspicious = self._check_history_file(
                                hist_file, distro)
                            results.extend(suspicious)
            except (PermissionError, OSError):
                continue

        return results

    def _check_history_file(self, filepath, distro_name):
        """bash_historyファイルの内容を解析"""
        results = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            suspicious_found = []
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                for cmd in self.suspicious_commands:
                    if cmd in line_stripped.lower():
                        suspicious_found.append({
                            "line": line_num,
                            "command": line_stripped[:200],
                            "keyword": cmd.strip(),
                        })
                        break

            if suspicious_found:
                cmd_list = '\n'.join(
                    [f"  行{s['line']}: {s['command']}"
                     for s in suspicious_found[:10]])

                # キーワード分類
                has_revshell = any(
                    k['keyword'] in ('nc ', 'ncat ', 'netcat ', 'mkfifo',
                                     '/dev/tcp/', '/dev/udp/', 'socat ',
                                     'reverse', 'bind')
                    for k in suspicious_found)
                has_download = any(
                    k['keyword'] in ('curl ', 'wget ')
                    for k in suspicious_found)
                has_recon = any(
                    k['keyword'] in ('nmap ', 'masscan ', 'tcpdump')
                    for k in suspicious_found)

                results.append({
                    "source": "WSL History",
                    "artifact": (f"{distro_name}: .bash_history "
                                 f"({len(suspicious_found)}件の不審コマンド)"),
                    "detail": f"ファイル: {filepath}\n不審コマンド:\n{cmd_list}",
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "status": "DANGER",
                    "reason": f"WSL内で不審コマンド{len(suspicious_found)}件検出",
                    "desc": build_tutor_desc(
                        detection=(
                            f"WSLディストリビューション「{distro_name}」の"
                            f"コマンド履歴から不審なコマンドが"
                            f"{len(suspicious_found)}件検出されました。\n"
                            f"ファイル: {filepath}\n"
                            f"検出コマンド（先頭10件）:\n{cmd_list}"
                        ),
                        why_dangerous=(
                            "攻撃者はWSL内でLinuxツールを使用して攻撃活動を行います。"
                            + (" リバースシェル関連コマンドが検出されており、"
                               "攻撃者が遠隔操作チャネルを確立した可能性があります。"
                               if has_revshell else "")
                            + (" ダウンロードコマンドが検出されており、"
                               "マルウェアやツールの取得に使用された可能性があります。"
                               if has_download else "")
                            + (" ネットワーク偵察コマンドが検出されており、"
                               "内部ネットワークの探索が行われた可能性があります。"
                               if has_recon else "")
                            + " Windows側の監視ツール(EDR等)ではWSL内のこれらの活動は"
                              "検知が困難です。"
                        ),
                        mitre_key="wsl_history",
                        normal_vs_abnormal=(
                            "【正常】開発者がcurl/wgetでパッケージ取得、"
                            "ssh -Lでトンネル構築等は日常的に使用します。\n"
                            "【異常】netcat/mkfifo（リバースシェル）、"
                            "nmap/masscan（ネットワークスキャン）、"
                            "base64 -d（エンコード解除）の組み合わせは攻撃活動の兆候。\n"
                            "【判断基準】コマンドの内容が業務活動として説明できるか？"
                            "特にリバースシェルの構築は正当な理由が極めて限定される。"
                        ),
                        next_steps=[
                            "検出されたコマンドが正当な業務活動か確認する",
                            "WSL内の /tmp ディレクトリに不審なファイルがないか確認する",
                            "「ネットワーク」タブでWSL関連の外部通信を確認する",
                            "リバースシェル関連コマンドがあれば即座にネットワーク隔離する",
                            "bash_historyの全文を保全する（フォレンジック証拠）",
                        ],
                        status="DANGER",
                    ),
                    "is_self": False,
                })

        except (PermissionError, OSError):
            pass

        return results

    def _check_vmmem(self):
        """vmmemプロセスの確認"""
        results = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    if (proc.info['name'] and
                            'vmmem' in proc.info['name'].lower()):
                        mem_mb = (proc.info['memory_info'].rss / (1024 * 1024)
                                  if proc.info['memory_info'] else 0)
                        is_heavy = mem_mb > 500

                        results.append({
                            "source": "WSL Process",
                            "artifact": f"vmmem (PID:{proc.info['pid']})",
                            "detail": f"メモリ使用量: {mem_mb:.0f} MB",
                            "timestamp": datetime.now().strftime(
                                '%Y-%m-%d %H:%M:%S'),
                            "status": "WARNING" if is_heavy else "SAFE",
                            "reason": (
                                f"WSL仮想マシンプロセス ({mem_mb:.0f}MB)"
                                if is_heavy else ""),
                            "desc": build_tutor_desc(
                                detection=(
                                    f"WSL2の仮想マシンプロセス(vmmem)が稼働中です。"
                                    f"メモリ使用量: {mem_mb:.0f}MB"
                                ),
                                why_dangerous=(
                                    f"メモリ使用量が{mem_mb:.0f}MBと大きく、"
                                    "WSL内で重い処理が動作中です。"
                                    "マイニング、大規模スキャン、データ処理等の"
                                    "可能性があります。"
                                    if is_heavy else ""
                                ),
                                normal_vs_abnormal=(
                                    "【正常】開発作業やDocker利用時は数百MBは正常。\n"
                                    "【異常】1GB超のメモリ使用は重い処理の兆候。"
                                    "ユーザーが使用していないのにvmmemが動作中の場合。\n"
                                    "【判断基準】ユーザーがWSLを使用中か確認。"
                                    if is_heavy else
                                    "WSL仮想マシンが稼働中ですが、メモリ使用量は通常範囲内です。"
                                ),
                                next_steps=(
                                    [
                                        "WSL内で実行中のプロセスを確認する（wsl -- ps aux）",
                                        "メモリ大量消費の原因プロセスを特定する",
                                    ] if is_heavy else None
                                ),
                                status="WARNING" if is_heavy else "SAFE",
                            ),
                            "is_self": False,
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return results
