# -*- coding: utf-8 -*-
# collectors/memory.py - P7+P16: 全メモリ領域表示 + RWX危険タグ + 統一解説強化
# ERR-MEM-001〜003: メモリ解析エラー系
import psutil
import os
from utils.tutor_template import build_tutor_desc


class MemoryCollector:
    def __init__(self):
        # JITコンパイラ使用アプリ（RWXが正常なもの）
        self.jit_whitelist = [
            'chrome.exe', 'msedge.exe', 'firefox.exe',
            'code.exe', 'pycharm.exe', 'electron.exe',
            'java.exe', 'javaw.exe', 'node.exe',
        ]
        # 完全スキップ対象（大量のマッピングを持つがフォレンジック価値が低い）
        self.skip_procs = ['registry', 'memory compression']

    def scan(self):
        results = []

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                proc_name = proc.info['name'] or 'Unknown'
                proc_pid = proc.info['pid']

                # ERR-MEM-001: スキップ対象プロセス
                if proc_name.lower() in self.skip_procs:
                    continue

                try:
                    maps = proc.memory_maps(grouped=False)
                except (psutil.AccessDenied, NotImplementedError):
                    # ERR-MEM-002: アクセス拒否は正常（SYSTEM権限プロセス等）
                    continue

                rwx_count = 0
                rwx_anon_count = 0
                rwx_named_count = 0
                rw_count = 0
                rx_count = 0
                total_regions = len(maps)

                rwx_paths = []  # RWX領域に紐付くファイルパス

                for m in maps:
                    perms = m.perms if hasattr(m, 'perms') else ''
                    has_r = 'r' in perms
                    has_w = 'w' in perms
                    has_x = 'x' in perms
                    is_anon = (m.path == '' or m.path == '[anon]')

                    if has_r and has_w and has_x:
                        rwx_count += 1
                        if is_anon:
                            rwx_anon_count += 1
                        else:
                            rwx_named_count += 1
                            if m.path and m.path not in rwx_paths:
                                rwx_paths.append(m.path)
                    elif has_r and has_w:
                        rw_count += 1
                    elif has_r and has_x:
                        rx_count += 1

                # プロセスごとにサマリー行を生成
                is_jit = proc_name.lower() in self.jit_whitelist

                if rwx_anon_count > 0 and not is_jit:
                    # 最も危険: 匿名RWXメモリ（JITアプリ以外）
                    results.append({
                        "pid": proc_pid,
                        "name": proc_name,
                        "user": proc.info['username'] or 'SYSTEM',
                        "address": f"匿名RWX: {rwx_anon_count}箇所",
                        "size": f"全{total_regions}領域",
                        "type": "RWX",
                        "perms_summary": f"RWX:{rwx_count} RW:{rw_count} RX:{rx_count}",
                        "status": "DANGER",
                        "reason": f"匿名RWXメモリ検知: {proc_name} (PID:{proc_pid})",
                        "desc": build_tutor_desc(
                            detection=(
                                f"プロセス「{proc_name}」(PID:{proc_pid})に、ディスク上のファイルと"
                                f"紐付かない読み書き実行可能(RWX)なメモリ領域が{rwx_anon_count}箇所あります。"
                                f"メモリ構成: RWX={rwx_count}, RW={rw_count}, RX={rx_count}, 全{total_regions}領域。"
                            ),
                            why_dangerous=(
                                "通常のアプリケーションは、コード領域(RX=読み取り+実行)とデータ領域(RW=読み書き)を"
                                "分離します（DEP/NX原則）。RWXはコードを動的に書き換えて実行できるため、"
                                "Cobalt Strike Beacon、Metasploit Meterpreter、反射型DLLインジェクション、"
                                "シェルコードローダーなどのファイルレス攻撃で使用されます。"
                                "特に「匿名」（ディスク上のファイルに紐付かない）RWX領域は、"
                                "攻撃者がメモリ上にのみコードを展開している強い兆候です。"
                            ),
                            mitre_key="mem_rwx_anon",
                            normal_vs_abnormal=(
                                "【正常】Chrome/Edge/Firefox/Node.js等のJITコンパイラ搭載アプリはRWXを使用します。"
                                "これらはホワイトリストで除外済みです。\n"
                                "【異常】svchost.exe、explorer.exe、notepad.exe等の標準Windowsプロセスや、"
                                "業務用アプリケーションにRWXがある場合は高確率でインジェクションです。\n"
                                "【判断基準】このプロセスがJITエンジンを使うアプリか？使わないなら異常と判断。"
                            ),
                            next_steps=[
                                "「プロセス」タブでこのプロセスの実行パス(exe)と親プロセスを確認する",
                                "「ネットワーク」タブでこのPIDの外部通信（特にC2ビーコニング）を確認する",
                                "「DNA」タブでこのプロセスのエントロピー（暗号化/パック兆候）を確認する",
                                "可能であればメモリダンプを取得し、YARAルールでシグネチャスキャンする",
                                "即座にネットワーク隔離を検討する（C2接続が確認された場合）",
                            ],
                            status="DANGER",
                        ),
                    })

                elif rwx_named_count > 0 and not is_jit:
                    # 危険: ファイル紐付きRWXだがJITアプリでない
                    path_info = ", ".join(rwx_paths[:3])
                    if len(rwx_paths) > 3:
                        path_info += f" 他{len(rwx_paths)-3}件"

                    results.append({
                        "pid": proc_pid,
                        "name": proc_name,
                        "user": proc.info['username'] or 'SYSTEM',
                        "address": f"RWX(名前付き): {rwx_named_count}箇所",
                        "size": f"全{total_regions}領域",
                        "type": "RWX",
                        "perms_summary": f"RWX:{rwx_count} RW:{rw_count} RX:{rx_count}",
                        "status": "WARNING",
                        "reason": f"名前付きRWXメモリ検知: {proc_name} (PID:{proc_pid})",
                        "desc": build_tutor_desc(
                            detection=(
                                f"プロセス「{proc_name}」(PID:{proc_pid})に、ファイルに紐付く"
                                f"RWXメモリ領域が{rwx_named_count}箇所あります。"
                                f"関連ファイル: {path_info}"
                            ),
                            why_dangerous=(
                                "ファイルに紐付くRWX領域は、DLLインジェクションやパッキング（実行時展開）で"
                                "発生することがあります。匿名RWXほど危険ではありませんが、"
                                "正規のアプリケーションでは通常見られないパーミッション設定です。"
                            ),
                            mitre_key="mem_rwx_named",
                            normal_vs_abnormal=(
                                "【正常】一部の古いアプリケーションやパッカーは正当な理由でRWXを使用します。\n"
                                "【異常】紐付くファイルパスがTemp、AppData、ProgramData等の"
                                "書き込み可能フォルダにある場合は要注意です。\n"
                                "【判断基準】紐付くファイルが正規のソフトウェアか、パスが標準的か確認。"
                            ),
                            next_steps=[
                                "紐付くファイルパスが正規のインストール先か確認する",
                                "ファイルのデジタル署名を確認する（署名なし＝要調査）",
                                "VirusTotal等でファイルハッシュを照会する",
                            ],
                            status="WARNING",
                        ),
                    })

                elif rwx_count > 0 and is_jit:
                    # JITアプリのRWX（正常だが記録）
                    results.append({
                        "pid": proc_pid,
                        "name": proc_name,
                        "user": proc.info['username'] or 'SYSTEM',
                        "address": f"RWX: {rwx_count}箇所 (JIT)",
                        "size": f"全{total_regions}領域",
                        "type": "JIT-RWX",
                        "perms_summary": f"RWX:{rwx_count} RW:{rw_count} RX:{rx_count}",
                        "status": "SAFE",
                        "reason": f"JITコンパイラ使用アプリのRWX: {proc_name}",
                        "desc": build_tutor_desc(
                            detection=(
                                f"JITコンパイラ使用アプリ「{proc_name}」(PID:{proc_pid})に"
                                f"RWXメモリ領域が{rwx_count}箇所あります。"
                            ),
                            why_dangerous="",
                            normal_vs_abnormal=(
                                "【正常】Chrome/Edge/Firefox等のブラウザ、Node.js、Java、VS Code等は"
                                "JavaScriptエンジン(V8等)やJVMのJITコンパイルのためにRWXを正常に使用します。"
                                "このプロセスはJITホワイトリストに含まれているため安全と判断しました。\n"
                                "【注意】ただし、ブラウザ自体がエクスプロイトの標的になる場合もあるため、"
                                "異常な外部通信やクラッシュが併発していないか確認してください。"
                            ),
                            status="SAFE",
                        ),
                    })

                else:
                    # RWXなし（正常プロセス）- メモリ領域が多い上位のみ記録
                    if total_regions > 50:
                        results.append({
                            "pid": proc_pid,
                            "name": proc_name,
                            "user": proc.info['username'] or 'SYSTEM',
                            "address": "-",
                            "size": f"全{total_regions}領域",
                            "type": "Normal",
                            "perms_summary": f"RWX:{rwx_count} RW:{rw_count} RX:{rx_count}",
                            "status": "SAFE",
                            "reason": "RWX領域なし（正常）",
                            "desc": build_tutor_desc(
                                detection=(
                                    f"プロセス「{proc_name}」(PID:{proc_pid})のメモリ構成を解析しました。"
                                    f"全{total_regions}領域中、RWX領域は検出されませんでした。"
                                    f"メモリ構成: RW={rw_count}, RX={rx_count}。"
                                ),
                                why_dangerous="",
                                normal_vs_abnormal=(
                                    "【正常】RWXメモリが存在せず、コード(RX)とデータ(RW)が適切に分離されています。"
                                    "DEP(データ実行防止)が正常に機能している状態です。"
                                ),
                                status="SAFE",
                            ),
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # ERR-MEM-003: プロセス消失
                continue
            except Exception:
                continue

        # DANGERを先頭に、WARNING、SAFEの順でPIDソート
        status_order = {"DANGER": 0, "WARNING": 1, "INFO": 2, "SAFE": 3}
        results.sort(key=lambda x: (status_order.get(x['status'], 9), x['pid']))
        return results
