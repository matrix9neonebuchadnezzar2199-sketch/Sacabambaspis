# -*- coding: utf-8 -*-
"""
Network Deep Analyzer - ネットワーク深層解析
P11+P16: ビーコニング検知、署名検証、DNS逆引き、大量接続検知、非標準ポート検知、アカウント異常
         + 統一解説フォーマット強化
"""

import psutil
import socket
import os
import subprocess
from collections import Counter, defaultdict
from utils.tutor_template import build_tutor_desc


class NetworkCollector:
    """ネットワーク接続の深層解析"""

    # ERR-NET-001: LOLBins拡充リスト
    LOLBINS = [
        'powershell.exe', 'pwsh.exe', 'cmd.exe', 'rundll32.exe',
        'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'mshta.exe',
        'certutil.exe', 'bitsadmin.exe', 'msiexec.exe',
        'installutil.exe', 'regasm.exe', 'regsvcs.exe',
        'msconfig.exe', 'msbuild.exe', 'xwizard.exe',
        'ieexec.exe', 'dnscmd.exe', 'ftp.exe',
        'finger.exe', 'bash.exe', 'wsl.exe',
        'forfiles.exe', 'pcalua.exe', 'presentationhost.exe',
        'syncappvpublishingserver.exe', 'hh.exe',
        'mmc.exe', 'control.exe', 'cmstp.exe',
    ]

    # ERR-NET-002: C2/マルウェア頻用ポート
    BLACKLIST_PORTS = {
        4444: 'Metasploit default',
        5555: 'Metasploit/Android debug',
        6666: 'IRC botnet',
        6667: 'IRC botnet',
        6697: 'IRC SSL',
        1337: 'Elite/backdoor',
        31337: 'Back Orifice',
        8080: 'HTTP proxy (要確認)',
        8443: 'HTTPS alt (要確認)',
        9090: 'Web管理 (要確認)',
        3389: 'RDP (外部向けは危険)',
        5900: 'VNC',
        5901: 'VNC',
        1080: 'SOCKS proxy',
        1234: 'Backdoor common',
        12345: 'NetBus',
        54321: 'Back Orifice 2000',
        7777: 'Backdoor common',
        9999: 'Backdoor common',
        443: 'HTTPS (LOLBin時のみ警告)',
    }

    # ERR-NET-003: 標準的なポート（これ以外は非標準）
    STANDARD_PORTS = {
        80, 443, 8080, 8443,
        53,
        21, 22, 23,
        25, 110, 143, 465, 587, 993, 995,
        389, 636,
        445, 139,
        3306, 5432, 1433, 1521, 27017,
        3389,
        5985, 5986,
        88, 464,
        135, 137, 138,
    }

    # ERR-NET-004: ビーコニング検知の閾値
    BEACON_THRESHOLD = 5

    # ERR-NET-005: 大量接続の閾値
    MASS_CONN_THRESHOLD = 30

    # ERR-NET-006: 攻撃ツールプロセス名
    ATTACK_TOOLS = [
        'mimikatz', 'psexec', 'psexesvc', 'cobalt', 'beacon',
        'rubeus', 'sharphound', 'bloodhound', 'lazagne',
        'chisel', 'ligolo', 'sliver', 'havoc',
        'nmap', 'masscan', 'crackmapexec', 'evil-winrm',
        'nc.exe', 'ncat.exe', 'netcat.exe', 'socat.exe',
        'plink.exe', 'ngrok.exe', 'frpc.exe', 'frps.exe',
    ]

    def __init__(self):
        self._dns_cache = {}
        self._sig_cache = {}

    def scan(self):
        """メインスキャン処理"""
        connections = []
        proc_conn_count = Counter()
        remote_ip_count = defaultdict(list)

        try:
            raw_conns = list(psutil.net_connections(kind='inet'))
        except Exception:
            return connections

        # パス1: 全接続を収集し、統計を取る
        conn_data = []
        for conn in raw_conns:
            if conn.raddr:
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
            else:
                raddr = "*"
                remote_ip = None
                remote_port = None

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "*"

            proc_name = "Unknown"
            proc_path = ""
            proc_user = ""
            pid = conn.pid or 0

            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc_path = proc.exe()
                try:
                    proc_user = proc.username()
                except Exception:
                    proc_user = ""
            except Exception:
                pass

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            state = conn.status

            proc_conn_count[pid] += 1
            if remote_ip and not self._is_local_ip(remote_ip):
                remote_ip_count[remote_ip].append(pid)

            conn_data.append({
                'pid': pid,
                'proc_name': proc_name,
                'proc_path': proc_path,
                'proc_user': proc_user,
                'laddr': laddr,
                'raddr': raddr,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'proto': proto,
                'state': state,
            })

        # パス1.5: バッチDNS逆引き + バッチ署名検証（高速化）
        all_remote_ips = [cd['remote_ip'] for cd in conn_data if cd['remote_ip']]
        self._batch_reverse_dns(all_remote_ips)
        all_exe_paths = [cd['proc_path'] for cd in conn_data if cd['proc_path']]
        self._batch_check_signatures(all_exe_paths)

        # パス2: 各接続を解析
        for cd in conn_data:
            analysis = self._deep_analyze(
                cd, proc_conn_count, remote_ip_count, conn_data
            )

            rdns = ''
            if cd['remote_ip'] and not self._is_local_ip(cd['remote_ip']):
                rdns = self._reverse_dns(cd['remote_ip'])

            signature = ''
            if cd['proc_path']:
                signature = self._check_signature(cd['proc_path'])

            conn_count = proc_conn_count.get(cd['pid'], 0)

            connections.append({
                'pid': cd['pid'],
                'process': cd['proc_name'],
                'local': cd['laddr'],
                'remote': cd['raddr'],
                'rdns': rdns,
                'state': cd['state'],
                'protocol': cd['proto'],
                'user': cd['proc_user'],
                'signature': signature,
                'conn_count': conn_count,
                'status': analysis['status'],
                'reason': analysis['reason'],
                'desc': analysis['desc'],
                'peer_details': analysis.get('peer_details', ''),
            })

        return connections

    def _deep_analyze(self, cd, proc_conn_count, remote_ip_count, conn_data=None):
        """接続の深層解析（複数ルール適用、最も危険度の高いものを返す）"""
        findings = []
        name_lower = cd['proc_name'].lower()
        remote_ip = cd['remote_ip']
        remote_port = cd['remote_port']
        state = cd['state']
        pid = cd['pid']

        # ルール1: 攻撃ツールの通信
        for tool in self.ATTACK_TOOLS:
            if tool in name_lower:
                findings.append({
                    'status': 'DANGER',
                    'reason': f'攻撃ツールの通信検知: {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                    'desc': build_tutor_desc(
                        detection=(
                            f'既知の攻撃ツール「{cd["proc_name"]}」(PID:{pid})が'
                            f'ネットワーク通信を行っています。'
                            f'接続先: {cd["raddr"]}, 状態: {state}'
                        ),
                        why_dangerous=(
                            f'「{cd["proc_name"]}」は侵入テスト・攻撃に使用されるツールです。'
                            'このツールがインストールされていること自体が、'
                            '攻撃者による侵害またはペネトレーションテストの痕跡です。'
                            'ネットワーク通信を行っている場合、C2サーバーへの接続、'
                            '認証情報の外部送信、またはラテラルムーブメントの可能性があります。'
                        ),
                        mitre_key="net_attack_tool",
                        normal_vs_abnormal=(
                            '【正常】社内で承認されたペネトレーションテスト中のみ。'
                            'テスト期間・対象ホストが事前に通知されているか確認。\n'
                            '【異常】予定外の攻撃ツール検知は侵害の強い証拠。\n'
                            '【判断基準】セキュリティチームに連絡し、承認済みテストか即座に確認。'
                        ),
                        next_steps=[
                            '即座にネットワークを遮断し、プロセスを停止する',
                            '接続先IPアドレスの所有者・評判をVirusTotal/AbuseIPDBで確認する',
                            'このプロセスの親プロセスと起動コマンドラインを確認する',
                            'フォレンジック保全（メモリダンプ＋ディスクイメージ）を実施する',
                            'セキュリティチームにインシデントとして報告する',
                        ],
                        status='DANGER',
                    ),
                })
                break

        # ルール2: LOLBinsの外部通信
        if name_lower in self.LOLBINS and remote_ip and not self._is_local_ip(remote_ip):
            findings.append({
                'status': 'DANGER',
                'reason': f'LOLBinの外部通信: {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                'desc': build_tutor_desc(
                    detection=(
                        f'Windows標準管理ツール「{cd["proc_name"]}」(PID:{pid})が'
                        f'外部IPアドレス({remote_ip})と通信しています。'
                        f'接続先: {cd["raddr"]}, プロトコル: {cd["proto"]}'
                    ),
                    why_dangerous=(
                        'Living off the Land (LOL) 攻撃は、OSに標準搭載されたツールを'
                        '悪用してファイルダウンロード・コード実行・データ送信を行う手法です。'
                        'セキュリティソフトはOS標準ツールを信頼するため検知が困難です。'
                        f'「{cd["proc_name"]}」が外部IPと通信する正当な理由は限られており、'
                        '攻撃者がC2通信やペイロードダウンロードに使用している可能性があります。'
                    ),
                    mitre_key="net_lolbin",
                    normal_vs_abnormal=(
                        '【正常】certutil.exeによる証明書のダウンロード、'
                        'bitsadmin.exeによるWindows Update等、限定的な用途。\n'
                        '【異常】powershell.exe/cmd.exe/mshta.exe等が不明な外部IPと通信。'
                        '特にBase64エンコードされたコマンドラインや非標準ポートの場合は高リスク。\n'
                        '【判断基準】コマンドライン引数を確認し、正当な管理操作か判断。'
                    ),
                    next_steps=[
                        '「プロセス」タブでこのプロセスのコマンドライン引数と親プロセスを確認する',
                        '接続先IPの評判をVirusTotal/AbuseIPDBで確認する',
                        '同時刻に作成されたファイル（ダウンロードされた可能性）を調査する',
                        'イベントログ（4104: PowerShell実行）で実行内容を確認する',
                    ],
                    status='DANGER',
                ),
            })

        # ルール3: ブラックリストポート
        if remote_port and remote_port in self.BLACKLIST_PORTS:
            port_info = self.BLACKLIST_PORTS[remote_port]
            if remote_port == 443:
                if name_lower in self.LOLBINS:
                    findings.append({
                        'status': 'WARNING',
                        'reason': f'LOLBinのHTTPS通信 (port {remote_port}) | {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                        'desc': build_tutor_desc(
                            detection=(
                                f'管理ツール「{cd["proc_name"]}」(PID:{pid})が'
                                f'HTTPS(port 443)で外部通信しています。接続先: {cd["raddr"]}'
                            ),
                            why_dangerous=(
                                'C2フレームワーク（Cobalt Strike、Sliver等）は'
                                'HTTPSを使用して通信を暗号化し、正規のWeb通信に偽装します。'
                                'LOLBinがHTTPS通信を行う場合、攻撃者がステージャー（初期ペイロード）を'
                                'ダウンロードしている、またはC2チャネルを確立している可能性があります。'
                            ),
                            mitre_key="net_blacklist_port",
                            normal_vs_abnormal=(
                                '【正常】certutil.exeによるHTTPSでの証明書取得など限定的。\n'
                                '【異常】powershell.exe/mshta.exe等がHTTPSで不明サーバーに接続。\n'
                                '【判断基準】接続先ドメインが既知の正規サイトか確認。'
                            ),
                            next_steps=[
                                'プロセスのコマンドライン引数を確認する',
                                'DNS逆引き結果でドメイン名を確認する',
                                '接続先IPの評判を確認する',
                            ],
                            status='WARNING',
                        ),
                    })
            elif remote_port in (8080, 8443, 9090):
                findings.append({
                    'status': 'WARNING',
                    'reason': f'代替HTTPポート: {remote_port} ({port_info}) | {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                    'desc': build_tutor_desc(
                        detection=(
                            f'プロセス「{cd["proc_name"]}」(PID:{pid})が'
                            f'代替HTTPポート{remote_port}で通信しています。'
                            f'接続先: {cd["raddr"]}, 用途: {port_info}'
                        ),
                        why_dangerous=(
                            f'ポート{remote_port}はWebプロキシや管理用ダッシュボードで使用されますが、'
                            'C2フレームワークやWebシェルの通信でも頻繁に使用されます。'
                            '正規のHTTP/HTTPS(80/443)以外のWebポートは確認が必要です。'
                        ),
                        normal_vs_abnormal=(
                            '【正常】開発環境のローカルサーバー(localhost:8080)、'
                            '社内プロキシサーバーへの接続。\n'
                            '【異常】外部IPの8080/8443/9090への接続で、用途が不明な場合。\n'
                            '【判断基準】接続先が社内インフラか外部か、プロセスが正規か確認。'
                        ),
                        next_steps=[
                            '接続先IPが社内インフラか外部かを確認する',
                            'プロセスの正当性を確認する',
                            'プロキシログで通信内容を確認する（可能な場合）',
                        ],
                        status='WARNING',
                    ),
                })
            else:
                findings.append({
                    'status': 'DANGER',
                    'reason': f'危険ポート: {remote_port} ({port_info}) | {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                    'desc': build_tutor_desc(
                        detection=(
                            f'プロセス「{cd["proc_name"]}」(PID:{pid})が'
                            f'既知の危険ポート{remote_port}で通信しています。'
                            f'接続先: {cd["raddr"]}, 既知の用途: {port_info}'
                        ),
                        why_dangerous=(
                            f'ポート{remote_port}は「{port_info}」として知られ、'
                            'マルウェアやバックドアの通信で頻繁に使用されます。'
                            '正当な業務アプリケーションがこのポートを使用することは稀です。'
                            '攻撃者はデフォルトポートを変更しない場合が多く、'
                            'この接続はリモートアクセス・C2通信の可能性が高いです。'
                        ),
                        mitre_key="net_blacklist_port",
                        normal_vs_abnormal=(
                            f'【正常】ポート{remote_port}を正当に使用するケースは非常に限定的。'
                            'RDP(3389)は社内リモート管理で使用される場合あり。\n'
                            f'【異常】外部IPへのポート{remote_port}接続は高確率で不正。\n'
                            '【判断基準】この通信を自分または管理者が意図的に行ったか？'
                        ),
                        next_steps=[
                            'プロセスの正当性（パス、署名、親プロセス）を確認する',
                            '接続先IPアドレスの評判をVirusTotal/AbuseIPDBで確認する',
                            '即座にネットワーク遮断を検討する',
                            'メモリダンプとフォレンジック保全を実施する',
                        ],
                        status='DANGER',
                    ),
                })

        # ルール4: 非標準ポートでのESTABLISHED接続
        if (remote_port and remote_port not in self.STANDARD_PORTS
                and remote_port > 1024 and state == 'ESTABLISHED'
                and remote_ip and not self._is_local_ip(remote_ip)):
            findings.append({
                'status': 'WARNING',
                'reason': f'非標準ポート通信: {remote_port} | {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                'desc': build_tutor_desc(
                    detection=(
                        f'プロセス「{cd["proc_name"]}」(PID:{pid})が'
                        f'非標準ポート{remote_port}で外部と接続を確立しています。'
                        f'接続先: {cd["raddr"]}, 状態: ESTABLISHED'
                    ),
                    why_dangerous=(
                        'C2通信やトンネリング（chisel、ngrok等）は検知を回避するため'
                        '一般的でないポート番号を使用することがあります。'
                        '標準ポート（80, 443, 22等）以外での外部接続は確認が必要です。'
                    ),
                    mitre_key="net_nonstandard",
                    normal_vs_abnormal=(
                        '【正常】オンラインゲーム、VPN、P2Pアプリ等は非標準ポートを使用します。'
                        '業務用アプリケーションのカスタムポートの場合もあります。\n'
                        '【異常】見覚えのないプロセスが高番号ポートで外部と通信。\n'
                        '【判断基準】プロセスが既知のアプリか？ポート番号が業務で使用されているか？'
                    ),
                    next_steps=[
                        'プロセスの正体（パス、署名、コマンドライン）を確認する',
                        '接続先IPとポートの組み合わせが正当な用途か確認する',
                        '同じポートを使う他の接続がないか「ネットワーク」タブ全体を確認する',
                    ],
                    status='WARNING',
                ),
            })

        # ルール5: ビーコニング検知（同一IPへの複数接続）
        if remote_ip and not self._is_local_ip(remote_ip):
            ip_conn_pids = remote_ip_count.get(remote_ip, [])
            ip_conn_count = len(ip_conn_pids)
            if ip_conn_count >= self.BEACON_THRESHOLD:
                findings.append({
                    'status': 'WARNING',
                    'reason': f'ビーコニング疑い: {remote_ip} へ{ip_conn_count}件 | {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                    'desc': build_tutor_desc(
                        detection=(
                            f'同一リモートIP({remote_ip})への接続が{ip_conn_count}件検出されました。'
                            f'関連プロセス: {cd["proc_name"]}(PID:{pid})'
                        ),
                        why_dangerous=(
                            'C2ビーコニングとは、マルウェアがC2サーバーに定期的に'
                            '「生存確認」の通信を送る動作です。Cobalt Strike等のC2フレームワークは'
                            'デフォルトで60秒間隔のビーコニングを行います。'
                            '同一IPへの反復的な接続パターンはC2通信の典型的な特徴です。'
                        ),
                        mitre_key="net_beaconing",
                        normal_vs_abnormal=(
                            '【正常】CDN(Akamai, CloudFront等)、Windows Update、'
                            'クラウドサービス(Azure, AWS)への定期通信。'
                            'ブラウザのKeep-Alive接続。\n'
                            '【異常】小さなデータ量で一定間隔の接続が繰り返される場合。'
                            '通信先が不明なIPやVPS/クラウドホスティングの場合。\n'
                            '【判断基準】DNS逆引き結果で接続先の正体を確認。'
                        ),
                        next_steps=[
                            '接続先IPのDNS逆引き結果（rdns列）でドメイン名を確認する',
                            '接続先IPの評判をVirusTotal/AbuseIPDBで確認する',
                            '接続間隔に規則性がないか確認する（一定間隔=ビーコニング）',
                            '通信しているプロセスの正当性を確認する',
                        ],
                        status='WARNING',
                    ),
                })

        # ルール6: 大量接続プロセス
        conn_count = proc_conn_count.get(pid, 0)
        if conn_count >= self.MASS_CONN_THRESHOLD:
            # 同一PIDの接続先を集計
            _peers = []
            _peer_details = []
            if conn_data:
                for _c in conn_data:
                    if _c['pid'] == pid and _c['remote_ip'] and not self._is_local_ip(_c['remote_ip']):
                        _peer_details.append(f"{_c['raddr']} ({_c['state']})")
                from collections import Counter as _C
                _ip_counts = _C(_c['remote_ip'] for _c in conn_data if _c['pid'] == pid and _c['remote_ip'] and not self._is_local_ip(_c['remote_ip']))
                _peers = [f"{ip}({cnt}件)" for ip, cnt in _ip_counts.most_common(3)]
            _top = ", ".join(_peers) if _peers else "詳細不明"
            _mass_reason = f'大量接続: {cd["proc_name"]} が{conn_count}件 | {(cd["proc_path"] or "パス不明")} | 主要接続先: {_top}'
            findings.append({
                'status': 'WARNING',
                'reason': _mass_reason,
                'peer_details': "\n".join(_peer_details[:20]) if _peer_details else '',
                'desc': build_tutor_desc(
                    detection=(
                        f'プロセス「{cd["proc_name"]}」(PID:{pid})が'
                        f'{conn_count}件のネットワーク接続を保持しています。'
                        f'閾値: {self.MASS_CONN_THRESHOLD}件\n'
                        f'主要接続先: {_top}'
                    ),
                    why_dangerous=(
                        '大量のネットワーク接続は、ポートスキャン（偵察活動）、'
                        'DDoS攻撃への加担、ワーム的な拡散（ラテラルムーブメント）、'
                        'または大量のデータ送信（情報窃取）の兆候です。'
                    ),
                    mitre_key="net_mass_conn",
                    normal_vs_abnormal=(
                        '【正常】Webブラウザ(chrome.exe等)は多数のCDN/APIに同時接続します。'
                        'データベースクライアントやクラウド同期アプリも大量接続します。\n'
                        '【異常】svchost.exe、rundll32.exe等のシステムプロセスが大量接続。'
                        '見覚えのないプロセスが大量接続。\n'
                        '【判断基準】プロセスがブラウザや正規アプリか確認。'
                    ),
                    next_steps=[
                        'プロセスの正体を「プロセス」タブで確認する',
                        '接続先IPアドレスに規則性がないか（連番IP=スキャン）確認する',
                        '送受信データ量が異常に大きくないか確認する',
                    ],
                    status='WARNING',
                ),
            })

        # ルール7: アカウント異常（SYSTEM以外のシステムプロセス通信）
        user_lower = cd['proc_user'].lower() if cd['proc_user'] else ''
        system_procs = ['svchost.exe', 'lsass.exe', 'services.exe',
                        'csrss.exe', 'smss.exe', 'wininit.exe']
        if (name_lower in system_procs and user_lower
                and 'system' not in user_lower
                and 'local service' not in user_lower
                and 'network service' not in user_lower):
            findings.append({
                'status': 'DANGER',
                'reason': f'アカウント異常: {cd["proc_name"]} が {cd["proc_user"]} で実行 | {(cd["proc_path"] or "パス不明")}',
                'desc': build_tutor_desc(
                    detection=(
                        f'システムプロセス「{cd["proc_name"]}」(PID:{pid})が'
                        f'通常と異なるアカウント({cd["proc_user"]})で実行されています。'
                        f'接続先: {cd["raddr"]}'
                    ),
                    why_dangerous=(
                        f'「{cd["proc_name"]}」はWindowsの中核プロセスであり、'
                        '必ずSYSTEM、LOCAL SERVICE、またはNETWORK SERVICEアカウントで実行されます。'
                        '一般ユーザーアカウントで実行されている場合、'
                        'プロセスインジェクション（正規プロセスに悪意のコードを注入）、'
                        'プロセスホロウイング（正規プロセスの中身を入れ替え）、'
                        'またはなりすまし（正規プロセス名を偽装）の可能性があります。'
                    ),
                    mitre_key="net_account_anomaly",
                    normal_vs_abnormal=(
                        '【正常】これらのプロセスが一般ユーザーで動くことは絶対にありません。\n'
                        '【異常】100%異常です。即座に調査が必要です。\n'
                        '【判断基準】ステータスが「DANGER」の場合は誤検知の可能性は極めて低い。'
                    ),
                    next_steps=[
                        'プロセスの実行パスが正規の場所(C:\\Windows\\System32)か確認する',
                        '「メモリ」タブでこのプロセスにRWXインジェクションがないか確認する',
                        'プロセスの親プロセスツリーを確認する',
                        '即座にネットワーク隔離とフォレンジック保全を実施する',
                    ],
                    status='DANGER',
                ),
            })

        # ルール8: 未署名プロセスの外部通信
        if (cd['proc_path'] and remote_ip
                and not self._is_local_ip(remote_ip)
                and state == 'ESTABLISHED'):
            sig = self._check_signature(cd['proc_path'])
            if sig == '未署名' and not self._is_trusted_path(cd['proc_path']):
                findings.append({
                    'status': 'WARNING',
                    'reason': f'未署名プロセスの外部通信: {cd["proc_name"]} | {(cd["proc_path"] or "パス不明")}',
                    'desc': build_tutor_desc(
                        detection=(
                            f'デジタル署名のないプロセス「{cd["proc_name"]}」(PID:{pid})が'
                            f'外部IPアドレスと通信を確立しています。'
                            f'接続先: {cd["raddr"]}, パス: {(cd["proc_path"] or "パス不明")}'
                        ),
                        why_dangerous=(
                            '正規のソフトウェアは通常、発行元のデジタル署名（コードサイニング証明書）で'
                            '署名されています。署名がないプロセスが外部と通信している場合、'
                            '攻撃者が作成したカスタムツール、改ざんされたバイナリ、'
                            'または未管理のソフトウェアである可能性があります。'
                        ),
                        mitre_key="net_unsigned",
                        normal_vs_abnormal=(
                            '【正常】自社開発ツール、OSSアプリ、スクリプト言語の実行ファイル等は'
                            '署名されていないことがあります。\n'
                            '【異常】見覚えのないファイル名、Temp/AppData/Downloads配下の'
                            '未署名EXEが外部通信している場合は高リスク。\n'
                            '【判断基準】ファイルパスが標準インストール先か？自分でインストールしたか？'
                        ),
                        next_steps=[
                            'ファイルのハッシュ値(SHA256)を取得し、VirusTotalで照会する',
                            'ファイルの作成日時・更新日時を確認する',
                            '「DNA」タブでファイルのエントロピーを確認する（高エントロピー=パック/暗号化）',
                            '接続先IPの評判を確認する',
                        ],
                        status='WARNING',
                    ),
                })

        # 最も危険度の高い結果を返す
        if not findings:
            return {
                'status': 'SAFE',
                'reason': '',
                'desc': build_tutor_desc(
                    detection='この接続に不審な点は検出されませんでした。',
                    why_dangerous='',
                    normal_vs_abnormal=(
                        '正常な通信パターンです。署名済みプロセスによる'
                        '標準ポートでの通信、またはローカル接続です。'
                    ),
                    status='SAFE',
                ),
            }

        # DANGER > WARNING > SAFE の優先順位
        danger = [f for f in findings if f['status'] == 'DANGER']
        warning = [f for f in findings if f['status'] == 'WARNING']

        if danger:
            result = danger[0]
            others = [f['reason'] for f in findings[1:]
                      if f['reason'] != result['reason']]
            if others:
                result['desc'] += '\n\n追加検知:\n' + '\n'.join(
                    '・' + r for r in others)
            return result
        elif warning:
            result = warning[0]
            others = [f['reason'] for f in findings[1:]
                      if f['reason'] != result['reason']]
            if others:
                result['desc'] += '\n\n追加検知:\n' + '\n'.join(
                    '・' + r for r in others)
            return result

        return {
            'status': 'SAFE',
            'reason': '',
            'desc': '',
        }

    def _is_local_ip(self, ip):
        """プライベートIP/ローカルIPか判定"""
        if not ip:
            return True
        if ip.startswith('127.') or ip == '::1':
            return True
        if ip.startswith('10.'):
            return True
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            try:
                second = int(ip.split('.')[1])
                if 16 <= second <= 31:
                    return True
            except Exception:
                pass
        if ip.startswith('169.254.'):
            return True
        if ip.startswith('fe80:') or ip.startswith('::'):
            return True
        if ip == '0.0.0.0' or ip == '::':
            return True
        return False

    def _reverse_dns(self, ip):
        """逆引きDNS（キャッシュ付き・タイムアウト2秒）"""
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1)
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                result = host if host != ip else ''
            finally:
                socket.setdefaulttimeout(old_timeout)
        except Exception:
            result = ''
        self._dns_cache[ip] = result
        return result

    def _batch_reverse_dns(self, ips):
        """逆引きDNSをバッチ並列実行"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        unique_ips = set(ip for ip in ips if ip and not self._is_local_ip(ip) and ip not in self._dns_cache)
        if not unique_ips:
            return
        def resolve(ip):
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(1)
                try:
                    host, _, _ = socket.gethostbyaddr(ip)
                    return ip, (host if host != ip else '')
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except Exception:
                return ip, ''
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(resolve, ip): ip for ip in unique_ips}
            for f in as_completed(futures):
                ip, hostname = f.result()
                self._dns_cache[ip] = hostname


    def _is_trusted_path(self, path):
        """信頼パス判定（Program Files, System32等の正規ディレクトリ）"""
        if not path:
            return False
        p = path.lower()
        trusted_dirs = [
            'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
            'c:\\program files\\', 'c:\\program files (x86)\\',
            'c:\\windows\\microsoft.net\\', 'c:\\windows\\winsxs\\',
        ]
        return any(p.startswith(d) for d in trusted_dirs)
    def _check_signature(self, exe_path):
        """デジタル署名の検証（キャッシュ付き）"""
        if exe_path in self._sig_cache:
            return self._sig_cache[exe_path]

        if not exe_path or not os.path.exists(exe_path):
            self._sig_cache[exe_path] = '不明'
            return '不明'

        # 信頼パスは検証スキップ
        _pl = exe_path.lower()
        _trusted = ['c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
                     'c:\\program files\\', 'c:\\program files (x86)\\',
                     'c:\\windows\\winsxs\\', 'c:\\windows\\microsoft.net\\']
        if any(_pl.startswith(d) for d in _trusted):
            self._sig_cache[exe_path] = '署名済み'
            return '署名済み'

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'(Get-AuthenticodeSignature "{exe_path}").Status'],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            status_text = result.stdout.strip()
            if status_text == 'Valid':
                sig = '署名済み'
            elif status_text == 'NotSigned':
                sig = '未署名'
            elif status_text == 'HashMismatch':
                sig = '改ざん疑い'
            elif status_text == 'UnknownError':
                sig = '検証不能'
            else:
                sig = status_text or '不明'
        except subprocess.TimeoutExpired:
            sig = 'タイムアウト'
        except Exception:
            sig = '不明'

        self._sig_cache[exe_path] = sig
        return sig

    def _batch_check_signatures(self, exe_paths):
        """デジタル署名をバッチ検証（PowerShell1回で全exe処理）"""
        unchecked = []
        _trusted_dirs = [
            'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
            'c:\\program files\\', 'c:\\program files (x86)\\',
            'c:\\windows\\winsxs\\', 'c:\\windows\\microsoft.net\\',
        ]
        for p in set(exe_paths):
            if not p or p in self._sig_cache:
                continue
            pl = p.lower()
            if any(pl.startswith(d) for d in _trusted_dirs):
                self._sig_cache[p] = '署名済み'  # 信頼パスはスキップ
            elif os.path.exists(p):
                unchecked.append(p)
        if not unchecked:
            return
        ps_lines = []
        for p in unchecked:
            safe_path = p.replace("'", "''")
            ps_lines.append(f"'{safe_path}|' + (Get-AuthenticodeSignature '{safe_path}').Status")
        ps_script = '; '.join(ps_lines)
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True, text=True, timeout=max(10, len(unchecked) * 3),
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            status_map = {'Valid': '署名済み', 'NotSigned': '未署名',
                          'HashMismatch': '改ざん疑い', 'UnknownError': '検証不能'}
            for line in result.stdout.strip().splitlines():
                if '|' in line:
                    path_part, status_part = line.rsplit('|', 1)
                    self._sig_cache[path_part] = status_map.get(status_part.strip(), status_part.strip() or '不明')
        except subprocess.TimeoutExpired:
            for p in unchecked:
                self._sig_cache.setdefault(p, 'タイムアウト')
        except Exception:
            for p in unchecked:
                self._sig_cache.setdefault(p, '不明')
        for p in unchecked:
            self._sig_cache.setdefault(p, '不明')
