# -*- coding: utf-8 -*-
# collectors/process.py - P7+P17: プロセス判別強化版 + 統一解説+MITREマッピング
# ERR-P7-001〜P7-005: プロセス解析エラー系
import psutil
import os
from datetime import datetime
from utils.tutor_template import build_tutor_desc


class ProcessCollector:
    def __init__(self):
        self.legitimate_parents = {
            "svchost.exe":      ["services.exe"],
            "smss.exe":         ["system", "smss.exe"],
            "csrss.exe":        ["smss.exe"],
            "wininit.exe":      ["smss.exe"],
            "winlogon.exe":     ["smss.exe"],
            "lsass.exe":        ["wininit.exe"],
            "services.exe":     ["wininit.exe"],
            "taskhostw.exe":    ["svchost.exe"],
            "runtimebroker.exe":["svchost.exe"],
            "dllhost.exe":      ["svchost.exe"],
            "sihost.exe":       ["svchost.exe"],
            "fontdrvhost.exe":  ["wininit.exe", "winlogon.exe"],
        }

        self.suspicious_parent_names = [
            "winword.exe", "excel.exe", "powerpnt.exe",
            "powershell.exe", "cmd.exe", "wscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe",
            "cscript.exe", "certutil.exe",
        ]

        self.system_process_valid_paths = {
            "svchost.exe":   [r"c:\windows\system32"],
            "lsass.exe":     [r"c:\windows\system32"],
            "csrss.exe":     [r"c:\windows\system32"],
            "services.exe":  [r"c:\windows\system32"],
            "smss.exe":      [r"c:\windows\system32"],
            "wininit.exe":   [r"c:\windows\system32"],
            "winlogon.exe":  [r"c:\windows\system32"],
            "explorer.exe":  [r"c:\windows"],
            "taskhostw.exe": [r"c:\windows\system32"],
            "spoolsv.exe":   [r"c:\windows\system32"],
            "lsm.exe":       [r"c:\windows\system32"],
        }

        self.suspicious_paths = [
            'users\\public', '\\appdata\\local\\temp',
            '\\appdata\\roaming', '\\programdata',
            '\\downloads', '\\music', '\\videos',
            '\\pictures', 'recycle.bin', '\\perflogs',
        ]

        self.known_system_names = [
            "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
            "explorer.exe", "winlogon.exe", "smss.exe", "taskhostw.exe",
            "spoolsv.exe", "wininit.exe", "dllhost.exe", "conhost.exe",
        ]
        self.typosquat_patterns = {
            "svchost.exe":  ["svch0st.exe", "scvhost.exe", "svchosl.exe",
                             "svchosts.exe", "svc_host.exe", "svchostt.exe"],
            "csrss.exe":    ["cssrs.exe", "csrs.exe", "crsss.exe", "csrsc.exe"],
            "lsass.exe":    ["lssas.exe", "lsas.exe", "lsass_.exe", "isass.exe"],
            "services.exe": ["service.exe", "servlces.exe", "serv1ces.exe"],
            "explorer.exe": ["explor3r.exe", "explorar.exe", "iexplore.exe"],
            "winlogon.exe": ["winlog0n.exe", "winiogon.exe", "winloqon.exe"],
            "smss.exe":     ["smsc.exe", "snss.exe"],
            "dllhost.exe":  ["dlihost.exe", "dl1host.exe", "dllh0st.exe"],
            "conhost.exe":  ["conh0st.exe", "c0nhost.exe"],
        }

    def scan(self):
        """メインスキャンループ"""
        process_list = []
        attrs = ['pid', 'name', 'exe', 'username', 'create_time', 'cmdline', 'ppid']

        pid_name_map = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid_name_map[proc.info['pid']] = proc.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for proc in psutil.process_iter(attrs):
            try:
                p_info = proc.info
                if not p_info['exe']:
                    continue

                ppid = p_info.get('ppid', 0)
                parent_name = pid_name_map.get(ppid, "unknown")
                findings = self._analyze_process(p_info, parent_name)
                status, reason, description = self._select_worst(findings)

                ct = p_info.get('create_time')
                if ct:
                    create_dt = datetime.fromtimestamp(ct).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    create_dt = "Unknown"

                entry = {
                    "type": "Process",
                    "pid": p_info['pid'],
                    "name": p_info['name'],
                    "path": p_info['exe'],
                    "username": p_info['username'] or "SYSTEM",
                    "parent": f"{parent_name} (PID:{ppid})",
                    "time": create_dt,
                    "status": status,
                    "reason": reason,
                    "desc": description,
                }
                process_list.append(entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return sorted(process_list, key=lambda x: x['pid'])

    def _analyze_process(self, info, parent_name):
        findings = []
        path_lower = info['exe'].lower()
        name_lower = info['name'].lower()
        parent_lower = parent_name.lower()

        # Rule-1: システムプロセスの正規パス検証
        if name_lower in self.system_process_valid_paths:
            valid_paths = self.system_process_valid_paths[name_lower]
            path_dir = os.path.dirname(path_lower)
            if not any(path_dir.startswith(vp) for vp in valid_paths):
                findings.append((
                    100, "DANGER",
                    f"正規パス偽装 (Masquerading): {info['name']}",
                    build_tutor_desc(
                        detection=(
                            f"プロセス「{info['name']}」は本来「{valid_paths[0]}」に"
                            f"存在すべきですが、「{os.path.dirname(info['exe'])}」から"
                            f"実行されています。PID: {info['pid']}"
                        ),
                        why_dangerous=(
                            "攻撃者はマルウェアにWindowsシステムファイルと同じ名前を付け、"
                            "別のフォルダに配置することで、監視ツールやセキュリティソフトの"
                            "目を欺こうとします。これは「Masquerading（なりすまし）」と呼ばれ、"
                            "防御回避の代表的な手法です。"
                        ),
                        mitre_key="proc_parent_anomaly",
                        normal_vs_abnormal=(
                            f"【正常】{info['name']}は必ず{valid_paths[0]}に存在します。"
                            "例外はありません。\n"
                            "【異常】正規パス以外からの実行は100%異常です。\n"
                            "【判断基準】パスが正規の場所かどうかだけで判断可能。"
                        ),
                        next_steps=[
                            "ファイルのハッシュ値(SHA-256)を取得しVirusTotalで検索する",
                            "ファイルのデジタル署名を確認する（正規品はMicrosoft署名付き）",
                            "「ネットワーク」タブでこのプロセスの外部通信を確認する",
                            "「メモリ」タブでRWXインジェクションがないか確認する",
                        ],
                        status="DANGER",
                    ),
                ))

        # Rule-2: ファイル名偽装検知（タイポスクワッティング）
        typo_result = self._check_typosquatting(name_lower)
        if typo_result:
            findings.append((
                95, "DANGER",
                f"ファイル名偽装 (Typosquatting): {info['name']} → {typo_result['similar_to']}",
                build_tutor_desc(
                    detection=(
                        f"プロセス名「{info['name']}」は正規のシステムファイル"
                        f"「{typo_result['similar_to']}」に酷似していますが、"
                        f"スペルが異なります（{typo_result['reason']}）。\n"
                        f"パス: {info['exe']}"
                    ),
                    why_dangerous=(
                        f"攻撃者は「svchost.exe」を「svch0st.exe」のように"
                        "1-2文字だけ変えた名前を使い、管理者やセキュリティソフトの"
                        "目視チェックをすり抜けようとします。"
                        "目視では見逃しやすく、自動検知が重要です。"
                    ),
                    mitre_key="proc_parent_anomaly",
                    normal_vs_abnormal=(
                        "【正常】タイポスクワッティング検知は誤検知の可能性が極めて低いです。\n"
                        "【異常】正規のシステムプロセスと1-2文字違いのプロセスは"
                        "ほぼ確実にマルウェアです。\n"
                        "【判断基準】ファイルのデジタル署名を確認。Microsoft署名がなければ偽物。"
                    ),
                    next_steps=[
                        f"ファイルの実体パス「{info['exe']}」を確認する",
                        "ファイルのプロパティで作成日時・デジタル署名を確認する",
                        f"親プロセス（{parent_name}）が正当かどうか確認する",
                        "ファイルのハッシュ値をVirusTotalで検索する",
                    ],
                    status="DANGER",
                ),
            ))

        # Rule-3: 親子関係の異常検知
        if name_lower in self.legitimate_parents:
            legit_parents = self.legitimate_parents[name_lower]
            if parent_lower not in legit_parents and parent_lower != "unknown":
                findings.append((
                    90, "DANGER",
                    f"親子関係の異常: {parent_name} → {info['name']}",
                    build_tutor_desc(
                        detection=(
                            f"プロセス「{info['name']}」(PID:{info['pid']})の親プロセスが"
                            f"「{parent_name}」です。正規の親プロセスは"
                            f"「{', '.join(legit_parents)}」のはずです。"
                        ),
                        why_dangerous=(
                            "Windowsの重要プロセスは決まった親プロセスからのみ起動されます。"
                            "例えば svchost.exe は必ず services.exe から起動されます。"
                            "これが崩れている場合、攻撃者がマルウェアから直接システムプロセスを"
                            "起動（プロセスインジェクション）した可能性があります。"
                        ),
                        mitre_key="proc_injection",
                        normal_vs_abnormal=(
                            f"【正常】{info['name']}の親は{', '.join(legit_parents)}のみ。\n"
                            f"【異常】親が{parent_name}であることは異常です。"
                            "プロセスインジェクションまたはマルウェアからの起動が疑われます。\n"
                            "【判断基準】親プロセスが正規リストに含まれるか確認。"
                        ),
                        next_steps=[
                            f"親プロセス「{parent_name}(PID:{info.get('ppid',0)})」自体が正当か確認する",
                            "「メモリ」タブでこのプロセスのRWXメモリ領域がないか確認する",
                            "「イベントログ」タブでプロセス作成イベント(4688)を確認する",
                            "プロセスツリー全体を確認し、不審な起点を特定する",
                        ],
                        status="DANGER",
                    ),
                ))

        # 不審な親プロセスからの起動
        if parent_lower in [p.lower() for p in self.suspicious_parent_names]:
            if name_lower not in ['conhost.exe', 'cmd.exe', 'powershell.exe']:
                findings.append((
                    85, "WARNING",
                    f"不審な親プロセス: {parent_name} → {info['name']}",
                    build_tutor_desc(
                        detection=(
                            f"プロセス「{info['name']}」(PID:{info['pid']})が"
                            f"「{parent_name}」から起動されています。"
                        ),
                        why_dangerous=(
                            "Officeアプリ(Word/Excel)やスクリプトエンジン(PowerShell/cmd)が"
                            "子プロセスを生成することは、マクロ攻撃やLOLBins攻撃の"
                            "典型的なパターンです。特にメール添付ファイルを開いた後に"
                            "この組み合わせが出現する場合は要注意です。"
                        ),
                        mitre_key="proc_lolbin",
                        normal_vs_abnormal=(
                            "【正常】管理者がPowerShellから意図的にツールを起動した場合。"
                            "cmdからプログラムを実行した場合。\n"
                            "【異常】Word/Excelから不明なプロセスが起動。"
                            "mshta/rundll32/regsvr32からの子プロセス生成。\n"
                            "【判断基準】ユーザーが意図的に操作したか？"
                            "Office文書を開いた直後か？"
                        ),
                        next_steps=[
                            "直前にメールの添付ファイルやダウンロードファイルを開いていないか確認する",
                            "「永続化」タブでこのプロセスが自動起動に登録されていないか確認する",
                            "「ネットワーク」タブで外部通信がないか確認する",
                        ],
                        status="WARNING",
                    ),
                ))

        # Rule-4: 不審な実行パス
        for bad_path in self.suspicious_paths:
            if bad_path in path_lower:
                if name_lower in self.system_process_valid_paths:
                    pass
                else:
                    is_high_risk = ('users\\public' in bad_path
                                    or 'recycle.bin' in bad_path
                                    or 'perflogs' in bad_path)
                    severity = "DANGER" if is_high_risk else "WARNING"
                    priority = 75 if is_high_risk else 60

                    findings.append((
                        priority, severity,
                        f"不審なフォルダからの実行 ({bad_path})",
                        build_tutor_desc(
                            detection=(
                                f"プロセス「{info['name']}」(PID:{info['pid']})が"
                                f"「{info['exe']}」から実行されています。"
                            ),
                            why_dangerous=(
                                "正規のアプリケーションは通常「C:\\Program Files」や"
                                "「C:\\Windows\\System32」にインストールされます。"
                                f"「{bad_path}」はユーザー権限で書き込み可能なため、"
                                "マルウェアが好んで潜伏場所として利用します。"
                                + (" このフォルダは攻撃者が頻繁にマルウェアを配置する"
                                   "場所として特に知られています。"
                                   if is_high_risk else "")
                            ),
                            mitre_key="proc_attack_tool",
                            normal_vs_abnormal=(
                                "【正常】インストーラーの一時展開、"
                                "ユーザーがDownloadsから直接実行（自覚がある場合）。\n"
                                "【異常】見覚えのないexeがTemp/Public/ProgramDataで実行。"
                                "Recycle.Bin/PerfLogsからの実行は高確率で不正。\n"
                                "【判断基準】自分でインストール・実行した記憶があるか？"
                            ),
                            next_steps=[
                                "フォルダ内に他の不審なファイルがないか確認する",
                                "ファイルの作成日時がインシデント発生時期と一致するか確認する",
                                "「痕跡」タブでこのファイルの実行履歴(Prefetch)を確認する",
                                "ファイルのハッシュ値をVirusTotalで検索する",
                            ],
                            status=severity,
                        ),
                    ))
                    break

        # Rule-5: コマンドライン引数の異常検知
        cmdline = info.get('cmdline')
        if cmdline and isinstance(cmdline, list):
            cmd_str = ' '.join(cmdline).lower()

            if '-encodedcommand' in cmd_str or '-enc ' in cmd_str or '-e ' in cmd_str:
                if 'powershell' in cmd_str or 'pwsh' in cmd_str:
                    findings.append((
                        92, "DANGER",
                        "Base64エンコードされたPowerShellコマンド",
                        build_tutor_desc(
                            detection=(
                                f"プロセス「{info['name']}」(PID:{info['pid']})が"
                                "Base64エンコードされたPowerShellコマンドを実行しています。"
                            ),
                            why_dangerous=(
                                "攻撃者はマルウェアのコマンドをBase64でエンコードして"
                                "人間が読めないようにし、検知を回避します。"
                                "正規の管理スクリプトでもBase64を使うことはありますが、"
                                "予定外のものであれば調査が必要です。"
                            ),
                            mitre_key="evt_powershell",
                            normal_vs_abnormal=(
                                "【正常】IT管理者が配布する管理スクリプトで"
                                "-EncodedCommandを使用する場合がある。\n"
                                "【異常】予定外のBase64 PowerShellは高確率で攻撃。"
                                "特に-WindowStyle Hidden併用は要注意。\n"
                                "【判断基準】IT部門に確認し、承認済みスクリプトか確認。"
                            ),
                            next_steps=[
                                "Base64部分を抽出しデコードして内容を確認する",
                                "「イベントログ」タブでPowerShellログ(4104)にデコード済み内容を確認する",
                                "デコード結果にURL/IPがあればC2通信の可能性を調査する",
                            ],
                            status="DANGER",
                        ),
                    ))

            download_indicators = [
                'downloadstring', 'downloadfile', 'invoke-webrequest',
                'wget', 'curl', 'bitsadmin', 'certutil -urlcache',
            ]
            for indicator in download_indicators:
                if indicator in cmd_str:
                    findings.append((
                        88, "DANGER",
                        f"外部からのダウンロード実行: {indicator}",
                        build_tutor_desc(
                            detection=(
                                f"プロセス「{info['name']}」(PID:{info['pid']})が"
                                f"コマンドライン内でダウンロードコマンド"
                                f"「{indicator}」を使用しています。"
                            ),
                            why_dangerous=(
                                "攻撃者は初期侵入後、追加のマルウェア（ペイロード）を"
                                "外部サーバーからダウンロードして実行します。"
                                "これは「Ingress Tool Transfer」と呼ばれる手法です。"
                            ),
                            mitre_key="proc_lolbin",
                            normal_vs_abnormal=(
                                "【正常】管理者がcurl/wgetでファイル取得。"
                                "パッケージマネージャーの動作。\n"
                                "【異常】不明なプロセスからのダウンロード実行。"
                                "PowerShellのDownloadStringは攻撃で多用。\n"
                                "【判断基準】ダウンロード先URLが信頼できるか確認。"
                            ),
                            next_steps=[
                                "コマンドライン内のURL/IPアドレスを抽出する",
                                "URLをVirusTotal/AbuseIPDBで確認する",
                                "ダウンロードされたファイルの保存先を特定し内容を確認する",
                            ],
                            status="DANGER",
                        ),
                    ))
                    break

        return findings

    def _check_typosquatting(self, process_name_lower):
        if process_name_lower in [n.lower() for n in self.known_system_names]:
            return None
        for legit, fakes in self.typosquat_patterns.items():
            if process_name_lower in [f.lower() for f in fakes]:
                return {"similar_to": legit, "reason": "既知の偽装パターンに一致"}
        for legit in self.known_system_names:
            dist = self._levenshtein_distance(process_name_lower, legit.lower())
            if 0 < dist <= 2:
                return {"similar_to": legit,
                        "reason": f"文字列類似度: {legit}と{dist}文字の差異"}
        return None

    def _levenshtein_distance(self, s1, s2):
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def _select_worst(self, findings):
        if not findings:
            return "SAFE", "", ""
        findings.sort(key=lambda x: x[0], reverse=True)
        worst = findings[0]
        reasons = [f[2] for f in findings[:3]]
        combined_reason = " / ".join(reasons)
        description = worst[3]
        if len(findings) > 1:
            extra_reasons = [f[2] for f in findings[1:3]]
            description += "\n\n【追加の検知】" + " / ".join(extra_reasons)
        return worst[1], combined_reason, description
