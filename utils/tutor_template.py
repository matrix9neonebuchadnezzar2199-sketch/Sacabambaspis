# -*- coding: utf-8 -*-
"""
Sacabambaspis Tutor Template - P16: 解説構造統一テンプレート
全コレクターの検知結果に統一的な解説構造を提供する。

【解説フォーマット仕様】
各検知結果の "desc" フィールドは以下の5セクションで構成する:

  【検知内容】 ... 何が検知されたか（事実のみ、簡潔に）
  【なぜ危険か】 ... 攻撃者がどう悪用するか、正常との違い
  【MITRE ATT&CK】 ... Technique ID + 簡易説明（該当する場合）
  【正常 vs 異常の判断ポイント】 ... 初心者が判断に迷うポイントを明示
  【次の調査手順】 ... ①②③の番号付きステップ

status が SAFE の場合は【検知内容】+【正常 vs 異常の判断ポイント】のみでよい。
status が INFO の場合は【検知内容】+【なぜ危険か】+【正常 vs 異常の判断ポイント】。
status が WARNING/DANGER の場合は全5セクション必須。
"""


# MITRE ATT&CK マッピング（P17で拡充予定、P16では主要なものを先行定義）
MITRE_MAP = {
    # Memory
    "mem_rwx_anon":       ("T1055",     "Process Injection",
                           "https://attack.mitre.org/techniques/T1055/"),
    "mem_rwx_named":      ("T1055.001", "DLL Injection",
                           "https://attack.mitre.org/techniques/T1055/001/"),

    # BinaryRename (P43)
    "binrename_lolbin":   ("T1036.003", "Masquerading: Rename System Utilities",
                           "https://attack.mitre.org/techniques/T1036/003/"),
    "binrename_attack_tool": ("T1036.003", "Masquerading: Rename System Utilities",
                           "https://attack.mitre.org/techniques/T1036/003/"),

    # Network
    "net_attack_tool":    ("T1219",     "Remote Access Software",
                           "https://attack.mitre.org/techniques/T1219/"),
    "net_lolbin":         ("T1218",     "System Binary Proxy Execution",
                           "https://attack.mitre.org/techniques/T1218/"),
    "net_blacklist_port": ("T1571",     "Non-Standard Port",
                           "https://attack.mitre.org/techniques/T1571/"),
    "net_nonstandard":    ("T1571",     "Non-Standard Port",
                           "https://attack.mitre.org/techniques/T1571/"),
    "net_beaconing":      ("T1071.001", "Web Protocols (C2)",
                           "https://attack.mitre.org/techniques/T1071/001/"),
    "net_mass_conn":      ("T1046",     "Network Service Discovery",
                           "https://attack.mitre.org/techniques/T1046/"),
    "net_account_anomaly":("T1078",     "Valid Accounts",
                           "https://attack.mitre.org/techniques/T1078/"),
    "net_unsigned":       ("T1036",     "Masquerading",
                           "https://attack.mitre.org/techniques/T1036/"),

    # ADS (Zone.Identifier)
    "ads_inet_exe":       ("T1566.001", "Phishing: Spearphishing Attachment",
                           "https://attack.mitre.org/techniques/T1566/001/"),
    "ads_inet_archive":   ("T1553.005", "Mark-of-the-Web Bypass",
                           "https://attack.mitre.org/techniques/T1553/005/"),
    "ads_inet_office":    ("T1566.001", "Phishing: Spearphishing Attachment",
                           "https://attack.mitre.org/techniques/T1566/001/"),

    # PCA
    "pca_attack_tool":    ("T1588.002", "Obtain Capabilities: Tool",
                           "https://attack.mitre.org/techniques/T1588/002/"),
    "pca_suspicious_path":("T1036.005", "Masquerading: Match Legitimate Location",
                           "https://attack.mitre.org/techniques/T1036/005/"),

    # WSL
    "wsl_installed":      ("T1202",     "Indirect Command Execution",
                           "https://attack.mitre.org/techniques/T1202/"),
    "wsl_distro":         ("T1202",     "Indirect Command Execution",
                           "https://attack.mitre.org/techniques/T1202/"),
    "wsl_vhdx":           ("T1564.006", "Hide Artifacts: Run Virtual Instance",
                           "https://attack.mitre.org/techniques/T1564/006/"),
    "wsl_history":        ("T1059.004", "Command and Scripting: Unix Shell",
                           "https://attack.mitre.org/techniques/T1059/004/"),

    # Recall
    "recall_enabled":     ("T1119",     "Automated Collection",
                           "https://attack.mitre.org/techniques/T1119/"),
    "recall_db_large":    ("T1119",     "Automated Collection",
                           "https://attack.mitre.org/techniques/T1119/"),
    "recall_process":     ("T1119",     "Automated Collection",
                           "https://attack.mitre.org/techniques/T1119/"),

    # Registry
    "reg_attack_tool":    ("T1547.001", "Boot/Logon Autostart: Registry Run Keys",
                           "https://attack.mitre.org/techniques/T1547/001/"),
    "reg_lolbin_args":    ("T1059.001", "PowerShell",
                           "https://attack.mitre.org/techniques/T1059/001/"),
    "reg_lolbin_path":    ("T1547.001", "Boot/Logon Autostart: Registry Run Keys",
                           "https://attack.mitre.org/techniques/T1547/001/"),

    # Process
    "proc_attack_tool":   ("T1588.002", "Obtain Capabilities: Tool",
                           "https://attack.mitre.org/techniques/T1588/002/"),
    "proc_lolbin":        ("T1218",     "System Binary Proxy Execution",
                           "https://attack.mitre.org/techniques/T1218/"),
    "proc_injection":     ("T1055",     "Process Injection",
                           "https://attack.mitre.org/techniques/T1055/"),
    "proc_parent_anomaly":("T1036",     "Masquerading",
                           "https://attack.mitre.org/techniques/T1036/"),

    # Persistence
    "pers_service":       ("T1543.003", "Create or Modify System Process: Windows Service",
                           "https://attack.mitre.org/techniques/T1543/003/"),
    "pers_scheduled_task":("T1053.005", "Scheduled Task",
                           "https://attack.mitre.org/techniques/T1053/005/"),
    "pers_wmi":           ("T1546.003", "WMI Event Subscription",
                           "https://attack.mitre.org/techniques/T1546/003/"),
    "pers_startup":       ("T1547.001", "Registry Run Keys / Startup Folder",
                           "https://attack.mitre.org/techniques/T1547/001/"),

    # EventLog
    "evt_log_clear":      ("T1070.001", "Indicator Removal: Clear Windows Event Logs",
                           "https://attack.mitre.org/techniques/T1070/001/"),
    "evt_brute_force":    ("T1110",     "Brute Force",
                           "https://attack.mitre.org/techniques/T1110/"),
    "evt_new_service":    ("T1543.003", "Windows Service",
                           "https://attack.mitre.org/techniques/T1543/003/"),
    "evt_powershell":     ("T1059.001", "PowerShell",
                           "https://attack.mitre.org/techniques/T1059/001/"),

    # Evidence
    "evid_prefetch":      ("T1059",     "Command and Scripting Interpreter",
                           "https://attack.mitre.org/techniques/T1059/"),
    "evid_amcache":       ("T1218",     "System Binary Proxy Execution",
                           "https://attack.mitre.org/techniques/T1218/"),

    # DNA (Entropy)
    "dna_high_entropy":   ("T1027",     "Obfuscated Files or Information",
                           "https://attack.mitre.org/techniques/T1027/"),
    "dna_packed":         ("T1027.002", "Software Packing",
                           "https://attack.mitre.org/techniques/T1027/002/"),

    # SRUM
    "srum_high_network":  ("T1041",     "Exfiltration Over C2 Channel",
                           "https://attack.mitre.org/techniques/T1041/"),
    "srum_suspicious_app":("T1204",     "User Execution",
                           "https://attack.mitre.org/techniques/T1204/"),

    # CAM
    "cam_suspicious":     ("T1003",     "OS Credential Dumping",
                           "https://attack.mitre.org/techniques/T1003/"),
    "evt_priv_escalation": ("T1078.003", "Valid Accounts: Local Accounts", "https://attack.mitre.org/techniques/T1078/003/"),
    "evt_process_create": ("T1059", "Command and Scripting Interpreter", "https://attack.mitre.org/techniques/T1059/"),
    "evt_app_uninstall": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "https://attack.mitre.org/techniques/T1562/001/"),
    "evid_userassist_tool": ("T1218", "System Binary Proxy Execution", "https://attack.mitre.org/techniques/T1218/"),
    "evid_userassist_recon": ("T1087", "Account Discovery", "https://attack.mitre.org/techniques/T1087/"),
    "evid_userassist_path": ("T1036.005", "Masquerading: Match Legitimate Name or Location", "https://attack.mitre.org/techniques/T1036/005/"),
    "evid_prefetch_tool": ("T1588.002", "Obtain Capabilities: Tool", "https://attack.mitre.org/techniques/T1588/002/"),
    "evid_prefetch_lolbin": ("T1218", "System Binary Proxy Execution", "https://attack.mitre.org/techniques/T1218/"),
    "evid_prefetch_recon": ("T1087", "Account Discovery", "https://attack.mitre.org/techniques/T1087/"),
    "dna_encrypted": ("T1486", "Data Encrypted for Impact", "https://attack.mitre.org/techniques/T1486/"),
}


def build_tutor_desc(detection, why_dangerous, mitre_key=None,
                     normal_vs_abnormal=None, next_steps=None,
                     status="DANGER"):
    """
    統一フォーマットで desc 文字列を生成する。

    Args:
        detection: str - 【検知内容】に表示するテキスト
        why_dangerous: str - 【なぜ危険か】に表示するテキスト
        mitre_key: str|None - MITRE_MAP のキー（Noneなら省略）
        normal_vs_abnormal: str|None - 【正常 vs 異常の判断ポイント】
        next_steps: list[str]|None - 【次の調査手順】のステップリスト
        status: str - SAFE/INFO/WARNING/DANGER

    Returns:
        str - 統一フォーマットの解説文字列
    """
    parts = []

    # 【検知内容】 - 全ステータスで必須
    parts.append(f"【検知内容】{detection}")

    # SAFE は最小限
    if status == "SAFE":
        if normal_vs_abnormal:
            parts.append(f"\n【正常 vs 異常の判断ポイント】{normal_vs_abnormal}")
        return "\n".join(parts)

    # 【なぜ危険か】 - INFO以上で必須
    if why_dangerous:
        parts.append(f"\n【なぜ危険か】{why_dangerous}")

    # 【MITRE ATT&CK】 - WARNING/DANGER で該当する場合
    if mitre_key and mitre_key in MITRE_MAP:
        tid, tname, turl = MITRE_MAP[mitre_key]
        parts.append(f"\n【MITRE ATT&CK】{tid} - {tname}\n  参照: {turl}")

    # 【正常 vs 異常の判断ポイント】 - 全ステータスで推奨
    if normal_vs_abnormal:
        parts.append(f"\n【正常 vs 異常の判断ポイント】{normal_vs_abnormal}")

    # 【次の調査手順】 - WARNING/DANGER で必須
    if next_steps and status in ("WARNING", "DANGER"):
        steps_text = "\n".join(f"  ① ② ③ ④ ⑤"[i] + f" {s}"
                               if i < 5 else f"  ⑤ {s}"
                               for i, s in enumerate(next_steps))
        # 上の方法だとずれるので直接番号を振る
        circled = "①②③④⑤⑥⑦⑧⑨⑩"
        lines = []
        for i, step in enumerate(next_steps):
            num = circled[i] if i < len(circled) else f"({i+1})"
            lines.append(f"  {num} {step}")
        parts.append("\n【次の調査手順】\n" + "\n".join(lines))

    return "\n".join(parts)
