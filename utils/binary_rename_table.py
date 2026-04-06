# -*- coding: utf-8 -*-
"""
Velociraptor Windows.Detection.BinaryRename 相当の PE 照合テーブル。
(filename, internal_name, original_filename, description)
filename == \"ANY\" は攻撃ツール行（ファイル名不問）。
"""
# Velociraptor Windows.Detection.BinaryRename テーブル移植
# (expected_filename, internal_name, original_filename, description)
# filename=ANY → どんなファイル名でも検知（攻撃ツール）
RENAME_TABLE = [
    # === システムツール（リネーム悪用） ===
    ("cmd.exe", "cmd", "Cmd.Exe", "Windows Command Processor"),
    ("powershell.exe", "POWERSHELL", "PowerShell.EXE", "Windows PowerShell"),
    ("certutil.exe", "CertUtil.exe", "CertUtil.exe", "CertUtil"),
    ("cscript.exe", "cscript.exe", "cscript.exe", "Console Based Script Host"),
    ("wscript.exe", "wscript.exe", "wscript.exe", "Windows Based Script Host"),
    ("mshta.exe", "MSHTA.EXE", "MSHTA.EXE", "HTML Application Host"),
    ("rundll32.exe", "rundll", "RUNDLL32.EXE", "Windows Rundll32"),
    ("regsvr32.exe", "REGSVR32", "REGSVR32.EXE", "Microsoft Register Server"),
    ("msiexec.exe", "msiexec", "msiexec.exe", "Windows Installer"),
    ("cmstp.exe", "CMSTP", "CMSTP.EXE", "Connection Manager Profile Installer"),
    ("wmic.exe", "wmic.exe", "wmic.exe", "WMI Commandline Utility"),
    ("net.exe", "net.exe", "net.exe", "Net Command"),
    ("net1.exe", "net1.exe", "net1.exe", "Net1 Command"),
    ("netsh.exe", "netsh.exe", "netsh.exe", "Network Shell"),
    ("wevtutil.exe", "wevtutil.exe", "wevtutil.exe", "Eventing Command Line Utility"),
    ("nltest.exe", "nltestrk.exe", "nltestrk.exe", "Logon Server Test Utility"),
    ("dsquery.exe", "dsquery.exe", "dsquery.exe", "AD DS/LDS Query Utility"),
    ("nbtstat.exe", "nbtinfo.exe", "nbtinfo.exe", "TCP/IP NetBios Information"),
    ("qprocess.exe", "qprocess", "qprocess.exe", "Query Process Utility"),
    ("qwinsta.exe", "qwinsta", "qwinsta.exe", "Query Session Utility"),
    ("7z.exe", "7z", "7z.exe", "7-Zip Console"),
    # === 攻撃ツール（ANY = ファイル名問わず検知） ===
    ("ANY", "nc", "nc.exe", "NetCat"),
    ("ANY", "AdFind.exe", "AdFind.exe", "Joeware ADFind"),
    ("ANY", "rclone", "rclone.exe", "Rsync for cloud storage"),
    ("ANY", "MEGAsync.exe", "MEGAsync.exe", "MEGAsync"),
    ("ANY", "mimikatz", "mimikatz.exe", "mimikatz"),
    ("ANY", "ProcDump", "procdump", "Sysinternals ProcDump"),
    ("ANY", "", "psexec.c", "Sysinternals PSExec"),
    ("ANY", "", "", "AnyDesk"),
    ("ANY", "", "", "Ammyy Admin"),
    ("ANY", "ProcessHacker.exe", "ProcessHacker.exe", "Process Hacker"),
    ("ANY", "ChromePass", "ChromePass", "Chrome Password Recovery"),
    ("ANY", "", "netscan.exe", "Network Scanner"),
    ("ANY", "WKV", "", "WirelessKeyView"),
    ("ANY", "rdpv.exe", "rdpv.exe", "RDP Password Recovery"),
    ("ANY", "RemCom", "RemCom.exe", "Remote Command Executor"),
    ("ANY", "", "winscp.com", "WinSCP Console"),
    ("ANY", "winscp", "winscp.exe", "WinSCP"),
    ("ANY", "iepv", "iepv.exe", "IE Passwords Viewer"),
    ("ANY", "VNCPassView", "VNCPassView.exe", "VNC Password Viewer"),
    ("ANY", "PCHunter", "PCHunter.exe", "PCHunter"),
    ("ANY", "Massscan_GUI.exe", "Massscan_GUI.exe", "Masscan GUI"),
    ("ANY", "PowerTool.exe", "PowerTool.exe", "Anti-rootkit Tool"),
    ("ANY", "BulletsPassView", "BulletsPassView.exe", "BulletsPassView"),
    ("ANY", "WinLister", "WinLister.exe", "WinLister"),
    ("ANY", "NirCmd", "NirCmd.exe", "NirCmd"),
    ("ANY", "NSudo", "NSudo.exe", "NSudo"),
    ("ANY", "Defender Control", "Defender Control", "Windows Defender Control"),
    # === リモートアクセス ===
    ("plink.exe", "Plink", "Plink", "SSH/Telnet Client"),
    ("pscp.exe", "PSCP", "PSCP", "SCP/SFTP Client"),
    ("psftp.exe", "PSFTP", "PSFTP", "Interactive SFTP Client"),
    ("psexec.exe", "PsExec", "psexec.c", "Sysinternals PSExec"),
    ("psexec64.exe", "PsExec", "psexec.exe", "Sysinternals PSExec 64-bit"),
    ("winrar.exe", "WinRAR", "WinRAR.exe", "WinRAR Archiver"),
]

# 誤検知抑制: 正規配置の Windows コンポーネントは LOLBin リネームとして報告しない
TRUSTED_PREFIX_DIRS = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)
