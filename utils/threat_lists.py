# -*- coding: utf-8 -*-
"""
横断的ヒューリスティック用の単一ソース。
各コレクター（実行痕跡・レジストリ・ネットワーク・永続化・CAM・SRUM等）で
重複していたリストをここに集約する。

PE ファイル名照合テーブルは utils/binary_rename_table.py（BinaryRename 専用の行データ）。
高危険度 substring は BINARY_RENAME_HARDCORE_SUBSTRINGS（ATTACK_TOOLS 由来 + extras）。
"""

# プロセス名・パス断片に対する攻撃ツール・フレームワークのヒント（小文字比較が多い）
ATTACK_TOOLS = sorted(
    {
        "mimikatz",
        "psexec",
        "psexesvc",
        "paexec",
        "cobalt",
        "beacon",
        "rubeus",
        "seatbelt",
        "sharphound",
        "bloodhound",
        "lazagne",
        "procdump",
        "nanodump",
        "safetykatz",
        "sharpwmi",
        "covenant",
        "sliver",
        "brute",
        "crack",
        "hashcat",
        "john",
        "hydra",
        "nmap",
        "masscan",
        "crackmapexec",
        "evil-winrm",
        "chisel",
        "ligolo",
        "ngrok",
        "frp",
        "frpc",
        "frps",
        "netcat",
        "nc.exe",
        "plink",
        "socat",
        "rclone",
        "megasync",
        "advanced_ip_scanner",
        "angry_ip",
        "nbtscan",
        "empire",
        "meterpreter",
        "havoc",
        "bruteratel",
        "certify",
        "whisker",
        "impacket",
        "pypykatz",
        "wce",
        "gsecdump",
        "pwdump",
        "fgdump",
        "whoami",
        "net.exe",
        "certutil",
        "bitsadmin",
    }
)

# レジストリ値・コマンド行向け LOLBin 断片（registry / persistence の substring 照合）
LOLBINS = [
    "powershell",
    "pwsh",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "wmic",
    "msconfig",
    "installutil",
    "regasm",
    "regsvcs",
    "msbuild",
    "cmstp",
    "esentutl",
    "expand",
    "extrac32",
    "makecab",
    "replace",
    "xwizard",
    "msdt",
    "bash",
    "forfiles",
    "pcalua",
    "explorer.exe /root",
    "curl",
    "wget",
]

# ネットワーク collector: プロセス名の完全一致（小文字）
LOLBIN_PROCESS_NAMES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "rundll32.exe",
        "wscript.exe",
        "cscript.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msiexec.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
        "msconfig.exe",
        "msbuild.exe",
        "xwizard.exe",
        "ieexec.exe",
        "dnscmd.exe",
        "ftp.exe",
        "finger.exe",
        "bash.exe",
        "wsl.exe",
        "forfiles.exe",
        "pcalua.exe",
        "presentationhost.exe",
        "syncappvpublishingserver.exe",
        "hh.exe",
        "mmc.exe",
        "control.exe",
        "cmstp.exe",
        "wmic.exe",
    }
)

RECON_TOOLS = [
    "whoami",
    "systeminfo",
    "ipconfig",
    "net.exe",
    "net1.exe",
    "nltest",
    "dsquery",
    "csvde",
    "ldifde",
    "quser",
    "qwinsta",
    "query",
    "klist",
    "tasklist",
    "taskkill",
    "sc.exe",
    "schtasks",
    "reg.exe",
    "arp.exe",
    "route",
    "tracert",
    "netstat",
    "nslookup",
    "ping.exe",
]

# パスに含まれると不審扱いしやすい断片（小文字で比較）
SUSPICIOUS_PATH_FRAGMENTS = sorted(
    {
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
        "\\downloads\\",
        "\\perflogs\\",
        "\\programdata\\",
        "\\recycler\\",
        "\\$recycle.bin\\",
        "\\windows\\debug\\",
        "\\windows\\temp\\",
        "\\appdata\\roaming\\",
        "\\appdata\\local\\",
    }
)

SUSPICIOUS_ARGS = sorted(
    {
        "-enc ",
        "-encodedcommand",
        "-nop",
        "-noprofile",
        "-windowstyle hidden",
        "-w hidden",
        "-ep bypass",
        "-executionpolicy bypass",
        "base64",
        "invoke-expression",
        "iex ",
        "downloadstring",
        "downloadfile",
        "net.webclient",
        "http://",
        "https://",
        "frombase64string",
        "start-process",
        "new-object",
        "io.memorystream",
    }
)

# process.py Rule-4: 実行パス断片（SUSPICIOUS_PATH_FRAGMENTS に加え Office 系ユーザーフォルダ等）
PROCESS_SUSPICIOUS_PATH_SUBSTRINGS = sorted(
    set(SUSPICIOUS_PATH_FRAGMENTS)
    | {
        "users\\public",
        "\\music",
        "\\videos",
        "\\pictures",
        "recycle.bin",
    }
)

# process.py: Office / スクリプト親からの子起動検知
SUSPICIOUS_PARENT_PROCESS_NAMES = [
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "cscript.exe",
    "certutil.exe",
]


def _build_binary_rename_hardcore_substrings():
    """
    BinaryRename の ANY 行で DANGER にする substring 集合。
    ATTACK_TOOLS をベースにし、PE InternalName/OriginalFilename に出やすい別名は extras で補う。
    substring 照合のため 3 文字未満は入れない（下記ショートトークン以外）。
    """
    extras = {
        "adfind",
        "remcom",
        "processhacker",
        "pchunter",
        "powertool",
        "chromepass",
        "wirelesskeyview",
        "wkv",
        "vncpassview",
        "iepv",
        "rdpv",
        "bulletspassview",
        "nircmd",
        "nsudo",
        "defender control",
    }
    short_ok = frozenset({"nc", "wce"})
    skip_stripped = frozenset({"net"})  # net.exe からの単独 net は誤爆しやすい

    out = set(extras)
    for t in ATTACK_TOOLS:
        tl = t.lower().strip()
        if not tl:
            continue
        out.add(tl)
        if tl.endswith(".exe"):
            base = tl[:-4]
            if len(base) >= 3 and base not in skip_stripped:
                out.add(base)
    for s in short_ok:
        out.add(s)
    return frozenset(out)


# collectors/binary_rename: ANY 行の DANGER 判定（単一ソース）
BINARY_RENAME_HARDCORE_SUBSTRINGS = _build_binary_rename_hardcore_substrings()


def path_contains_suspicious_fragment(path_lower: str) -> bool:
    """パス文字列に SUSPICIOUS_PATH_FRAGMENTS のいずれかが含まれるか（小文字のパスを渡すこと）。"""
    if not path_lower:
        return False
    pl = path_lower.replace("/", "\\")
    return any(frag in pl for frag in SUSPICIOUS_PATH_FRAGMENTS)
