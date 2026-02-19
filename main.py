# -*- coding: utf-8 -*-
import sys
import os
import traceback
import platform

# 1. パス設定
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

def enable_colors():
    """ WindowsでANSIエスケープシーケンス（色）を有効にする """
    if platform.system() == 'Windows':
        os.system('')

def print_banner():
    # カラーコード定義
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

    # "SACA" だけデカく
    banner = rf"""{CYAN}
      _________  _____  _________   _____
     /   _____/ /  _  \ \_   ___ \ /  _  \
     \_____  \ /  /_\  \/    \  \//  /_\  \
     /        \/    |    \     \____/    |    \
    /_______  /\____|__  /\______  /\____|__  /
            \/         \/        \/         \/
    {RESET}"""

    print(banner)
    # 下に小さく続きを表示 & 顔文字
    print(f"{WHITE}             bambaspis {YELLOW}v3.2{RESET}")
    print(f"\n                                   {YELLOW}><(((( ﾟ <   ( ◉▼◉ )   > ﾟ ))))><{RESET}")
    print("-" * 70)
    print("   Target: APT / Malware / Rootkit Hunter")
    print("-" * 70)

def select_mode():
    """起動モード選択"""
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

    print(f"\n{CYAN}  [1]{RESET} Full Scan      - All 12 categories scan + launch browser")
    print(f"{CYAN}  [2]{RESET} Viewer Only    - Launch browser with last scan data (no scan)")
    print()

    while True:
        choice = input(f"  {YELLOW}Select mode (1/2): {RESET}").strip()
        if choice in ('1', '2'):
            return int(choice)
        print(f"  {YELLOW}Please enter 1 or 2.{RESET}")

def main():
    enable_colors()
    print_banner()

    try:
        # 2. ログフォルダ作成
        log_dir = os.path.join(BASE_DIR, "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            print(f"[*] Init: Log directory created at {log_dir}")

        # 3. 管理者権限チェック
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("\033[93m[!] WARNING: Not running as Administrator. Deep scan may fail.\033[0m")
        except:
            pass

        # 4. モード選択
        mode = select_mode()

        # 5. アプリ本体のインポート
        print("[*] Loading modules...")

        if mode == 1:
            from web.app import start_scan_and_server
            start_scan_and_server()
        else:
            from web.app import start_viewer_only
            start_viewer_only()

    except Exception:
        print("\n" + "!"*60)
        print("【 CRITICAL ERROR 】")
        print("!"*60)
        traceback.print_exc()
        print("!"*60)
        print("\nPress Enter to exit...")
        input()
        sys.exit(1)

if __name__ == "__main__":
    main()
