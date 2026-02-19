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

def main():
    enable_colors()
    print_banner()
    try:
        log_dir = os.path.join(BASE_DIR, "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            print(f"[*] Init: Log directory created at {log_dir}")
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("\033[93m[!] WARNING: Not running as Administrator. Deep scan may fail.\033[0m")
        except:
            pass
        print("[*] Loading modules...")
        from web.app import start_server_only
        start_server_only()
    except Exception:
        print("\n" + "!" * 60)
        print("【 CRITICAL ERROR 】")
        print("!" * 60)
        traceback.print_exc()
        print("!" * 60)
        print("\nPress Enter to exit...")
        try:
            input()
        except:
            import time; time.sleep(10)
        sys.exit(1)

if __name__ == "__main__":
    main()
