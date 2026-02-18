import sys
import os

def resource_path(relative_path):
    """ PyInstallerの一時フォルダパスと開発環境のパスを振り分ける """
    try:
        # PyInstallerで作成された一時フォルダ
        base_path = sys._MEIPASS
    except Exception:
        # 通常のPython実行環境
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
