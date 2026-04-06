import os
import sys


def _development_base_path():
    """utils/ の1つ上 = プロジェクトルート（CWD に依存しない）"""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)


def resource_path(relative_path):
    """PyInstaller の一時フォルダと開発時のプロジェクトルートを振り分ける"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = _development_base_path()
    return os.path.join(base_path, relative_path)
