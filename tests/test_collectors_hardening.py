# -*- coding: utf-8 -*-
"""collectors ハードニング（mutex プレースホルダ・Prefetch ヌル分割）の回帰テスト。"""

from collectors.mutant import MutantCollector


def test_mutant_no_placeholder_mutex_keys():
    m = MutantCollector()
    keys = m.known_mutexes.keys()
    assert "YOURMALWARE" not in keys
    assert "DC_MUTEX-XXXXXXX" not in keys
    assert "Remcos-XXXXXX" not in keys
    assert "YOURBEAUTIFULKEY" not in keys
    assert "Global\\YOURBEAUTIFULKEY" not in keys


def test_prefetch_null_split_uses_real_null_byte():
    text = "a\x00b\x00"
    files = [f.strip() for f in text.split("\x00") if f.strip()]
    assert files == ["a", "b"]
    wrong = [f.strip() for f in text.split("\\x00") if f.strip()]
    assert wrong != ["a", "b"]
