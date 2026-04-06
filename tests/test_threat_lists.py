# -*- coding: utf-8 -*-
from utils import threat_lists as tl


def test_binary_rename_hardcore_includes_core_tools():
    h = tl.BINARY_RENAME_HARDCORE_SUBSTRINGS
    assert "mimikatz" in h
    assert "nc" in h
    assert "netcat" in h
    assert "rclone" in h
    assert "adfind" in h


def test_binary_rename_hardcore_excludes_bare_net():
    assert "net" not in tl.BINARY_RENAME_HARDCORE_SUBSTRINGS


def test_path_contains_suspicious_fragment():
    assert tl.path_contains_suspicious_fragment(r"c:\users\x\appdata\local\temp\a".lower())
    assert not tl.path_contains_suspicious_fragment(r"c:\windows\system32\notepad.exe".lower())
