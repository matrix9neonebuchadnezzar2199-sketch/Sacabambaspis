# -*- coding: utf-8 -*-
"""utils/ioc_database: 正規化・照合・取込の単体テスト"""

import utils.ioc_database as ioc


def test_normalize_sha1_strips_0000_prefix():
    assert ioc.normalize_sha1("0000" + "a" * 40) == "a" * 40
    assert ioc.normalize_sha1("") == ""
    assert ioc.normalize_sha1("not-hex") == ""


def test_normalize_sha256_valid():
    h = "ab" * 32
    assert ioc.normalize_sha256(h) == h
    assert ioc.normalize_sha256(h.upper()) == h
    assert ioc.normalize_sha256("short") == ""


def test_check_sha1_builtin_hit():
    # IOC_SHA1_DATABASE の先頭エントリ（Mimikatz）
    h = "e7a2e86a1c28e1a0e98c1b2c4f87ab3fdfa8ce9a"
    r = ioc.check_sha1_ioc(h)
    assert r is not None
    assert r["matched"] is True
    assert r["source"] == "builtin"
    assert "Mimikatz" in r["name"]


def test_check_ioc_hash_dispatches_by_length():
    sha1 = "e7a2e86a1c28e1a0e98c1b2c4f87ab3fdfa8ce9a"
    r1 = ioc.check_ioc_hash(sha1)
    assert r1 is not None

    unknown256 = "0" * 64
    assert ioc.check_ioc_hash(unknown256) is None

    assert ioc.check_ioc_hash("bad") is None


def test_parse_ioc_import_text_sha256(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc, "USER_IOC_PATH", str(tmp_path / "user_ioc.json"))
    h = "a" * 64
    out = ioc.parse_ioc_import_text(f"{h},ImportedLabel\n", replace=True)
    assert out["sha256_added"] == 1
    assert h in ioc.USER_IOC_SHA256
    assert ioc.USER_IOC_SHA256[h]["name"] == "ImportedLabel"


def test_clear_user_iocs(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc, "USER_IOC_PATH", str(tmp_path / "user_ioc.json"))
    ioc.parse_ioc_import_text("a" * 64 + ",x\n", replace=True)
    assert len(ioc.USER_IOC_SHA256) >= 1
    ioc.clear_user_iocs()
    assert ioc.USER_IOC_SHA256 == {}
    assert ioc.USER_IOC_SHA1 == {}


def test_get_ioc_stats_keys():
    s = ioc.get_ioc_stats()
    assert "builtin_sha1" in s
    assert "user_sha256" in s
    assert s["builtin_sha1"] >= 1


def test_should_read_file_for_sha256_without_user_ioc(monkeypatch):
    monkeypatch.setattr(ioc, "USER_IOC_SHA256", {})
    monkeypatch.setattr(ioc, "IOC_SHA256_DATABASE", {})
    assert ioc.should_read_file_for_sha256_ioc() is False


def test_should_read_file_for_sha256_with_user_ioc(monkeypatch):
    monkeypatch.setattr(ioc, "USER_IOC_SHA256", {"a" * 64: {"name": "x"}})
    assert ioc.should_read_file_for_sha256_ioc() is True
