# -*- coding: utf-8 -*-
from pathlib import Path

from utils import signature as sig


def test_deferred_returns_without_powershell(tmp_path):
    sig.clear_cache()
    p = tmp_path / "dummy.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)

    sig.set_deferred_signature_verify(True)
    try:
        st, signer = sig.verify_signature(str(p))
        assert st == "Deferred"
        assert signer == ""
    finally:
        sig.set_deferred_signature_verify(False)


def test_verify_signature_invokes_powershell_without_shell_true(monkeypatch):
    sig.clear_cache()
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = kwargs.get("shell")

        class R:
            stdout = "NotSigned|"
            stderr = ""

        return R()

    monkeypatch.setattr(sig.subprocess, "run", fake_run)
    tf = Path(__file__)
    st, _ = sig.verify_signature(str(tf))
    assert "cmd" in captured
    assert captured.get("shell") is not True
    assert isinstance(captured["cmd"], list)
