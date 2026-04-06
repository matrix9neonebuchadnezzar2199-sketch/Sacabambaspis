# -*- coding: utf-8 -*-
"""utils/path_helper: 開発時のベースパス解決"""
import os

import utils.path_helper as ph


def test_resource_path_joins_under_project():
    p = ph.resource_path(os.path.join("web", "templates"))
    assert "web" in p.replace("\\", "/")
    assert p.endswith(os.path.join("web", "templates"))


def test_development_base_is_parent_of_utils():
    base = ph._development_base_path()
    assert os.path.isdir(os.path.join(base, "utils"))
    assert os.path.isfile(os.path.join(base, "main.py"))
