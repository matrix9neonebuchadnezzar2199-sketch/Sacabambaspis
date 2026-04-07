# -*- coding: utf-8 -*-
from web.app import app


def test_post_without_origin_allowed():
    app.config["TESTING"] = True
    with app.test_client() as c:
        rv = c.post("/api/ioc/clear")
        assert rv.status_code in (200, 400, 500)


def test_post_foreign_origin_blocked():
    app.config["TESTING"] = True
    with app.test_client() as c:
        rv = c.post(
            "/api/ioc/clear",
            headers={"Origin": "https://evil.example"},
        )
        assert rv.status_code == 403
        assert b"Origin not allowed" in rv.data or "Origin not allowed" in rv.get_json().get(
            "message", ""
        )


def test_post_localhost_origin_allowed():
    app.config["TESTING"] = True
    with app.test_client() as c:
        rv = c.post(
            "/api/ioc/clear",
            headers={"Origin": "http://127.0.0.1:5000"},
        )
        assert rv.status_code != 403
