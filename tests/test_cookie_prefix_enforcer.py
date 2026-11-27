import copy

import pytest

import cookie_prefix_enforcer as ce


def enforcer(**kwargs):
    return ce.CookiePrefixEnforcer(**kwargs)


def test_parse_set_cookie_fills_defaults():
    jar = enforcer()
    cookie = jar.parse_set_cookie("sid=abc123")
    assert cookie["name"] == "sid"
    assert cookie["value"] == "abc123"
    assert cookie["path"] == "/"
    assert cookie["domain"] is None
    assert cookie["secure"] is False
    assert cookie["httponly"] is False
    assert cookie["samesite"] is None
    assert cookie["max_age"] is None


def test_parse_set_cookie_reads_attributes():
    jar = enforcer()
    cookie = jar.parse_set_cookie(
        "sid=abc; Path=/app; Domain=.Example.COM; Secure; HttpOnly; SameSite=Lax; Max-Age=60"
    )
    assert cookie["path"] == "/app"
    assert cookie["domain"] == "example.com"
    assert cookie["secure"] is True
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "lax"
    assert cookie["max_age"] == 60
    for bad in ["", "novalue", "a=1; Max-Age=soon"]:
        with pytest.raises(ce.CookieError) as exc:
            jar.parse_set_cookie(bad)
        assert exc.value.code == "COOKIE_HEADER_INVALID"


def test_check_prefix_requires_secure_for_host_prefix():
    jar = enforcer()
    plain = jar.check_prefix(jar.parse_set_cookie("sid=1; Secure"))
    assert plain == {"ok": True, "reason": None}
    missing = jar.check_prefix(jar.parse_set_cookie("__Host-sid=1; Path=/"))
    assert missing["ok"] is False
    assert missing["reason"] == "COOKIE_PREFIX_SECURE_REQUIRED"
    good = jar.check_prefix(jar.parse_set_cookie("__Host-sid=1; Path=/; Secure"))
    assert good == {"ok": True, "reason": None}


def test_check_prefix_rejects_domain_and_short_path_for_host_prefix():
    jar = enforcer()
    domain = jar.check_prefix(jar.parse_set_cookie("__Host-sid=1; Secure; Domain=.example.com"))
    assert domain["ok"] is False
    assert domain["reason"] == "COOKIE_PREFIX_DOMAIN_FORBIDDEN"
    short = jar.check_prefix(jar.parse_set_cookie("__Host-sid=1; Secure; Path=/sub"))
    assert short["ok"] is False
    assert short["reason"] == "COOKIE_PREFIX_PATH_REQUIRED"


def test_check_prefix_secure_prefix_allows_domain():
    jar = enforcer()
    out = jar.check_prefix(jar.parse_set_cookie("__Secure-sid=1; Secure; Domain=.example.com"))
    assert out == {"ok": True, "reason": None}
    bad = jar.check_prefix(jar.parse_set_cookie("__Secure-sid=1; Domain=.example.com"))
    assert bad["reason"] == "COOKIE_PREFIX_SECURE_REQUIRED"


def test_scope_cover_matches_domain_suffix():
    jar = enforcer()
    cookie = jar.parse_set_cookie("sid=1; Domain=.example.com")
    assert jar.scope_cover(cookie, "example.com") is True
    assert jar.scope_cover(cookie, "a.example.com") is True
    assert jar.scope_cover(cookie, "a.b.example.com") is True
    assert jar.scope_cover(cookie, "notexample.com") is False
    assert jar.scope_cover(cookie, "example.com.evil.net") is False


def test_scope_cover_host_only_cookie_stays_on_origin():
    jar = enforcer()
    out = jar.apply("sid=1; Path=/", host="shop.example.com")
    assert out["accepted"] is True
    cookie = out["cookie"]
    assert cookie["origin"] == "shop.example.com"
    assert jar.scope_cover(cookie, "shop.example.com") is True
    assert jar.scope_cover(cookie, "a.shop.example.com") is False
    assert jar.scope_cover(cookie, "other.example.com") is False


def test_samesite_combo_rejects_none_without_secure():
    jar = enforcer()
    cookie = jar.parse_set_cookie("sid=1; SameSite=None")
    out = jar.samesite_combo(cookie)
    assert out["action"] == "reject"
    assert out["reason"] == "COOKIE_SAMESITE_NONE_INSECURE"
    ok = jar.samesite_combo(jar.parse_set_cookie("sid=1; SameSite=None; Secure"))
    assert ok == {"action": "send", "reason": None}


def test_samesite_combo_rejects_unknown_value_and_defaults_to_lax():
    jar = enforcer()
    bad = jar.samesite_combo(jar.parse_set_cookie("sid=1; SameSite=Loose"))
    assert bad["action"] == "reject"
    assert bad["reason"] == "COOKIE_SAMESITE_INVALID"
    default = jar.samesite_combo(jar.parse_set_cookie("sid=1"))
    assert default == {"action": "send", "reason": None}


def test_samesite_combo_withholds_on_cross_site():
    jar = enforcer()
    lax = jar.samesite_combo(jar.parse_set_cookie("sid=1; SameSite=Lax"), cross_site=True)
    assert lax == {"action": "withhold", "reason": "COOKIE_SAMESITE_CROSS_SITE"}
    strict = jar.samesite_combo(jar.parse_set_cookie("sid=1; SameSite=Strict"), cross_site=True)
    assert strict["action"] == "withhold"
    none_secure = jar.samesite_combo(
        jar.parse_set_cookie("sid=1; SameSite=None; Secure"), cross_site=True
    )
    assert none_secure == {"action": "send", "reason": None}


def test_apply_rejects_prefixed_cookie_on_insecure_channel():
    jar = enforcer(secure_transport=False)
    out = jar.apply("__Secure-sid=1; Secure; Path=/", host="shop.example.com")
    assert out["accepted"] is False
    assert out["reason"] == "COOKIE_PREFIX_INSECURE_CHANNEL"
    assert jar.name_count("sid") == 0
    assert jar.stats()["rejected"] == 1
    assert jar.stats()["applied"] == 0


def test_apply_keeps_only_the_most_specific_same_name():
    jar = enforcer()
    first = jar.apply("sid=old; Path=/", host="shop.example.com")
    assert first["accepted"] is True
    assert first["replaced"] is False
    second = jar.apply("sid=new; Path=/app", host="shop.example.com")
    assert second["accepted"] is True
    assert second["replaced"] is True
    assert jar.name_count("sid") == 1
    shorter = jar.apply("sid=short; Path=/v", host="shop.example.com")
    assert shorter["accepted"] is False
    assert shorter["reason"] == "COOKIE_SHADOWED"
    assert jar.name_count("sid") == 1
    assert jar.stats()["applied"] == 2
    assert jar.stats()["replaced"] == 1


def test_deliver_filters_by_host_path_and_secure():
    jar = enforcer()
    jar.apply("theme=dark; Path=/", host="shop.example.com")
    jar.apply("sid=abc; Path=/app; Secure", host="shop.example.com")
    jar.apply("other=1; Path=/", host="other.example.com")
    rows = jar.deliver("shop.example.com", "/app/page")
    assert [row["name"] for row in rows] == ["sid", "theme"]
    assert [row["path"] for row in rows] == ["/app", "/"]
    assert [row["name"] for row in jar.deliver("shop.example.com", "/")] == ["theme"]
    assert [row["name"] for row in jar.deliver("shop.example.com", "/app/page", secure=False)] == ["theme"]
    assert jar.stats()["delivered"] == 4


def test_apply_capacity_is_hard_limit():
    jar = enforcer(max_cookies=2)
    jar.apply("a=1", host="shop.example.com")
    jar.apply("b=2", host="shop.example.com")
    with pytest.raises(ce.CookieError) as exc:
        jar.apply("c=3", host="shop.example.com")
    assert exc.value.code == "COOKIE_JAR_LIMIT"
    assert jar.name_count("a") == 1
    assert jar.name_count("b") == 1
    assert jar.name_count("c") == 0
    replaced = jar.apply("a=9", host="shop.example.com")
    assert replaced["accepted"] is True
    assert replaced["replaced"] is True


def test_snapshot_roundtrip_and_counters():
    jar = enforcer(max_cookies=4)
    jar.apply("sid=old; Path=/", host="shop.example.com")
    jar.apply("sid=new; Path=/app", host="shop.example.com")
    jar.apply("__Host-sid=1; Path=/", host="shop.example.com")
    state = jar.snapshot()
    assert set(state) == {"version", "cookies", "max_cookies", "secure_transport", "stats"}
    pristine = copy.deepcopy(state)
    assert pristine["max_cookies"] == 4
    assert len(pristine["cookies"]) == 1
    assert pristine["cookies"][0]["path"] == "/app"

    before = dict(jar.stats())
    assert before["applied"] == 2
    assert before["rejected"] == 1

    state["cookies"].clear()
    state["stats"]["applied"] = 99
    assert jar.name_count("sid") == 1
    assert jar.stats()["applied"] == 2

    clone = enforcer()
    clone.restore(pristine)
    assert clone.name_count("sid") == 1
    assert clone.stats()["applied"] == 2
    assert clone.stats()["restores"] == 1
    assert [row["name"] for row in clone.deliver("shop.example.com", "/app")] == ["sid"]

    for bad in [None, {}, {"version": 2, "cookies": [], "max_cookies": 4,
                           "secure_transport": True, "stats": {}}]:
        with pytest.raises(ce.CookieError) as exc:
            clone.restore(bad)
        assert exc.value.code == "COOKIE_SNAPSHOT_INVALID"
    assert clone.name_count("sid") == 1
    assert clone.stats()["restores"] == 1
