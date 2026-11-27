import copy

import pytest

import cookie_scope_guard as csg

HOST = "a.example.com"


def guard(**kwargs):
    return csg.CookieScopeGuard(**kwargs)


def test_store_returns_parsed_cookie_and_delivers_it():
    jar = guard()
    stored = jar.store("sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
                       origin_host=HOST, secure=True, now=0.0)
    assert (stored.name, stored.value, stored.domain, stored.path) == (
        "sid", "abc123", HOST, "/")
    assert stored.host_only is True
    assert stored.secure is True
    assert stored.http_only is True
    assert stored.same_site == "Lax"
    assert stored.prefix == ""

    delivered = jar.cookies_for(HOST, "/", secure=True)
    assert [item.name for item in delivered] == ["sid"]
    assert delivered[0].value == "abc123"
    assert jar.cookies_for(HOST, "/", secure=False) == []


def test_delivery_orders_longer_paths_first():
    jar = guard()
    jar.store("a=1; Path=/app; Secure", origin_host=HOST, secure=True, now=1.0)
    jar.store("b=2; Path=/app/deep; Secure", origin_host=HOST, secure=True, now=2.0)
    names = [item.name for item in jar.cookies_for(HOST, "/app/deep/x", secure=True)]
    assert names == ["b", "a"]


def test_domain_attribute_is_normalized_and_covers_subdomains():
    jar = guard()
    stored = jar.store("t=v; Domain=.Example.COM; Path=/",
                       origin_host=HOST, secure=True, now=0.0)
    assert stored.domain == "example.com"
    assert stored.host_only is False
    assert [item.name for item in jar.cookies_for("sub.example.com", "/", secure=True)] == ["t"]


def test_host_only_cookie_never_reaches_subdomains():
    jar = guard()
    jar.store("h=1; Path=/", origin_host=HOST, secure=True, now=0.0)
    assert [item.name for item in jar.cookies_for(HOST, "/", secure=True)] == ["h"]
    assert jar.cookies_for("sub.a.example.com", "/", secure=True) == []


def test_path_matching_respects_segment_boundaries():
    jar = guard()
    jar.store("p=1; Path=/app; Secure", origin_host=HOST, secure=True, now=0.0)
    assert [item.name for item in jar.cookies_for(HOST, "/app", secure=True)] == ["p"]
    assert [item.name for item in jar.cookies_for(HOST, "/app/deep", secure=True)] == ["p"]
    assert jar.cookies_for(HOST, "/application", secure=True) == []


def test_max_age_zero_deletes_existing_cookie():
    jar = guard()
    jar.store("s=1; Path=/; Secure", origin_host=HOST, secure=True, now=0.0)
    assert jar.store("s=; Path=/; Max-Age=0; Secure",
                     origin_host=HOST, secure=True, now=1.0) is None
    assert jar.cookies_for(HOST, "/", secure=True) == []
    assert jar.stats()["expired"] == 1


def test_overwrite_keeps_original_creation_time():
    jar = guard()
    first = jar.store("k=1; Path=/; Secure", origin_host=HOST, secure=True, now=0.0)
    second = jar.store("k=2; Path=/; Secure", origin_host=HOST, secure=True, now=5.0)
    assert first.created_at == 0.0
    assert second.created_at == 0.0
    assert second.value == "2"
    assert len(jar.cookies_for(HOST, "/", secure=True)) == 1
    assert jar.stats()["stored"] == 1
    assert jar.stats()["replaced"] == 1


def test_secure_prefix_requires_secure_transport():
    jar = guard()
    with pytest.raises(csg.CookieScopeError) as exc:
        jar.store("__Secure-a=1; Path=/", origin_host=HOST, secure=False, now=0.0)
    assert exc.value.code == "COOKIE_PREFIX_VIOLATION"
    assert jar.stats()["rejected"] == 1
    stored = jar.store("__Secure-a=1; Path=/; Secure",
                       origin_host=HOST, secure=True, now=1.0)
    assert stored.name == "__Secure-a"
    assert stored.prefix == "__Secure-"


def test_public_suffix_and_foreign_domain_are_rejected():
    jar = guard(public_suffixes=("example.com",))
    with pytest.raises(csg.CookieScopeError) as exc:
        jar.store("x=1; Domain=example.com; Path=/",
                  origin_host=HOST, secure=True, now=0.0)
    assert exc.value.code == "COOKIE_DOMAIN_REJECTED"
    with pytest.raises(csg.CookieScopeError) as exc:
        jar.store("y=1; Domain=other.com; Path=/",
                  origin_host=HOST, secure=True, now=0.0)
    assert exc.value.code == "COOKIE_DOMAIN_REJECTED"


def test_per_domain_capacity_is_enforced():
    jar = guard(max_per_domain=2)
    jar.store("a=1; Path=/; Secure", origin_host=HOST, secure=True, now=0.0)
    jar.store("b=2; Path=/; Secure", origin_host=HOST, secure=True, now=1.0)
    with pytest.raises(csg.CookieScopeError) as exc:
        jar.store("c=3; Path=/; Secure", origin_host=HOST, secure=True, now=2.0)
    assert exc.value.code == "COOKIE_STORE_FULL"
    assert len(jar.cookies_for(HOST, "/", secure=True)) == 2
    assert jar.stats()["rejected"] == 1


def test_clear_removes_only_the_exact_record():
    jar = guard()
    jar.store("a=1; Path=/app; Secure", origin_host=HOST, secure=True, now=0.0)
    jar.store("b=2; Path=/; Secure", origin_host=HOST, secure=True, now=1.0)
    assert jar.clear("a", domain=HOST, path="/app") == 1
    assert jar.clear("a", domain=HOST, path="/app") == 0
    assert [item.name for item in jar.cookies_for(HOST, "/app", secure=True)] == ["b"]
    assert jar.stats()["cleared"] == 1


def test_clear_domain_cascades_to_subdomains():
    jar = guard()
    jar.store("a=1; Domain=example.com; Path=/", origin_host=HOST, secure=True, now=0.0)
    jar.store("b=2; Path=/", origin_host="b.example.com", secure=True, now=0.0)
    jar.store("c=3; Path=/", origin_host="other.com", secure=True, now=0.0)
    assert jar.clear_domain("example.com") == 2
    assert jar.cookies_for(HOST, "/", secure=True) == []
    assert [item.name for item in jar.cookies_for("other.com", "/", secure=True)] == ["c"]
    assert jar.stats()["cleared"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    jar = guard()
    jar.store("sid=1; Domain=example.com; Path=/; Secure", origin_host=HOST,
              secure=True, now=0.0)
    state = jar.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "cookies", "stats"}

    state["cookies"].clear()
    state["stats"]["stored"] = 99
    assert jar.cookies_for(HOST, "/", secure=True) != []
    assert jar.stats()["stored"] == 1

    clone = guard()
    clone.restore(pristine)
    assert [item.name for item in clone.cookies_for("sub.example.com", "/", secure=True)] == ["sid"]
    assert clone.stats()["stored"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    jar = guard()
    jar.store("sid=1; Path=/; Secure", origin_host=HOST, secure=True, now=0.0)
    good = jar.snapshot()
    bad_states = [
        None,
        {},
        dict(good, version=2),
        dict(good, cookies="nope"),
        dict(good, stats={"stored": 1}),
    ]
    for bad in bad_states:
        with pytest.raises(csg.CookieScopeError) as exc:
            jar.restore(bad)
        assert exc.value.code == "COOKIE_SNAPSHOT_INVALID"

    assert [item.name for item in jar.cookies_for(HOST, "/", secure=True)] == ["sid"]
    assert jar.stats()["stored"] == 1


def test_stats_track_store_replace_reject_and_clear():
    jar = guard()
    jar.store("a=1; Path=/; Secure", origin_host=HOST, secure=True, now=0.0)
    jar.store("a=2; Path=/; Secure", origin_host=HOST, secure=True, now=1.0)
    with pytest.raises(csg.CookieScopeError):
        jar.store("__Secure-b=1; Path=/", origin_host=HOST, secure=False, now=2.0)
    jar.clear("a", domain=HOST, path="/")
    assert jar.stats() == {
        "stored": 1,
        "replaced": 1,
        "rejected": 1,
        "cleared": 1,
        "expired": 0,
    }
