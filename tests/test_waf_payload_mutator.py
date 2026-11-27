import copy

import pytest

import waf_payload_mutator as wm


def mutator(**kwargs):
    return wm.WafPayloadMutator(**kwargs)


def add_seed(m, seed_id="s1", payload="a b", **kwargs):
    m.add_seed(seed_id, payload, **kwargs)


def test_add_seed_validates_identity_and_payload():
    m = mutator()
    add_seed(m)
    with pytest.raises(wm.WafError) as exc:
        add_seed(m)
    assert exc.value.code == "WAF_DUPLICATE_SEED"

    for payload in ("", b"abc", None):
        with pytest.raises(wm.WafError) as exc:
            m.add_seed("s9", payload)
        assert exc.value.code == "WAF_INVALID_SEED"

    with pytest.raises(wm.WafError) as exc:
        m.mutate("ghost")
    assert exc.value.code == "WAF_UNKNOWN_SEED"


def test_mutate_emits_encoding_layers_then_transforms():
    m = mutator(max_layers=2)
    add_seed(m)
    variants = m.mutate("s1")
    assert [(v.kind, v.raw) for v in variants] == [
        ("urlencode_l1", "a%20b"),
        ("urlencode_l2", "a%2520b"),
        ("case_swap", "A B"),
        ("comment_pad", "a/**/b"),
        ("space_to_plus", "a+b"),
    ]
    assert [v.variant_id for v in variants] == [
        "s1@urlencode_l1",
        "s1@urlencode_l2",
        "s1@case_swap",
        "s1@comment_pad",
        "s1@space_to_plus",
    ]
    assert [v.layer for v in variants] == [1, 2, 0, 0, 0]


def test_mutate_stops_at_layer_cap():
    m = mutator(max_layers=1)
    add_seed(m)
    assert [v.kind for v in m.mutate("s1")] == [
        "urlencode_l1", "case_swap", "comment_pad", "space_to_plus"]


def test_mutate_respects_variant_cap():
    m = mutator(max_layers=3, max_variants=3)
    add_seed(m)
    variants = m.mutate("s1")
    assert [v.kind for v in variants] == [
        "urlencode_l1", "urlencode_l2", "urlencode_l3"]
    assert m.stats()["suppressed"] == 3


def test_dedupe_collapses_decoded_equivalents():
    m = mutator(max_layers=2)
    add_seed(m)
    unique = m.dedupe(m.mutate("s1"))
    assert [v.kind for v in unique] == [
        "urlencode_l1", "case_swap", "space_to_plus"]
    assert [v.normalized for v in unique] == ["a b", "A B", "a+b"]


def test_normalize_decodes_layers_and_strips_comments():
    m = mutator()
    assert m.normalize("a%2520b") == "a b"
    assert m.normalize("a/**/b") == "a b"
    assert m.normalize("  a   b  ") == "a b"
    assert m.normalize("A B") == "A B"


def test_combine_stacks_kinds_in_order():
    m = mutator()
    add_seed(m)
    combined = m.combine("s1", "case_swap", "comment_pad")
    assert combined.variant_id == "s1@combo:case_swap+comment_pad"
    assert combined.kind == "combo:case_swap+comment_pad"
    assert combined.raw == "A/**/B"
    with pytest.raises(wm.WafError) as exc:
        m.combine("s1", "rot13")
    assert exc.value.code == "WAF_INVALID_KIND"


def test_validate_echo_accepts_equivalent_response():
    m = mutator(max_layers=2)
    add_seed(m)
    m.mutate("s1")
    result = m.validate_echo("s1@urlencode_l2", status_code=200, echo="a b")
    assert result.state == "equivalent"
    assert result.variant_id == "s1@urlencode_l2"
    assert m.stats()["validated"] == 1
    assert m.stats()["equivalent"] == 1


def test_validate_echo_classifies_blocked_and_different():
    m = mutator()
    add_seed(m)
    m.mutate("s1")
    blocked = m.validate_echo("s1@case_swap", status_code=403)
    assert blocked.state == "blocked"
    different = m.validate_echo("s1@space_to_plus", status_code=200,
                                echo="a b c")
    assert different.state == "different"
    assert m.stats()["blocked"] == 1
    assert m.stats()["different"] == 1


def test_validate_echo_rejects_unknown_variant_and_bad_status():
    m = mutator()
    add_seed(m)
    m.mutate("s1")
    with pytest.raises(wm.WafError) as exc:
        m.validate_echo("s1@ghost", status_code=200, echo="a b")
    assert exc.value.code == "WAF_UNKNOWN_VARIANT"
    with pytest.raises(wm.WafError) as exc:
        m.validate_echo("s1@case_swap", status_code="200")
    assert exc.value.code == "WAF_INVALID_STATUS"


def test_rank_orders_state_tiers_then_layer():
    m = mutator(max_layers=2)
    add_seed(m)
    m.mutate("s1")
    m.validate_echo("s1@urlencode_l1", status_code=200, echo="a b")
    m.validate_echo("s1@comment_pad", status_code=200, echo="a b")
    m.validate_echo("s1@space_to_plus", status_code=200, echo="a+b")
    assert [v.variant_id for v in m.rank("s1")] == [
        "s1@comment_pad",
        "s1@urlencode_l1",
        "s1@case_swap",
        "s1@urlencode_l2",
        "s1@space_to_plus",
    ]


def test_survivors_lists_only_equivalent_variants():
    m = mutator(max_layers=2)
    add_seed(m)
    m.mutate("s1")
    m.validate_echo("s1@urlencode_l1", status_code=200, echo="a b")
    m.validate_echo("s1@comment_pad", status_code=200, echo="a b")
    m.validate_echo("s1@case_swap", status_code=403)
    assert m.survivors("s1") == ("s1@comment_pad", "s1@urlencode_l1")


def test_stats_count_mutation_and_validation_activity():
    m = mutator(max_layers=2)
    add_seed(m)
    m.mutate("s1")
    m.validate_echo("s1@urlencode_l1", status_code=200, echo="a b")
    m.validate_echo("s1@case_swap", status_code=403)
    assert m.stats() == {
        "seeds": 1,
        "variants": 5,
        "deduped": 0,
        "validated": 2,
        "equivalent": 1,
        "different": 0,
        "blocked": 1,
        "suppressed": 0,
        "restores": 0,
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    m = mutator(max_layers=2)
    add_seed(m)
    m.mutate("s1")
    m.validate_echo("s1@urlencode_l1", status_code=200, echo="a b")
    state = m.snapshot()
    assert set(state) == {"version", "seeds", "variants", "validations", "stats"}
    pristine = copy.deepcopy(state)
    state["variants"].clear()
    state["stats"]["validated"] = 42
    assert m.stats()["validated"] == 1
    assert m.validate_echo("s1@case_swap", status_code=200,
                           echo="a b").state == "equivalent"

    clone = mutator(max_layers=2)
    clone.restore(pristine)
    assert clone.variant("s1@urlencode_l2") is not None
    assert clone.survivors("s1") == ("s1@urlencode_l1",)
    assert clone.stats()["validated"] == 1
    assert clone.stats()["restores"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    m = mutator()
    add_seed(m)
    m.mutate("s1")
    stats = {"seeds": 1, "variants": 5, "deduped": 0, "validated": 0,
             "equivalent": 0, "different": 0, "blocked": 0,
             "suppressed": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"version": 9, "seeds": [], "variants": [], "validations": [],
         "stats": stats},
        {"version": 1, "seeds": "nope", "variants": [], "validations": [],
         "stats": stats},
        {"version": 1, "seeds": [], "variants": [], "validations": [],
         "stats": {"validated": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(wm.WafError) as exc:
            m.restore(bad)
        assert exc.value.code == "WAF_SNAPSHOT_INVALID"
    assert m.stats() == stats
    assert m.variant("s1@case_swap") is not None
