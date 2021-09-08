from knot_resolver_manager.datamodel import KresConfig, KresConfigStrict


def test_dns64_true_default():
    config = KresConfig({"dns64": True})
    strict = KresConfigStrict(config)

    assert strict.dns64
    assert strict.dns64.prefix == "64:ff9b::"
