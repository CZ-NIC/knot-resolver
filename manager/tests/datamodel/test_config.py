from knot_resolver_manager.datamodel import KresConfig, KresConfigStrict
from knot_resolver_manager.datamodel.types import IPv6Network96, TimeUnit


def test_dns64_true_default():
    config = KresConfig({"dns64": True})
    strict = KresConfigStrict(config)

    assert strict.dns64
    assert strict.dns64.prefix == IPv6Network96("64:ff9b::/96")


def test_dnssec_true_default():
    config = KresConfig({"dnssec": True})
    strict = KresConfigStrict(config)

    assert strict.dnssec.trust_anchor_sentinel == True
    assert strict.dnssec.trust_anchor_signal_query == True
    assert strict.dnssec.time_skew_detection == True
    assert strict.dnssec.keep_removed == 0
    assert strict.dnssec.refresh_time == None
    assert strict.dnssec.hold_down_time == TimeUnit("30d")

    assert strict.dnssec.trust_anchors == None
    assert strict.dnssec.negative_trust_anchors == None
    assert strict.dnssec.trust_anchors_files == None
