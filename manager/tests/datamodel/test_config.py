from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.datamodel.types import IPv6Network96, TimeUnit


def test_dns64_true_default():
    config = KresConfig({"dns64": True})

    assert config.dns64
    assert config.dns64.prefix == IPv6Network96("64:ff9b::/96")


def test_dnssec_true_default():
    config = KresConfig({"dnssec": True})

    assert config.dnssec.trust_anchor_sentinel == True
    assert config.dnssec.trust_anchor_signal_query == True
    assert config.dnssec.time_skew_detection == True
    assert config.dnssec.keep_removed == 0
    assert config.dnssec.refresh_time == None
    assert config.dnssec.hold_down_time == TimeUnit("30d")

    assert config.dnssec.trust_anchors == None
    assert config.dnssec.negative_trust_anchors == None
    assert config.dnssec.trust_anchors_files == None
