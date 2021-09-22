from knot_resolver_manager.datamodel.dnssec_schema import DnssecSchema
from knot_resolver_manager.datamodel.types import TimeUnit

tree = {
    "trust-anchor-sentinel": False,
    "trust-anchor-signal-query": False,
    "time-skew-detection": False,
    "keep-removed": 3,
    "refresh-time": "10s",
    "hold-down-time": "45d",
    "trust-anchors": [". 3600 IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"],
    "negative-trust-anchors": ["bad.boy", "example.com"],
    "trust-anchors-files": [{"file": "root.key", "read-only": True}],
}

strict = DnssecSchema(tree)


def test_validating():
    assert strict.trust_anchor_sentinel == False
    assert strict.trust_anchor_signal_query == False
    assert strict.time_skew_detection == False
    assert strict.keep_removed == 3
    assert strict.refresh_time == TimeUnit("10s")
    assert strict.hold_down_time == TimeUnit("45d")

    assert strict.trust_anchors == [
        ". 3600 IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"
    ]
    assert strict.negative_trust_anchors == ["bad.boy", "example.com"]
    assert strict.trust_anchors_files[0].file == "root.key"
    assert strict.trust_anchors_files[0].read_only == True
