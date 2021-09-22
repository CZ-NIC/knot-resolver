from knot_resolver_manager.datamodel.options_config import OptionsSchema
from knot_resolver_manager.datamodel.types import TimeUnit

tree = {
    "glue-checking": "strict",
    "qname-minimisation": False,
    "query-loopback": True,
    "reorder-rrset": False,
    "query-case-randomization": False,
    "query-priming": True,
    "rebinding-protection": False,
    "refuse-no-rd": False,
    "time-jump-detection": False,
    "violators-workarounds": True,
    "serve-stale": True,
    "prediction": {"window": "10m", "period": 20},
}

strict = OptionsSchema(tree)


def test_validating():
    assert strict.glue_checking == "strict"
    assert strict.qname_minimisation == False
    assert strict.query_loopback == True
    assert strict.reorder_rrset == False
    assert strict.query_case_randomization == False
    assert strict.query_priming == True
    assert strict.rebinding_protection == False
    assert strict.refuse_no_rd == False
    assert strict.time_jump_detection == False
    assert strict.violators_workarounds == True
    assert strict.serve_stale == True

    assert strict.prediction.window == TimeUnit("10m")
    assert strict.prediction.period == 20


def test_prediction_true_defaults():
    y = OptionsSchema({"prediction": True})

    assert y.prediction.window == TimeUnit("15m")
    assert y.prediction.period == 24
