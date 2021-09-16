from knot_resolver_manager.datamodel.options_config import Options, OptionsStrict
from knot_resolver_manager.datamodel.types import TimeUnit
from knot_resolver_manager.utils import Format

yaml = """
glue-checking: strict
qname-minimisation: false
query-loopback: true
reorder-rrset: false
query-case-randomization: false
query-priming: true
rebinding-protection: false
refuse-no-rd: false
time-jump-detection: false
violators-workarounds: true
serve-stale: true
prediction:
    window: 10m
    period: 20
"""

config = Options.from_yaml(yaml)
strict = OptionsStrict(config)


def test_parsing():
    assert config.glue_checking == "strict"
    assert config.qname_minimisation == False
    assert config.query_loopback == True
    assert config.reorder_rrset == False
    assert config.query_case_randomization == False
    assert config.query_priming == True
    assert config.rebinding_protection == False
    assert config.refuse_no_rd == False
    assert config.time_jump_detection == False
    assert config.violators_workarounds == True
    assert config.serve_stale == True

    assert config.prediction.window == TimeUnit("10m")
    assert config.prediction.period == 20


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
    x = config.copy_with_changed_subtree(Format.JSON, "/prediction", "true")
    y = OptionsStrict(x)

    assert x.prediction == True
    assert y.prediction.window == TimeUnit("15m")
    assert y.prediction.period == 24
