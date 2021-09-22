from knot_resolver_manager.datamodel.options_schema import OptionsSchema
from knot_resolver_manager.datamodel.types import TimeUnit


def test_prediction_true():
    y = OptionsSchema({"prediction": True})

    assert y.prediction.window == TimeUnit("15m")
    assert y.prediction.period == 24
