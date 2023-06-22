from knot_resolver_manager.datamodel.options_schema import OptionsSchema


def test_prediction_true_defaults():
    o = OptionsSchema({"prediction": True})
    assert str(o.prediction.window) == "15m"
    assert int(o.prediction.period) == 24
