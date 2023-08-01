from knot_resolver_manager.datamodel.cache_schema import CacheSchema


def test_prediction_true_defaults():
    o = CacheSchema({"prediction": True})
    assert str(o.prediction.window) == "15m"
    assert int(o.prediction.period) == 24
