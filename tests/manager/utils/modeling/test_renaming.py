from knot_resolver_manager.utils.modeling.renaming import renamed


def test_all():
    ref = {
        "awesome-customers": [{"name": "John", "home-address": "London"}, {"name": "Bob", "home-address": "Prague"}],
        "storage": {"bobby-pin": 5, "can-opener": 0, "laptop": 1},
    }

    rnm = renamed(ref)
    assert rnm["awesome_customers"][0]["home_address"] == "London"
    assert rnm["awesome_customers"][1:][0]["home_address"] == "Prague"
    assert set(rnm["storage"].items()) == set((("can_opener", 0), ("bobby_pin", 5), ("laptop", 1)))
    assert set(rnm["storage"].keys()) == set(("bobby_pin", "can_opener", "laptop"))


def test_nested_init():
    val = renamed(renamed(({"ke-y": "val-ue"})))
    assert val["ke_y"] == "val-ue"


def test_original():
    obj = renamed(({"ke-y": "val-ue"})).original()
    assert obj["ke-y"] == "val-ue"
