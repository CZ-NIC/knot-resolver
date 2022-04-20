import json
from typing import Any, Dict, cast

from pytest import raises

from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.exceptions import SchemaException
from knot_resolver_manager.utils.modelling import SchemaNode
from tests.unit.utils import test_instance_of_kres_config


def test_config_defaults():
    config = test_instance_of_kres_config()

    # DNS64 default
    assert config.dns64 == False


def test_dnssec_false():
    config = KresConfig({"server": {"id": "test"}, "dnssec": False})

    assert config.dnssec == False


def test_dnssec_default_true():
    config = test_instance_of_kres_config()

    # DNSSEC defaults
    assert config.dnssec.trust_anchor_sentinel == True
    assert config.dnssec.trust_anchor_signal_query == True
    assert config.dnssec.time_skew_detection == True
    assert config.dnssec.refresh_time == None
    assert config.dnssec.trust_anchors == None
    assert config.dnssec.negative_trust_anchors == None
    assert config.dnssec.trust_anchors_files == None
    assert int(config.dnssec.keep_removed) == 0
    assert str(config.dnssec.hold_down_time) == "30d"


def test_dns64_prefix_default():
    assert str(KresConfig({"server": {"id": "test"}, "dns64": True}).dns64.prefix) == "64:ff9b::/96"


def test_config_json_schema():
    dct = KresConfig.json_schema()

    def recser(obj: Any, path: str = "") -> None:
        if not isinstance(obj, dict):
            return
        else:
            obj = cast(Dict[Any, Any], obj)
            for key in obj:
                recser(obj[key], path=f"{path}/{key}")
            try:
                _ = json.dumps(obj)
            except BaseException as e:
                raise Exception(f"failed to serialize '{path}'") from e

    recser(dct)
