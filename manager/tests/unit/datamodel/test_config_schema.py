import json
from typing import Any, Dict, cast

from pytest import raises
from yaml.nodes import Node

from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.datamodel.types import IPv6Network96, TimeUnit
from knot_resolver_manager.exceptions import SchemaException
from knot_resolver_manager.utils.modelling import SchemaNode


def test_dns64_true():
    config = KresConfig({"dns64": True})

    assert config.dns64
    assert config.dns64.prefix == IPv6Network96("64:ff9b::/96")


def test_dns64_default_false():
    config = KresConfig()

    assert config.dns64 == False


def test_dnssec_false():
    config = KresConfig({"dnssec": False})

    assert config.dnssec == False


def test_dnssec_default_true():
    config = KresConfig()

    assert config.dnssec.trust_anchor_sentinel == True
    assert config.dnssec.trust_anchor_signal_query == True
    assert config.dnssec.time_skew_detection == True
    assert config.dnssec.keep_removed == 0
    assert config.dnssec.refresh_time == None
    assert config.dnssec.hold_down_time == TimeUnit("30d")

    assert config.dnssec.trust_anchors == None
    assert config.dnssec.negative_trust_anchors == None
    assert config.dnssec.trust_anchors_files == None


def test_json_schema():
    dct = KresConfig.json_schema()

    def recser(obj: Any, path: str = ""):
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


def test_attribute_parsing():
    class TestClass(SchemaNode):
        """
        This is an awesome test class

        ---
        field: This field does nothing interesting
        value: Neither does this
        """

        field: str
        value: int

    schema = TestClass.json_schema()
    assert schema["properties"]["field"]["description"] == "This field does nothing interesting"
    assert schema["properties"]["value"]["description"] == "Neither does this"

    class AdditionalItem(SchemaNode):
        """
        This class is wrong

        ---
        field: nope
        nothing: really nothing
        """

        nothing: str

    with raises(SchemaException):
        _ = AdditionalItem.json_schema()

    class WrongDescription(SchemaNode):
        """
        This class is wrong

        ---
        other: description
        """

        nothing: str

    with raises(SchemaException):
        _ = WrongDescription.json_schema()

    class NoDescription(SchemaNode):
        nothing: str

    _ = NoDescription.json_schema()

    class NormalDescription(SchemaNode):
        """
        Does nothing special
        Really
        """

    _ = NormalDescription.json_schema()
