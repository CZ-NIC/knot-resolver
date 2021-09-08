from knot_resolver_manager.datamodel.dns64_config import Dns64, Dns64Strict

yaml = """
prefix: fe80::21b:77ff:0:0
"""

config = Dns64.from_yaml(yaml)
strict = Dns64Strict(config)


def test_parsing():
    assert config.prefix == "fe80::21b:77ff:0:0"


def test_validating():
    assert strict.prefix == "fe80::21b:77ff:0:0"
