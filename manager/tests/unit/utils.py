from knot_resolver_manager.datamodel.config_schema import KresConfig


def test_instance_of_kres_config() -> KresConfig:
    """
    Creates an instance of KresConfig without requiring any arguments.
    """
    return KresConfig({"id": "test"})
