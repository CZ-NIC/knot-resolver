from strictyaml import Map, Str, Int
from strictyaml.parser import load
from strictyaml.representation import YAML

from .datamodel import ConfData


_CONFIG_SCHEMA = Map({"lua_config": Str(), "num_workers": Int()})


def _get_config_schema():
    """
    Returns a schema defined using the strictyaml library, that the manager
    should accept at it's input.

    If this function does something, that can be cached, it should cache it by
    itself. For example, loading the schema from a file is OK, the loaded
    parsed schema object should then however be cached in memory. The function
    is on purpose non-async and it's expected to return very fast.
    """
    return _CONFIG_SCHEMA


class ConfigValidationException(Exception):
    pass


async def _validate_config(config):
    """
    Perform runtime value validation of the provided configuration object which
    is guaranteed to follow the configuration schema returned by the
    `get_config_schema` function.

    Throws a ConfigValidationException in case any errors are found. The error
    message should be in the error message of the exception.
    """

    if config["num_workers"] < 0:
        raise ConfigValidationException("Number of workers must be non-negative")


async def parse(yaml: str) -> ConfData:
    conf = ConfData.from_yaml(yaml)
    await conf.validate()
    return conf