from .datamodel import ConfData


class ConfigValidationException(Exception):
    pass


async def parse(yaml: str) -> ConfData:
    conf = ConfData.from_yaml(yaml)
    await conf.validate()
    return conf
