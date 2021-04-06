from typing import List, Optional

from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .compat.dataclasses import dataclass
from .datamodel_types import IPV6_PREFIX_96


class DataValidationError(Exception):
    pass


@dataclass
class ServerConfig(DataclassParserValidatorMixin):
    instances: int = 1

    def validate(self):
        if not 0 < self.instances <= 256:
            raise DataValidationError("number of kresd 'instances' must be in range 1..256")


@dataclass
class Dns64Config(DataclassParserValidatorMixin):
    prefix: str = "64:ff9b::"

    def validate(self):
        if not bool(IPV6_PREFIX_96.match(self.prefix)):
            raise DataValidationError("'dns64.prefix' must be valid IPv6 address and '/96' CIDR")


@dataclass
class LoggingConfig(DataclassParserValidatorMixin):
    level: int = 3

    def validate(self):
        if not 0 <= self.level <= 7:
            raise DataValidationError("logging 'level' must be in range 0..7")


@dataclass
class LuaConfig(DataclassParserValidatorMixin):
    script_list: Optional[List[str]] = None
    script: Optional[str] = None

    def __post_init__(self):
        # Concatenate array to single string
        if self.script_list is not None:
            self.script = "\n".join(self.script_list)

    def validate(self):
        assert self.script_list is not None or self.script is not None


@dataclass
class KresConfig(DataclassParserValidatorMixin):
    server: ServerConfig = ServerConfig()
    dns64: Optional[Dns64Config] = None
    logging: LoggingConfig = LoggingConfig()
    lua: LuaConfig = LuaConfig()

    def validate(self):
        self.server.validate()
        if self.dns64 is not None:
            self.dns64.validate()
        self.lua.validate()
