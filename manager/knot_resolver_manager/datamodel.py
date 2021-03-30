from typing import List, Optional

from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .compat.dataclasses import dataclass


class DataValidationError(Exception):
    pass


@dataclass
class ServerConfig(DataclassParserValidatorMixin):
    instances: int = 1

    def validate(self):
        if self.instances < 0:
            raise DataValidationError("Number of workers must be non-negative")


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
    lua: LuaConfig = LuaConfig()

    def validate(self):
        pass
