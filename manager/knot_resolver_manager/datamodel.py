from typing import List, Union

from .utils import dataclass_nested


class DataValidationError(Exception):
    pass


@dataclass_nested
class ServerConfig:
    instances: int = 1

    async def validate(self):
        if self.instances < 0:
            raise DataValidationError("Number of workers must be non-negative")


@dataclass_nested
class LuaConfig:
    script: Union[str, List[str], None] = None

    def __post_init__(self):
        # Concatenate array to single string
        if isinstance(self.script, List):
            self.script = "\n".join(self.script)


@dataclass_nested
class KresConfig:
    server: ServerConfig = ServerConfig()
    lua: LuaConfig = LuaConfig()

    async def validate(self):
        await self.server.validate()
