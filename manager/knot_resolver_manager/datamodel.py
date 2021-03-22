from dataclasses import dataclass

from .utils import dataclass_strictyaml


class ConfDataValidationException(Exception):
    pass


@dataclass
@dataclass_strictyaml
class ConfData:
    num_workers: int = 1
    lua_config: str = None

    async def validate(self) -> bool:
        if self.num_workers < 0:
            raise ConfDataValidationException("Number of workers must be non-negative")
