from dataclasses import dataclass
from typing import Optional

from .utils import StrictyamlParser


class ConfDataValidationException(Exception):
    pass


@dataclass
class ConfData(StrictyamlParser):
    num_workers: int = 1
    lua_config: Optional[str] = None

    async def validate(self) -> bool:
        if self.num_workers < 0:
            raise ConfDataValidationException("Number of workers must be non-negative")

        return True
