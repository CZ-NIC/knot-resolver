from typing import Optional

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.datamodel.types import SizeUnits
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class CacheConfig(DataclassParserValidatorMixin):
    storage: str = "/var/cache/knot-resolver"
    size_max: Optional[str] = None
    _size_max_bytes: int = 100 * SizeUnits.mebibyte

    def __post_init__(self):
        if self.size_max:
            self._size_max_bytes = SizeUnits.parse(self.size_max)

    def get_size_max(self) -> int:
        return self._size_max_bytes

    def _validate(self):
        pass
