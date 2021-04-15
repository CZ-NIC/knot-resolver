import os
from typing import Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .errors import DataValidationError


@dataclass
class ServerConfig(DataclassParserValidatorMixin):
    hostname: Optional[str] = None
    instances: Union[Literal["auto"], int, None] = None
    _instances: int = 1
    use_cache_gc: bool = True

    def __post_init__(self):
        if isinstance(self.instances, int):
            self._instances = self.instances
        elif self.instances == "auto":
            cpu_count = os.cpu_count()
            if cpu_count is not None:
                self._instances = cpu_count
            else:
                # TODO: do better logging
                print("cannot find number of system available CPUs")

    def get_instances(self) -> int:
        return self._instances

    def _validate(self):
        if not 0 < self._instances <= 256:
            raise DataValidationError("number of kresd instances must be in range 1..256")
