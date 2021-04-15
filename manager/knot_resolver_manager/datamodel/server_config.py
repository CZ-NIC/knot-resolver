import os
from typing import Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .errors import DataValidationError


@dataclass
class ServerConfig(DataclassParserValidatorMixin):
    hostname: Optional[str] = None
    instances: Union[Literal["auto"], int] = 1
    instances_num: int = 1
    use_cache_gc: bool = True

    def __post_init__(self):
        if isinstance(self.instances, int):
            self.instances_num = self.instances
        elif self.instances == "auto":
            cpu_count = os.cpu_count()
            if cpu_count is not None:
                self.instances_num = cpu_count
            else:
                # TODO: do better logging
                print("cannot get number of CPUs")

    def _validate(self):
        if not 0 < self.instances_num <= 256:
            raise DataValidationError("number of kresd instances must be in range 1..256")
