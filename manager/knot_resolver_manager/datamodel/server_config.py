from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .errors import DataValidationError


@dataclass
class ServerConfig(DataclassParserValidatorMixin):
    instances: int = 1

    def validate(self):
        if not 0 < self.instances <= 256:
            raise DataValidationError("number of kresd instances must be in range 1..256")
