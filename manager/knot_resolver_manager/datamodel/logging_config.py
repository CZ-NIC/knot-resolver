from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .errors import DataValidationError


@dataclass
class LoggingConfig(DataclassParserValidatorMixin):
    level: int = 3

    def _validate(self):
        if not 0 <= self.level <= 7:
            raise DataValidationError("logging 'level' must be in range 0..7")
