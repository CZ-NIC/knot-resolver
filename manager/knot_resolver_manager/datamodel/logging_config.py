from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.exceptions import DataValidationException
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class LoggingConfig(DataclassParserValidatorMixin):
    level: int = 3

    def _validate(self):
        if not 0 <= self.level <= 7:
            raise DataValidationException("logging 'level' must be in range 0..7")
