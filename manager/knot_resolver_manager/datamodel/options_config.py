from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class OptionsConfig(DataclassParserValidatorMixin):
    def _validate(self):
        pass
