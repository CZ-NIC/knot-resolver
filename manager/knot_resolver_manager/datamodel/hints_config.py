from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class StaticHintsConfig(DataclassParserValidatorMixin):
    def validate(self):
        pass
