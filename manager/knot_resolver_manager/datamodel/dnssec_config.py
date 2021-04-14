from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class DnssecConfig(DataclassParserValidatorMixin):
    def validate(self):
        pass
