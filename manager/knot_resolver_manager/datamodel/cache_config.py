from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class CacheConfig(DataclassParserValidatorMixin):
    def _validate(self):
        pass
