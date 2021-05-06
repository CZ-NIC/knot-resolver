from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .errors import DataValidationError
from .types import RE_IPV6_PREFIX_96


@dataclass
class Dns64Config(DataclassParserValidatorMixin):
    prefix: str = "64:ff9b::"

    def _validate(self):
        if not bool(RE_IPV6_PREFIX_96.match(self.prefix)):
            raise DataValidationError("'dns64.prefix' must be valid IPv6 /96 prefix")
