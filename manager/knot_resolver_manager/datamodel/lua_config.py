from typing import List, Optional

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.datamodel.errors import DataValidationError
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class LuaConfig(DataclassParserValidatorMixin):
    script_list: Optional[List[str]] = None
    script: Optional[str] = None

    def __post_init__(self):
        # Concatenate array to single string
        if self.script_list is not None:
            self.script = "\n".join(self.script_list)

    def _validate(self):
        if self.script is None:
            raise DataValidationError("Lua script not specified")
