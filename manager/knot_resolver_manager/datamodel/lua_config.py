from typing import Optional

from knot_resolver_manager.utils import DataParser, DataValidator
from knot_resolver_manager.utils.exceptions import DataValidationException


class Lua(DataParser):
    script_only: bool = False
    script: Optional[str] = None
    script_file: Optional[str] = None


class LuaStrict(DataValidator):
    script_only: bool
    script: Optional[str]
    script_file: Optional[str]

    def _validate(self) -> None:
        if self.script and self.script_file:
            raise DataValidationException("'lua.script' and 'lua.script-file' are both defined, only one can be used")
