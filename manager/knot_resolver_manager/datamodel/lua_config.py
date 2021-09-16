from typing import Optional

from knot_resolver_manager.exceptions import ValidationException
from knot_resolver_manager.utils import SchemaNode


class Lua(SchemaNode):
    script_only: bool = False
    script: Optional[str] = None
    script_file: Optional[str] = None


class LuaStrict(SchemaNode):
    script_only: bool
    script: Optional[str]
    script_file: Optional[str]

    def _validate(self) -> None:
        if self.script and self.script_file:
            raise ValidationException("'lua.script' and 'lua.script-file' are both defined, only one can be used")
