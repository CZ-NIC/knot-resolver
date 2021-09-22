from typing import Optional

from knot_resolver_manager.exceptions import DataException
from knot_resolver_manager.utils import SchemaNode


class Lua(SchemaNode):
    script_only: bool = False
    script: Optional[str] = None
    script_file: Optional[str] = None

    def _validate(self) -> None:
        if self.script and self.script_file:
            raise DataException("'script' and 'script-file' are both defined, only one can be used")
