from typing import Optional

from knot_resolver_manager.utils import SchemaNode


class LuaSchema(SchemaNode):
    """
    Custom Lua configuration.

    ---
    script_only: Ignore declarative configuration and use only Lua script or file defined in this section.
    script: Custom Lua configuration script.
    script_file: Path to file that contains Lua configuration script.
    """

    script_only: bool = False
    script: Optional[str] = None
    script_file: Optional[str] = None

    def _validate(self) -> None:
        if self.script and self.script_file:
            raise ValueError("'lua.script' and 'lua.script-file' are both defined, only one can be used")
