from typing import Optional

from knot_resolver.datamodel.types import ReadableFile
from knot_resolver.utils.modeling import ConfigSchema


class LuaSchema(ConfigSchema):
    """
    Custom Lua configuration.

    ---
    script_only: Ignore declarative configuration intended for workers and use only Lua script or script file configured in this section.
    script: Custom Lua configuration script intended for workers.
    script_file: Path to file that contains Lua configuration script for workers.
    policy_script_only: Ignore declarative configuration intended for policy-loader and use only Lua script or script file configured in this section.
    policy_script: Custom Lua configuration script intended for policy-loader.
    policy_script_file: Path to file that contains Lua configuration script for policy-loader.
    """

    script_only: bool = False
    script: Optional[str] = None
    script_file: Optional[ReadableFile] = None
    policy_script_only: bool = False
    policy_script: Optional[str] = None
    policy_script_file: Optional[ReadableFile] = None

    def _validate(self) -> None:
        if self.script and self.script_file:
            raise ValueError("'lua.script' and 'lua.script-file' are both defined, only one can be used")
        if self.policy_script and self.policy_script_file:
            raise ValueError("'lua.policy-script' and 'lua.policy-script-file' are both defined, only one can be used")
