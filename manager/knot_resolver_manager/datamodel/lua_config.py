from typing import List, Optional, Union

from knot_resolver_manager.utils import DataParser, DataValidator


class Lua(DataParser):
    script: Optional[Union[List[str], str]] = None
    script_file: Optional[str] = None


class LuaStrict(DataValidator):
    script: Optional[str]
    script_file: Optional[str]

    def _script(self, lua: Lua) -> Optional[str]:
        if isinstance(lua.script, List):
            return "\n".join(lua.script)
        return lua.script

    def _validate(self) -> None:
        pass
