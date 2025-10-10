from typing import List, Optional

from knot_resolver.datamodel.types import IDPattern, ReadableFile
from knot_resolver.utils.modeling import ConfigSchema


class TunnelFilterSchema(ConfigSchema):
    """
    Block suspected attempts of data exfiltration via DNS tunneling.

    ---
    enable: enable/disable this filtering
    file: path to the neural network to be used
    tags: set of tags when to apply the filtering (same as in other local-data)
    """

    enable: bool = False
    file: Optional[ReadableFile] = None
    tags: Optional[List[IDPattern]] = None

    def _validate(self) -> None:
        if not self.enable:
            return
        if self.file is None:
            raise ValueError("missing path to the neural network file")
