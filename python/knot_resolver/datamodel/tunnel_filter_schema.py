from typing import List, Optional

from knot_resolver.datamodel.types import IDPattern, Int0_65535, Percent, ReadableFile
from knot_resolver.utils.modeling import ConfigSchema


class TunnelFilterSchema(ConfigSchema):
    """
    Block suspected attempts of data exfiltration via DNS tunneling.

    ---
    enable: enable/disable this filtering
    file: path to the neural network to be used
    sensitivity: deep inspection sensitivity to domain name length
    threshold: neural network inference threshold in percentage
    hitms: domain name hash table item expiry time
    hitcap: number of malicious queries from SLD needed for automatic blacklisting
    tags: set of tags when to apply the filtering (same as in other local-data)
    """

    enable: bool = False
    file: Optional[ReadableFile] = None
    sensitivity: Percent = Percent(10)
    threshold: Percent = Percent(95)
    hitms: Int0_65535 = Int0_65535(60000)
    hitcap: Int0_65535 = Int0_65535(10)
    tags: Optional[List[IDPattern]] = None

    def _validate(self) -> None:
        if not self.enable:
            return
        if self.file is None:
            raise ValueError("missing path to the neural network file")
