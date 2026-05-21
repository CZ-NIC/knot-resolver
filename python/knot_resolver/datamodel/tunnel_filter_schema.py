from typing import List, Optional

from knot_resolver.datamodel.types import IDPattern, Int0_65535, Percent, ReadableFile
from knot_resolver.utils.modeling import ConfigSchema


class RpzBuilderSchema(ConfigSchema):
    """
    Create an RPZ from domains, which are frequently classified as tunneling.

    ---
    time_window_ms: time between subsequent tunneling classifications of the same registrable domain
    threshold: number of malicious queries from a registrable domain needed for automatic blacklisting
    add_tags: set of tags when to add the RPZ record for the registrable domain
    rpz_tags: set of tags when to apply the filtering using the created RPZ
    """

    time_window_ms: Int0_65535 = Int0_65535(60000)
    threshold: Int0_65535 = Int0_65535(10)
    add_tags: Optional[List[IDPattern]] = None
    rpz_tags: Optional[List[IDPattern]] = None


class TunnelFilterSchema(ConfigSchema):
    """
    Block suspected attempts of data exfiltration via DNS tunneling.

    ---
    enable: enable/disable this filtering
    file: path to the neural network to be used
    sensitivity: deep inspection sensitivity to domain name length
    threshold: neural network inference threshold in percentage
    tags: set of tags when to apply the filtering (same as in other local-data)
    rpz_builder: Create an RPZ from domains, which are frequently classified as tunneling
    """

    enable: bool = False
    file: Optional[ReadableFile] = None
    sensitivity: Percent = Percent(10)
    threshold: Percent = Percent(95)
    tags: Optional[List[IDPattern]] = None
    rpz_builder: RpzBuilderSchema = RpzBuilderSchema()

    def _validate(self) -> None:
        if not self.enable:
            return
        if self.file is None:
            raise ValueError("missing path to the neural network file")
