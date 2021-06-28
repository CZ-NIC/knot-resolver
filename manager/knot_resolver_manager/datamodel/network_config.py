from typing import List, Optional, Union

from knot_resolver_manager.compat.dataclasses import dataclass, field
from knot_resolver_manager.datamodel.types import SizeUnits
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class InterfacesConfig(DataclassParserValidatorMixin):
    listen: str
    kind: str = "dns"
    freebind: bool = False
    _address: Optional[str] = None
    _port: Optional[int] = None
    _kind_port_map = {"dns": 53, "xdp": 53, "dot": 853, "doh": 443}

    def __post_init__(self):
        # split 'address@port'
        if "@" in self.listen:
            address, port = self.listen.split("@", maxsplit=1)
            self._address = address
            self._port = int(port)
        else:
            # if port number not specified
            self._address = self.listen
            # set port number based on 'kind'
            self._port = self._kind_port_map.get(self.kind)

    def get_address(self) -> Optional[str]:
        return self._address

    def get_port(self) -> Optional[int]:
        return self._port

    def _validate(self):
        pass


@dataclass
class EdnsBufferSizeConfig(DataclassParserValidatorMixin):
    downstream: Optional[str] = None
    upstream: Optional[str] = None
    _downstream_bytes: int = 1232
    _upstream_bytes: int = 1232

    def __post_init__(self):
        if self.downstream:
            self._downstream_bytes = SizeUnits.parse(self.downstream)
        if self.upstream:
            self._upstream_bytes = SizeUnits.parse(self.upstream)

    def _validate(self):
        pass

    def get_downstream(self) -> int:
        return self._downstream_bytes

    def get_upstream(self) -> int:
        return self._upstream_bytes


@dataclass
class NetworkConfig(DataclassParserValidatorMixin):
    interfaces: List[InterfacesConfig] = field(
        default_factory=lambda: [InterfacesConfig(listen="127.0.0.1"), InterfacesConfig(listen="::1", freebind=True)]
    )
    edns_buffer_size: Union[str, EdnsBufferSizeConfig] = EdnsBufferSizeConfig()

    def __post_init__(self):
        if isinstance(self.edns_buffer_size, str):
            bufsize = self.edns_buffer_size
            self.edns_buffer_size = EdnsBufferSizeConfig(downstream=bufsize, upstream=bufsize)

    def _validate(self):
        pass
