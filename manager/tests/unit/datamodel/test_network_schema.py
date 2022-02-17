from typing import Any, Dict, Optional

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.network_schema import ListenSchema, NetworkSchema
from knot_resolver_manager.datamodel.types import PortNumber
from knot_resolver_manager.datamodel.types.types import InterfaceOptionalPort
from knot_resolver_manager.exceptions import KresManagerException


def test_listen_defaults():
    o = NetworkSchema()

    assert len(o.listen) == 2
    # {"ip-address": "127.0.0.1"}
    assert o.listen[0].interface == InterfaceOptionalPort("127.0.0.1")
    assert o.listen[0].port == PortNumber(53)
    assert o.listen[0].kind == "dns"
    assert o.listen[0].freebind == False
    # {"ip-address": "::1", "freebind": True}
    assert o.listen[1].interface == InterfaceOptionalPort("::1")
    assert o.listen[1].port == PortNumber(53)
    assert o.listen[1].kind == "dns"
    assert o.listen[1].freebind == True


@pytest.mark.parametrize(
    "listen,port",
    [
        ({"unix-socket": "/tmp/kresd-socket"}, None),
        ({"interface": "::1"}, 53),
        ({"interface": "::1", "kind": "dot"}, 853),
        ({"interface": "::1", "kind": "doh-legacy"}, 443),
        ({"interface": "::1", "kind": "doh2"}, 443),
    ],
)
def test_listen_port_defaults(listen: Dict[str, Any], port: Optional[int]):
    assert ListenSchema(listen).port == (PortNumber(port) if port else None)


@pytest.mark.parametrize(
    "listen",
    [
        {"unix-socket": "/tmp/kresd-socket"},
        {"unix-socket": ["/tmp/kresd-socket", "/tmp/kresd-socket2"]},
        {"interface": "::1"},
        {"interface": "::1@5353"},
        {"interface": "::1", "port": 5353},
        {"interface": ["127.0.0.1", "::1"]},
        {"interface": ["127.0.0.1@5353", "::1@5353"]},
        {"interface": ["127.0.0.1", "::1"], "port": 5353},
        {"interface": "lo"},
        {"interface": "lo@5353"},
        {"interface": "lo", "port": 5353},
        {"interface": ["lo", "eth0"]},
        {"interface": ["lo@5353", "eth0@5353"]},
        {"interface": ["lo", "eth0"], "port": 5353},
    ],
)
def test_listen_valid(listen: Dict[str, Any]):
    assert ListenSchema(listen)


@pytest.mark.parametrize(
    "listen",
    [
        {"unit-socket": "/tmp/kresd-socket", "port": "53"},
        {"interface": "::1", "unit-socket": "/tmp/kresd-socket"},
        {"interface": "::1@5353", "port": 5353},
        {"interface": ["127.0.0.1", "::1@5353"]},
        {"interface": ["127.0.0.1@5353", "::1@5353"], "port": 5353},
        {"interface": "lo@5353", "port": 5353},
        {"interface": ["lo", "eth0@5353"]},
        {"interface": ["lo@5353", "eth0@5353"], "port": 5353},
    ],
)
def test_listen_invalid(listen: Dict[str, Any]):
    with raises(KresManagerException):
        ListenSchema(listen)
