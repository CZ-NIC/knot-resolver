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


def test_listen_kind_port_defaults():
    assert ListenSchema({"unix-socket": "/tmp/kresd-socket"}).port == None
    assert ListenSchema({"interface": "::1"}).port == PortNumber(53)
    assert ListenSchema({"interface": "::1", "kind": "dot"}).port == PortNumber(853)
    assert ListenSchema({"interface": "::1", "kind": "doh-legacy"}).port == PortNumber(443)
    assert ListenSchema({"interface": "::1", "kind": "doh2"}).port == PortNumber(443)


def test_listen_unix_socket_valid():
    assert ListenSchema({"unix-socket": "/tmp/kresd-socket"})
    assert ListenSchema({"unix-socket": ["/tmp/kresd-socket", "/tmp/kresd-socket2"]})


def test_listen_unix_socket_invalid():
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "unix-socket": "/tmp/kresd-socket"})
    with raises(KresManagerException):
        ListenSchema({"unit-socket": "/tmp/kresd-socket", "port": "53"})


def test_listen_ip_address_valid():
    assert ListenSchema({"interface": "::1"})
    assert ListenSchema({"interface": "::1@5353"})
    assert ListenSchema({"interface": "::1", "port": 5353})
    assert ListenSchema({"interface": ["127.0.0.1", "::1"]})
    assert ListenSchema({"interface": ["127.0.0.1@5353", "::1@5353"]})
    assert ListenSchema({"interface": ["127.0.0.1", "::1"], "port": 5353})


def test_listen_ip_address_invalid():
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1@5353", "port": 5353})
    with raises(KresManagerException):
        ListenSchema({"ip-address": ["127.0.0.1", "::1@5353"]})
    with raises(KresManagerException):
        ListenSchema({"ip-address": ["127.0.0.1@5353", "::1@5353"], "port": 5353})


def test_listen_interface_valid():
    assert ListenSchema({"interface": "lo"})
    assert ListenSchema({"interface": "lo@5353"})
    assert ListenSchema({"interface": "lo", "port": 5353})
    assert ListenSchema({"interface": ["lo", "eth0"]})
    assert ListenSchema({"interface": ["lo@5353", "eth0@5353"]})
    assert ListenSchema({"interface": ["lo", "eth0"], "port": 5353})


def test_listen_interface_invalid():
    with raises(KresManagerException):
        ListenSchema({"interface": "lo@5353", "port": 5353})
    with raises(KresManagerException):
        ListenSchema({"interface": ["lo", "eth0@5353"]})
    with raises(KresManagerException):
        ListenSchema({"interface": ["lo@5353", "eth0@5353"], "port": 5353})


def test_listen_invalid():
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "port": 0})
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "port": 65_536})
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "interface": "lo"})
