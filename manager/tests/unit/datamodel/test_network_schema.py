from pytest import raises

from knot_resolver_manager.datamodel.network_schema import ListenSchema, NetworkSchema
from knot_resolver_manager.datamodel.types import IPAddressPort
from knot_resolver_manager.exceptions import KresManagerException


def test_listen_defaults():
    o = NetworkSchema()

    assert len(o.listen) == 2
    # {"ip-address": "127.0.0.1"}
    assert o.listen[0].ip_address == IPAddressPort("127.0.0.1")
    assert o.listen[0].port == 53
    assert o.listen[0].kind == "dns"
    assert o.listen[0].freebind == False
    # {"ip-address": "::1", "freebind": True}
    assert o.listen[1].ip_address == IPAddressPort("::1")
    assert o.listen[1].port == 53
    assert o.listen[1].kind == "dns"
    assert o.listen[1].freebind == True


def test_listen_kind_port_defaults():
    soc = ListenSchema({"unix-socket": "/tmp/kresd-socket"})
    dns = ListenSchema({"ip-address": "::1"})
    dot = ListenSchema({"ip-address": "::1", "kind": "dot"})
    doh2 = ListenSchema({"ip-address": "::1", "kind": "doh2"})

    assert soc.port == None
    assert dns.port == 53
    assert dot.port == 853
    assert doh2.port == 443


def test_listen_unix_socket():
    assert ListenSchema({"unix-socket": "/tmp/kresd-socket"})
    assert ListenSchema({"unix-socket": ["/tmp/kresd-socket", "/tmp/kresd-socket2"]})

    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "unix-socket": "/tmp/kresd-socket"})
    with raises(KresManagerException):
        ListenSchema({"unit-socket": "/tmp/kresd-socket", "port": "53"})


def test_listen_ip_address():
    assert ListenSchema({"ip-address": "::1"})
    assert ListenSchema({"ip-address": "::1@5353"})
    assert ListenSchema({"ip-address": "::1", "port": 5353})
    assert ListenSchema({"ip-address": ["127.0.0.1", "::1"]})
    assert ListenSchema({"ip-address": ["127.0.0.1@5353", "::1@5353"]})
    assert ListenSchema({"ip-address": ["127.0.0.1", "::1"], "port": 5353})

    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1@5353", "port": 5353})
    with raises(KresManagerException):
        ListenSchema({"ip-address": ["127.0.0.1", "::1@5353"]})
    with raises(KresManagerException):
        ListenSchema({"ip-address": ["127.0.0.1@5353", "::1@5353"], "port": 5353})


def test_listen_interface():
    assert ListenSchema({"interface": "lo"})
    assert ListenSchema({"interface": "lo@5353"})
    assert ListenSchema({"interface": "lo", "port": 5353})
    assert ListenSchema({"interface": ["lo", "eth0"]})
    assert ListenSchema({"interface": ["lo@5353", "eth0@5353"]})
    assert ListenSchema({"interface": ["lo", "eth0"], "port": 5353})

    with raises(KresManagerException):
        ListenSchema({"interface": "lo@5353", "port": 5353})
    with raises(KresManagerException):
        ListenSchema({"interface": ["lo", "eth0@5353"]})
    with raises(KresManagerException):
        ListenSchema({"interface": ["lo@5353", "eth0@5353"], "port": 5353})


def test_listen_validation():
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "port": -10})
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "interface": "eth0"})
