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


def test_listen_validation():
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "port": -10})
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "interface": "eth0"})
    with raises(KresManagerException):
        ListenSchema({"ip-address": "::1", "unit-socket": "/tmp/kresd-socket"})
    with raises(KresManagerException):
        ListenSchema({"unit-socket": "/tmp/kresd-socket", "port": "53"})
