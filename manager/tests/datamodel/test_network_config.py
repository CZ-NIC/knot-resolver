import ipaddress

from knot_resolver_manager.datamodel.network_config import Network


def test_interfaces_default():
    o = Network()

    assert len(o.interfaces) == 2
    # {"listen": {"ip": "127.0.0.1", "port": 53}}
    assert o.interfaces[0].listen.ip == ipaddress.ip_address("127.0.0.1")
    assert o.interfaces[0].listen.port == 53
    assert o.interfaces[0].kind == "dns"
    assert o.interfaces[0].freebind == False
    # {"listen": {"ip": "::1", "port": 53}, "freebind": True}
    assert o.interfaces[1].listen.ip == ipaddress.ip_address("::1")
    assert o.interfaces[1].listen.port == 53
    assert o.interfaces[1].kind == "dns"
    assert o.interfaces[1].freebind == True
