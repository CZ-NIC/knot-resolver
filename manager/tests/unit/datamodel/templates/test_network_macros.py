from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.network_schema import ListenSchema


def test_network_listen():
    tmpl_str = """{% from 'macros/network_macros.lua.j2' import network_listen %}
{{ network_listen(listen) }}"""
    tmpl = template_from_str(tmpl_str)

    soc = ListenSchema({"unix-socket": "/tmp/kresd-socket", "kind": "dot"})
    assert tmpl.render(listen=soc) == "net.listen('/tmp/kresd-socket',nil,{kind='tls',freebind=false})"
    soc_list = ListenSchema({"unix-socket": [soc.unix_socket, "/tmp/kresd-socket2"], "kind": "dot"})
    assert (
        tmpl.render(listen=soc_list)
        == "net.listen('/tmp/kresd-socket',nil,{kind='tls',freebind=false})\n"
        + "net.listen('/tmp/kresd-socket2',nil,{kind='tls',freebind=false})\n"
    )

    ip = ListenSchema({"ip-address": "::1", "freebind": True})
    assert tmpl.render(listen=ip) == "net.listen('::1',53,{kind='dns',freebind=true})"
    ip_list = ListenSchema({"ip-address": [ip.ip_address, "127.0.0.1@5353"]})
    assert (
        tmpl.render(listen=ip_list)
        == "net.listen('::1',53,{kind='dns',freebind=false})\n"
        + "net.listen('127.0.0.1',5353,{kind='dns',freebind=false})\n"
    )

    intrfc = ListenSchema({"interface": "eth0", "kind": "doh2"})
    assert tmpl.render(listen=intrfc) == "net.listen(net.eth0,443,{kind='doh2',freebind=false})"
    intrfc_list = ListenSchema({"interface": [intrfc.interface, "lo@5353"], "port": 5555, "kind": "doh2"})
    assert (
        tmpl.render(listen=intrfc_list)
        == "net.listen(net.eth0,5555,{kind='doh2',freebind=false})\n"
        + "net.listen(net.lo,5353,{kind='doh2',freebind=false})\n"
    )
