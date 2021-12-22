from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.network_schema import InterfaceSchema


def test_net_listen():
    ip = InterfaceSchema({"listen": {"ip": "::1", "port": 53}, "freebind": True})
    soc = InterfaceSchema({"listen": {"unix-socket": "/tmp/kresd-socket"}, "kind": "dot"})
    infc = InterfaceSchema({"listen": {"interface": "eth0"}, "kind": "doh"})

    tmpl_str = """{% from 'macros/network_macros.lua.j2' import net_listen %}
{{ net_listen(interface) }}"""

    tmpl = template_from_str(tmpl_str)
    assert (
        tmpl.render(interface=ip)
        == f"net.listen('{ip.listen.ip}',{ip.listen.port},{{kind='dns',freebind={str(ip.freebind).lower()}}})"
    )
    assert (
        tmpl.render(interface=soc)
        == f"net.listen('{soc.listen.unix_socket}',nil,{{kind='tls',freebind={str(soc.freebind).lower()}}})"
    )
    assert (
        tmpl.render(interface=infc)
        == f"net.listen(net.{infc.listen.interface},443,{{kind='doh',freebind={str(soc.freebind).lower()}}})"
    )
