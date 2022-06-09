from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.forward_zone_schema import ForwardServerSchema


def test_string_table():
    s = "any string"
    t = [s, "other string"]
    tmpl_str = """{% from 'macros/common_macros.lua.j2' import string_table %}
{{ string_table(x) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(x=s) == f"'{s}'"
    assert tmpl.render(x=t) == f"{{'{s}','{t[1]}',}}"


def test_str2ip_table():
    s = "2001:DB8::d0c"
    t = [s, "192.0.2.1"]
    tmpl_str = """{% from 'macros/common_macros.lua.j2' import str2ip_table %}
{{ str2ip_table(x) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(x=s) == f"kres.str2ip('{s}')"
    assert tmpl.render(x=t) == f"{{kres.str2ip('{s}'),kres.str2ip('{t[1]}'),}}"


def test_qtype_table():
    s = "AAAA"
    t = [s, "TXT"]
    tmpl_str = """{% from 'macros/common_macros.lua.j2' import qtype_table %}
{{ qtype_table(x) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(x=s) == f"kres.type.{s}"
    assert tmpl.render(x=t) == f"{{kres.type.{s},kres.type.{t[1]},}}"


def test_servers_table():
    s = "2001:DB8::d0c"
    t = [s, "192.0.2.1"]
    tmpl_str = """{% from 'macros/common_macros.lua.j2' import servers_table %}
{{ servers_table(x) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(x=s) == f"'{s}'"
    assert tmpl.render(x=t) == f"{{'{s}','{t[1]}',}}"
    assert tmpl.render(x=[{"address": s}, {"address": t[1]}]) == f"{{'{s}','{t[1]}',}}"


def test_tls_servers_table():
    d = ForwardServerSchema(
        {"address": "2001:DB8::d0c", "hostname": "res.example.com", "ca-file": "/etc/knot-resolver/tlsca.crt"}
    )
    t = [d, ForwardServerSchema({"address": "192.0.2.1", "pin-sha256": "YQ=="})]
    tmpl_str = """{% from 'macros/common_macros.lua.j2' import tls_servers_table %}
{{ tls_servers_table(x) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(x=[d.address, t[1].address]) == f"{{'{d.address}','{t[1].address}',}}"
    assert (
        tmpl.render(x=t)
        == f"{{{{'{d.address}',hostname='{d.hostname}',ca_file='{d.ca_file}',}},{{'{t[1].address}',pin_sha256='{t[1].pin_sha256}',}},}}"
    )
