import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.dnssec_schema import TrustAnchorFileSchema


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            [". 3600 IN DS 19036 8 2 49AAC11...", ". 3600 IN DS 19036 8 2 49AAC11..."],
            """trust_anchors.add('. 3600 IN DS 19036 8 2 49AAC11...')
trust_anchors.add('. 3600 IN DS 19036 8 2 49AAC11...')\n""",
        )
    ],
)
def test_trust_anchors(val, lua):
    tmpl = template_from_str("{% from 'macros/dnssec_macros.lua.j2' import trust_anchors %}" "{{ trust_anchors(tas) }}")
    assert tmpl.render(tas=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            ["bad.boy", "example.com"],
            """trust_anchors.set_insecure({
    'bad.boy',
    'example.com',
})""",
        )
    ],
)
def test_negative_trust_anchors(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/dnssec_macros.lua.j2' import negative_trust_anchors %}" "{{ negative_trust_anchors(ntas) }}"
    )
    assert tmpl.render(ntas=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            [
                TrustAnchorFileSchema({"file": "/path/to/tafile", "read-only": True}),
                TrustAnchorFileSchema({"file": "/path/to/another/tafile"}),
            ],
            """trust_anchors.add_file('/path/to/tafile',  readonly = true)
trust_anchors.add_file('/path/to/another/tafile',  readonly = false)\n""",
        )
    ],
)
def test_trust_anchors_files(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/dnssec_macros.lua.j2' import trust_anchors_files %}" "{{ trust_anchors_files(tafs) }}"
    )
    assert tmpl.render(tafs=val) == lua
