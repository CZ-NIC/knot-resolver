import pytest

from knot_resolver_manager.datamodel.cache_schema import PredictionSchema, PrefillSchema
from knot_resolver_manager.datamodel.config_schema import template_from_str


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            [
                PrefillSchema(
                    {
                        "origin": ".",
                        "url": "https://www.internic.net/domain/root.zone",
                    }
                )
            ],
            """prefill.config({
    ['.'] = {
        url = 'https://www.internic.net/domain/root.zone',
        interval = 86400,
    }
})""",
        ),
        (
            [
                PrefillSchema(
                    {
                        "origin": ".",
                        "url": "https://www.internic.net/domain/root.zone",
                        "refresh-interval": "12h",
                        "ca-file": "/etc/pki/tls/certs/ca-bundle.crt",
                    }
                )
            ],
            """prefill.config({
    ['.'] = {
        url = 'https://www.internic.net/domain/root.zone',
        interval = 43200,
        ca_file = '/etc/pki/tls/certs/ca-bundle.crt',
    }
})""",
        ),
    ],
)
def test_prefill_config(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/cache_macros.lua.j2' import prefill_config %}" "{{ prefill_config(config) }}"
    )
    assert tmpl.render(config=val, negation=False).replace(" ", "") == lua.replace(" ", "")


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            PredictionSchema(),
            """predict.config({
    window = 15,
    period = 24,
})""",
        ),
        (
            PredictionSchema(
                {
                    "window": "60m",
                }
            ),
            """predict.config({
    window = 60,
    period = 24,
})""",
        ),
        (
            PredictionSchema({"window": "60m", "period": 48}),
            """predict.config({
    window = 60,
    period = 48,
})""",
        ),
    ],
)
def test_predict_config(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/cache_macros.lua.j2' import predict_config %}" "{{ predict_config(config) }}"
    )
    assert tmpl.render(config=val, negation=False) == lua
