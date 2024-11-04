from knot_resolver.utils.modeling import ConfigSchema


class DeferSchema(ConfigSchema):
    """
    Configuration of request prioritization (defer).

    ---
    enabled: Use request prioritization.
    """

    enabled: bool = True
