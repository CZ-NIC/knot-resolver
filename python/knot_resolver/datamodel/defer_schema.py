from knot_resolver.datamodel.types import TimeUnit
from knot_resolver.utils.modeling import ConfigSchema


class DeferSchema(ConfigSchema):
    """
    Configuration of request prioritization (defer).

    ---
    enable: Use request prioritization.
    log_period: Minimal time between two log messages, or '0s' to disable.
    """

    enable: bool = False
    log_period: TimeUnit = TimeUnit("0s")
