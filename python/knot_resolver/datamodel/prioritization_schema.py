from knot_resolver.datamodel.types import TimeUnit
from knot_resolver.utils.modeling import ConfigSchema


class PrioritizationSchema(ConfigSchema):
    """
    Configuration of request prioritization (defer).

    ---
    enabled: Enable/disable request prioritization.
    logging_period: Minimal time between two log messages, or '0s' to disable.
    """

    enabled: bool = False
    logging_period: TimeUnit = TimeUnit("0s")
