from knot_resolver.datamodel.types import TimeUnit
from knot_resolver.utils.modeling import ConfigSchema


class DeferSchema(ConfigSchema):
    """
    Configuration of request prioritization (defer).

    ---
    enabled: Use request prioritization.
    log_period: Minimal time between two log messages, or '0s' to disable.
    hard_timeout: If a measured operation lasts longer, kresd is interrupted; use '0s' to disable.
    coredump_period: Minimal time between two coredumps caused by hard_timeout, or '0s' to disable them.
    """

    enabled: bool = False
    log_period: TimeUnit = TimeUnit("0s")
    hard_timeout: TimeUnit = TimeUnit("0s")
    coredump_period: TimeUnit = TimeUnit("10m")
