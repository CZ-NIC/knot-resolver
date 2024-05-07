from knot_resolver_manager.datamodel.types import Percent
from knot_resolver_manager.utils.modeling import ConfigSchema


class RateLimitingSchema(ConfigSchema):
    """
    Configuration of rate limiting.

    ---
    capacity: Expected maximal number of blocked networks/hosts at the same time.
    rate_limit: Number of allowed queries per second from a single host.
    instant_limit: Number of allowed queries at a single point in time from a single host.
    tc_limit_perc: Percent of rate/instant limit from which responses are sent as truncated.
    """

    capacity: int = 524288
    rate_limit: int
    instant_limit: int = 50
    tc_limit_perc: Percent = Percent(90)

    def _validate(self) -> None:
        max_instant_limit = int(2**32 / 768 - 1)
        if not 1 <= self.instant_limit <= max_instant_limit:
            raise ValueError(f"'instant-limit' should be in range 1..{max_instant_limit}")
        if not 1 <= self.rate_limit <= 1000 * self.instant_limit:
            raise ValueError("'rate-limit' should be in range 1..(1000 * instant-limit)")
        if self.capacity <= 0:
            raise ValueError("'capacity' should be positive")
