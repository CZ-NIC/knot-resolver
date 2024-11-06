from knot_resolver.datamodel.types import (
    Int0_32,
    IntPositive,
    TimeUnit,
)
from knot_resolver.utils.modeling import ConfigSchema


class RateLimitingSchema(ConfigSchema):
    """
    Configuration of rate limiting.

    ---
    capacity: Expected maximal number of blocked networks/hosts at the same time.
    rate_limit: Maximal number of allowed queries per second from a single host.
    instant_limit: Maximal number of allowed queries at a single point in time from a single host.
    slip: Number of restricted responses out of which one is sent as truncated, the others are dropped.
    log_period: Minimal time between two log messages, or '0s' to disable.
    dry_run: Perform only classification and logging but no restrictions.
    """

    capacity: IntPositive = IntPositive(524288)
    rate_limit: IntPositive
    instant_limit: IntPositive = IntPositive(50)
    slip: Int0_32 = Int0_32(2)
    log_period: TimeUnit = TimeUnit("0s")
    dry_run: bool = False

    def _validate(self) -> None:
        max_instant_limit = int(2 ** 32 // 768 - 1)
        if not int(self.instant_limit) <= max_instant_limit:
            raise ValueError(f"'instant-limit' has to be in range 1..{max_instant_limit}")
        if not int(self.rate_limit) <= 1000 * int(self.instant_limit):
            raise ValueError("'rate-limit' has to be in range 1..(1000 * instant-limit)")
