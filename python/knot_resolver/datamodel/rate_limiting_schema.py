from knot_resolver.utils.modeling import ConfigSchema


class RateLimitingSchema(ConfigSchema):
    """
    Configuration of rate limiting.

    ---
    capacity: Expected maximal number of blocked networks/hosts at the same time.
    rate_limit: Maximal number of allowed queries per second from a single host.
    instant_limit: Maximal number of allowed queries at a single point in time from a single host.
    slip: Number of restricted responses out of which one is sent as truncated, the others are dropped.
    """

    capacity: int = 524288
    rate_limit: int
    instant_limit: int = 50
    slip: int = 2

    def _validate(self) -> None:
        max_instant_limit = int(2**32 / 768 - 1)
        if not 1 <= self.instant_limit <= max_instant_limit:
            raise ValueError(f"'instant-limit' has to be in range 1..{max_instant_limit}")
        if not 1 <= self.rate_limit <= 1000 * self.instant_limit:
            raise ValueError("'rate-limit' has to be in range 1..(1000 * instant-limit)")
        if not 0 < self.capacity:
            raise ValueError("'capacity' has to be positive")
        if not 0 <= self.slip <= 100:
            raise ValueError("'slip' has to be in range 0..100")
