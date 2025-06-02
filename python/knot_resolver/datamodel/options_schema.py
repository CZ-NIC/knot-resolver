from typing import Literal

from knot_resolver.utils.modeling import ConfigSchema

GlueCheckingEnum = Literal["normal", "strict", "permissive"]


class OptionsSchema(ConfigSchema):
    """
    Fine-tuning global parameters of DNS resolver operation.

    ---
    glue_checking: Glue records strictness checking level.
    minimize: Send minimum amount of information in recursive queries to enhance privacy.
    query_loopback: Permits queries to loopback addresses.
    reorder_rrset: Controls whether resource records within a RRSet are reordered each time it is served from the cache.
    query_case_randomization: Randomize Query Character Case.
    priming: Initializing DNS resolver cache with Priming Queries (RFC 8109)
    rebinding_protection: Protection against DNS Rebinding attack.
    refuse_no_rd: Queries without RD (recursion desired) bit set in query are answered with REFUSED.
    time_jump_detection: Detection of difference between local system time and expiration time bounds in DNSSEC signatures for '. NS' records.
    violators_workarounds: Workarounds for known DNS protocol violators.
    serve_stale: Allows using timed-out records in case DNS resolver is unable to contact upstream servers.
    """

    glue_checking: GlueCheckingEnum = "normal"
    minimize: bool = True
    query_loopback: bool = False
    reorder_rrset: bool = True
    query_case_randomization: bool = True
    priming: bool = True
    rebinding_protection: bool = False
    refuse_no_rd: bool = True
    time_jump_detection: bool = True
    violators_workarounds: bool = False
    serve_stale: bool = False
