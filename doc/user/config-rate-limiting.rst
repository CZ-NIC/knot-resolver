.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-rate-limiting:

Rate limiting
=============

Rate limiting is a method to combat DNS reflection amplification
attacks. These attacks rely on the fact that the source address of a UDP query
can be forged, and without a worldwide deployment of `BCP38
<https://tools.ietf.org/html/bcp38>`_, such a forgery cannot be prevented.
An attacker can use a DNS server (or multiple servers) as an amplification
source to flood a victim with a large number of unsolicited DNS responses.
Rate limiting lowers the amplification factor of these attacks by sending some
responses as truncated or by dropping them altogether.

See the `operator's overview blogpost <https://en.blog.nic.cz/2024/07/15/knot-resolver-6-news-dos-protection-operators-overview/>`_
for more in depth introduction to this section,
but beware that the *soft limit* was dropped in favor of the *slip* mechanism
that's common in other DNS servers.


.. option:: rate-limiting/rate-limit: <int>

    Maximal allowed number of UDP queries per second from a single IPv6 or IPv4 address.
    To be set according to the server performance.
    Setting the value enables rate limiting as the rest of the configuration is optional.

    Rate limiting is performed for the whole address and several chosen prefixes.
    The limits of prefixes are constant multiples of :option:`rate-limit <rate-limiting/rate-limit: <int>`.
    The specific prefixes and multipliers, which might be adjusted in the future, are as follows:

    .. table::

       +------+------+------+------+------+------+
       | IPv6 | /128 |  /64 |  /56 |  /48 |  /32 |
       +======+======+======+======+======+======+
       |      |    1 |    2 |    3 |    4 |   64 |
       +------+------+------+------+------+------+

    .. table::

       +------+------+------+------+------+
       | IPv4 |  /32 |  /24 |  /20 |  /18 |
       +======+======+======+======+======+
       |      |    1 |   32 |  256 |  768 |
       +------+------+------+------+------+

    With each host/network, a counter of unrestricted responses is associated;
    if the counter would exceed its capacity, it is not incremented and the response is restricted.
    Counters use exponential decay for lowering their values,
    i.e. they are lowered by a constant fraction of their value each millisecond.
    The specified rate limit is reached, when the number of queries is the same every millisecond;
    sending many queries once a second or even a larger timespan leads to a more strict limiting.


.. option:: rate-limiting/instant-limit: <int>

    :default: 50

    Maximal allowed number of queries at a single point in time from a single IPv6 or IPv4 address.
    To be set according to the expected normal behaviour of clients; likely not needed to be alterered.
    The limits for prefixes use the same multipliers as for :option:`rate-limit <rate-limiting/rate-limit: <int>`.

    This limit is relevant for bursts of queries,
    e.g. when a recently inactive host/network suddenly starts sending many queries.

    The :option:`instant-limit <rate-limiting/instant-limit: <int>`
    sets the actual capacity of each counter of responses,
    and together with the :option:`rate-limit <rate-limiting/rate-limit: <int>`
    they set the fraction by which the counter is periodically lowered.
    The :option:`instant-limit <rate-limiting/instant-limit: <int>` may be at least
    :option:`rate-limit <rate-limiting/rate-limit: <int>` **/ 1000**, at which point the
    counters are zeroed each millisecond.


.. option:: rate-limiting/slip: <int>

    :default: 2

    Number of restricted responses out of which one is sent as truncated, the others are dropped.

    As attacks using DNS/UDP are usually based on a forged source address,
    an attacker could deny services to the victim's netblock if all
    responses would be completely blocked. The idea behind SLIP mechanism
    is to send each N\ :sup:`th` response as truncated, thus allowing client to
    reconnect via TCP for at least some degree of service. It is worth
    noting, that some responses can't be truncated (e.g. SERVFAIL).

    - Setting the value to **0** will cause all rate-limited responses to
      be dropped. The outbound bandwidth and packet rate will be strictly capped
      by the :option:`rate-limit <rate-limiting/rate-limit: <int>` option.
      All legitimate requestors affected
      by the limit will face denial of service and will observe excessive timeouts.
      Therefore this setting is not recommended.

    - Setting the value to **1** will cause all rate-limited responses to
      be sent as truncated. The amplification factor of the attack will be reduced,
      but the outbound data bandwidth won't be lower than the incoming bandwidth.
      Also the outbound packet rate will be the same as without rate limiting.

    - Setting the value to **2** will cause approximately half of the rate-limited responses
      to be dropped, and the other half will be sent as truncated. With this
      configuration, both outbound bandwidth and packet rate will be lower than the
      inbound. On the other hand, the dropped responses enlarge the time window
      for possible cache poisoning attack on the resolver.

    - Setting the value to anything **larger than 2** will keep on decreasing
      the outgoing rate-limited bandwidth, packet rate, and chances to notify
      legitimate requestors to reconnect using TCP. These attributes are inversely
      proportional to the configured value. Setting the value high is not advisable.


.. option:: rate-limiting/capacity: <int>

    :default: 524288

    Maximal number of stored hosts/networks with their counters.
    The data structure tries to store only the most frequent sources,
    so it is safe to set it according to the expected maximal number of limited ones.

    Use **1.4 *** ``maximum-qps`` **/** :option:`rate-limit <rate-limiting/rate-limit: <int>`,
    where ``maximum-qps`` is the number of queries which can be handled by the server per second.
    There is at most ``maximum-qps`` **/** :option:`rate-limit <rate-limiting/rate-limit: <int>` limited hosts;
    larger networks have higher limits, so they require only a fraction of the value (handled by the **1.4** multiplier).
    The value will be rounded up to the nearest power of two.

    The memory occupied by one table structure is **8 *** :option:`capacity <rate-limiting/capacity: <int>` Bytes.


.. option:: rate-limiting/log-period: <time ms|s|m|h|d>

    :default: 0s

    Minimal time between two log messages, or ``0s`` to disable logging.

    If a response is limited, the address and the prefix on which it was blocked is logged
    and logging is disabled for the :option:`log-period <rate-limiting/log-period: <time ms|s|m|h|d>`.
    As long as limiting is needed, one source is logged each period
    and sources with more blocked queries have greater probability to be chosen.


.. option:: rate-limiting/dry-run: true|false

    :default: false

    Perform only classification and logging but no restrictions.
