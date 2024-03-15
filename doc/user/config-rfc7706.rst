.. SPDX-License-Identifier: GPL-3.0-or-later

Root on loopback (RFC 7706)
---------------------------
Knot Resolver developers think that literal implementation of :rfc:`7706`
("Decreasing Access Time to Root Servers by Running One on Loopback")
is a bad idea so it is not implemented in the form envisioned by the RFC.

You can get the very similar effect without its downsides by combining
:ref:`config-cache-prefill` and :ref:`config-serve-stale` modules with Aggressive Use
of DNSSEC-Validated Cache (:rfc:`8198`) behavior which is enabled
automatically together with DNSSEC validation.
