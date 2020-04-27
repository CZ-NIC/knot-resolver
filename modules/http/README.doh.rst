.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-http-doh:

DNS-over-HTTP (DoH)
===================

.. warning::

  * DoH support was added in version 4.0.0 and is subject to change.
  * DoH implementation in Knot Resolver is intended for experimentation
    only as there is insufficient experience with the module
    and the DoH protocol in general.
  * For the time being it is recommended to run DoH endpoint
    on a separate machine which is not handling normal DNS operations.
  * Read about perceived benefits and risks at
    `Mozilla's DoH page <https://support.mozilla.org/en-US/kb/firefox-dns-over-https>`_.
  * It is important to understand **limits of encrypting only DNS traffic**.
    Relevant security analysis can be found in article
    *Simran Patil and Nikita Borisov. 2019. What can you learn from an IP?*
    See `slides <https://irtf.org/anrw/2019/slides-anrw19-final44.pdf>`_
    or `the article itself <https://dl.acm.org/authorize?N687437>`_.
  * Independent information about political controversies around the DoH
    deployment by default can be found in blog posts
    `DNS Privacy at IETF 104 <http://www.potaroo.net/ispcol/2019-04/angst.html>`_
    and
    `More DOH <http://www.potaroo.net/ispcol/2019-04/moredoh.html>`_
    by Geoff Huston
    and `Centralised DoH is bad for Privacy, in 2019 and beyond <https://labs.ripe.net/Members/bert_hubert/centralised-doh-is-bad-for-privacy-in-2019-and-beyond>`_
    by Bert Hubert.

Following section compares several options for running a DoH capable server.
Make sure you read through this chapter before exposing the DoH service to users.

DoH support in Knot Resolver
----------------------------

The :ref:`HTTP module <mod-http>` in Knot Resolver also provides support for
binary DNS-over-HTTP protocol standardized in :rfc:`8484`.

This integrated DoH server has following properties:

:Scenario:
        HTTP module in Knot Resolver configured to provide ``/doh`` endpoint
        (as shown below).

:Advantages:
        - Integrated solution provides management and monitoring in one place.
        - Supports ACLs for DNS traffic based on client's IP address.

:Disadvantages:
        - Exposes Knot Resolver instance to attacks over HTTP.
        - Does not offer fine grained authorization and logging at HTTP level.
        - Let's Encrypt integration is not automated.


:ref:`Example configuration <mod-http-example>` is part of examples for generic
HTTP module. After configuring your endpoint you can reach the DoH endpoint using
URL ``https://your.resolver.hostname.example/doh``, done!

.. code-block:: bash

	# query for www.knot-resolver.cz AAAA
	$ curl -k https://your.resolver.hostname.example/doh?dns=l1sBAAABAAAAAAAAA3d3dw1rbm90LXJlc29sdmVyAmN6AAAcAAE

Please see section :ref:`mod-http-tls` for further details about TLS configuration.

Alternative configurations use HTTP proxies between clients and a Knot Resolver instance:

Normal HTTP proxy
-----------------
:Scenario:
        A standard HTTP-compliant proxy is configured to proxy `GET`
        and `POST` requests to HTTP endpoint `/doh` to a machine
        running Knot Resolver.

:Advantages:
        - Protects Knot Resolver instance from
          `some` types of attacks at HTTP level.
        - Allows fine-grained filtering and logging at HTTP level.
        - Let's Encrypt integration is readily available.
        - Is based on mature software.

:Disadvantages:
        - Fine-grained ACLs for DNS traffic are not available because
          proxy hides IP address of client sending DNS query.
        - More complicated setup with two components (proxy + Knot Resolver).

HTTP proxy with DoH support
---------------------------
:Scenario:
        HTTP proxy extended with a
        `special module for DNS-over-HTTP <https://github.com/facebookexperimental/doh-proxy>`_.
        The module transforms HTTP requests to standard DNS queries
        which are then processed by Knot Resolver.
        DNS replies from Knot Resolver are then transformed back to HTTP
        encoding by the proxy.

:Advantages:
        - Protects Knot Resolver instance from `all` attacks at HTTP level.
        - Allows fine-grained filtering and logging at HTTP level.
        - Let's Encrypt integration is readily available
          if proxy is based on a standard HTTP software.

:Disadvantages:
        - Fine-grained ACLs for DNS traffic are not available because
          proxy hides IP address of client sending DNS query.
          (Unless proxy and resolver are using non-standard packet extensions like
          `DNS X-Proxied-For <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_.)
        - More complicated setup with three components (proxy + special module + Knot Resolver).

Client configuration
--------------------
Most common client today is web browser Firefox, which requires manual configuration
to use your own DNS resolver. Configuration options in Firefox are described at
`Mozilla support site <https://support.mozilla.org/en-US/kb/firefox-dns-over-https#w_switching-providers>`_.

.. warning::

  Make sure you read :ref:`warnings at beginning of this section <mod-http-doh>`.
