.. SPDX-License-Identifier: GPL-3.0-or-later

.. _tls-server-config:

DNS-over-TLS server (DoT)
-------------------------
DoT encrypts DNS traffic with Transport Security Layer protocol and thus protects DNS traffic from certain types of attacks.

.. warning::

   It is important to understand **limits of encrypting only DNS traffic**.
   Relevant security analysis can be found in article
   *Simran Patil and Nikita Borisov. 2019. What can you learn from an IP?*
   See `slides <https://irtf.org/anrw/2019/slides-anrw19-final44.pdf>`_
   or `the article itself <https://dl.acm.org/authorize?N687437>`_.

DNS-over-TLS server (:rfc:`7858`) is enabled by default on localhost.
Information how to configure listening on specific IP addresses is in previous sections:
:func:`net.listen()`.

By default a self-signed certificate is generated. For serious deployments
it is strongly recommended to configure your own TLS certificates signed
by a trusted CA. This is done using function :c:func:`net.tls()`.

.. function:: net.tls([cert_path], [key_path])

   Get/set path to a server TLS certificate and private key for DNS-over-TLS
   and DNS-over-HTTPS (doesn't apply to legacy `doh` handled by http module).

   Example output:

   .. code-block:: lua

      > net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")
      > net.tls()  -- print configured paths
      ("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")

.. function:: net.tls_padding([true | false])

   Get/set EDNS(0) padding of answers to queries that arrive over TLS
   transport.  If set to `true` (the default), it will use a sensible
   default padding scheme, as implemented by libknot if available at
   compile time.  If set to a numeric value >= 2 it will pad the
   answers to nearest *padding* boundary, e.g. if set to `64`, the
   answer will have size of a multiple of 64 (64, 128, 192, ...).  If
   set to `false` (or a number < 2), it will disable padding entirely.

.. function:: net.tls_sticket_secret([string with pre-shared secret])

   Set secret for TLS session resumption via tickets, by :rfc:`5077`.

   The server-side key is rotated roughly once per hour.
   By default or if called without secret, the key is random.
   That is good for long-term forward secrecy, but multiple kresd instances
   won't be able to resume each other's sessions.

   If you provide the same secret to multiple instances, they will be able to resume
   each other's sessions *without* any further communication between them.
   This synchronization works only among instances having the same endianess
   and time_t structure and size (`sizeof(time_t)`).

   **For good security** the secret must have enough entropy to be hard to guess,
   and it should still be occasionally rotated manually and securely forgotten,
   to reduce the scope of privacy leak in case the
   `secret leaks eventually <https://en.wikipedia.org/wiki/Forward_secrecy>`_.

   .. warning:: **Setting the secret is probably too risky with TLS <= 1.2**.
      GnuTLS stable release supports TLS 1.3 since 3.6.3 (summer 2018).
      Therefore setting the secrets should be considered experimental for now
      and might not be available on your system.

.. function:: net.tls_sticket_secret_file([string with path to a file containing pre-shared secret])

   The same as :func:`net.tls_sticket_secret`,
   except the secret is read from a (binary) file.
