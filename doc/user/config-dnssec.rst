.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-dnssec:

*************************
DNSSEC, data verification
*************************

Good news! Knot Resolver uses secure configuration by default, and this configuration
should not be changed unless absolutely necessary, so feel free to skip over this section.

.. warning::

   Options in this section are intended only for expert users and normally should not be needed.

Since version 4.0, **DNSSEC validation is enabled by default**.
If you really need to turn DNSSEC off and are okay with lowering security of your
system by doing so, add the following snippet to your configuration file.

.. code-block:: yaml

   # turns off DNSSEC validation
   dnssec:
     enable: false

The resolver supports DNSSEC including :rfc:`5011` automated DNSSEC TA updates
and :rfc:`7646` negative trust anchors.  Depending on your distribution, DNSSEC
trust anchors should be either maintained in accordance with the distro-wide
policy, or automatically maintained by the resolver itself.

In practice this means that you can forget about it and your favorite Linux
distribution will take care of it for you.

Following :option:`dnssec <dnssec: <options>>` section allows to modify DNSSEC configuration *if you really have to*:

.. option:: dnssec: <options>

   DNSSEC configuration options.

   .. option:: enable: true|false

      :default: true

      If ``false``, DNSSEC is disabled.

   .. option:: trust-anchors-files: <list>

      .. option:: file: <path>

         Path to the key file.

      .. option:: read-only: true|false

         :default: false

         Blocks zonefile updates according to :rfc:`5011`.

      The format is standard zone file, though additional information may be persisted in comments.
      Either DS or DNSKEY records can be used for TAs.
      If the file does not exist, bootstrapping of *root* TA will be attempted.
      If you want to use bootstrapping, install `lua-http`_ library.

      Each file can only contain records for a single domain.
      The TAs will be updated according to :rfc:`5011` and persisted in the file (if allowed).

      .. code-block:: yaml

         dnssec:
           trust-anchors-files:
             - file: root.key
               read-only: false

   .. option:: trust-anchors-keep-removed: <int>

      :default: 0

      How many ``Removed`` keys should be held in history (and key file) before being purged.
      Note: all ``Removed`` keys will be purged from key file after restarting the process.

   .. option:: negative-trust-anchors: <list of domain names>

      When you use a domain name as an *negative trust anchor* (NTA), DNSSEC validation will be turned off at/below these names.
      If you want to disable DNSSEC validation completely, set ``dnssec: false`` instead.

      .. code-block:: yaml

         dnssec:
           negative-trust-anchors:
             - bad.boy
             - example.com

      .. warning::

         If you set NTA on a name that is not a zone cut, it may not always affect names not separated from the NTA by a zone cut.

   .. option:: trust-anchors: <list of RR strings>

      Inserts DS/DNSKEY record(s) in presentation format (e.g. ``. 3600 IN DS 19036 8 2 49AAC11...``) into current keyset.
      These will not be managed or updated, use it only for testing or if you have a specific use case for not using a keyfile.

      .. note::

         Static keys are very error-prone and should not be used in production. Use :option:`trust-anchors-files <trust-anchors-files: <list>>` instead.

      .. code-block:: yaml

         dnssec:
           trust-anchors:
             - ". 3600 IN DS 19036 8 2 49AAC11..."

DNSSEC is main technology to protect data, but it is also possible to change how strictly
resolver checks data from insecure DNS zones:

.. option:: options/glue-checking: normal|strict|permissive

   :default: normal

   The resolver strictness checking level.

   By default, resolver runs in *normal* mode. There are possibly many small adjustments
   hidden behind the mode settings, but the main idea is that in *permissive* mode, the resolver
   tries to resolve a name with as few lookups as possible, while in *strict* mode it spends much
   more effort resolving and checking referral path. However, if majority of the traffic is covered
   by DNSSEC, some of the strict checking actions are counter-productive.

   .. csv-table::
    :header: "Glue type", "Modes when it is accepted",   "Example glue [#example_glue]_"

    "mandatory glue",     "strict, normal, permissive",  "ns1.example.org"
    "in-bailiwick glue",  "normal, permissive",          "ns1.example2.org"
    "any glue records",   "permissive",                  "ns1.example3.net"

   .. [#example_glue] The examples show glue records acceptable from servers
        authoritative for `org` zone when delegating to `example.org` zone.
        Unacceptable or missing glue records trigger resolution of names listed
        in NS records before following respective delegation.

.. _lua-http: https://luarocks.org/modules/daurnimator/http
