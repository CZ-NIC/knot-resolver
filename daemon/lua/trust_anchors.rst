.. SPDX-License-Identifier: GPL-3.0-or-later

.. warning:: Options in this section are intended only for expert users and
   normally should not be needed.

Since version 4.0, **DNSSEC validation is enabled by default**.
If you really need to turn DNSSEC off and are okay with lowering security of your
system by doing so, add the following snippet to your configuration file.

.. code-block:: lua

   -- turns off DNSSEC validation
   trust_anchors.remove('.')

The resolver supports DNSSEC including :rfc:`5011` automated DNSSEC TA updates
and :rfc:`7646` negative trust anchors.  Depending on your distribution, DNSSEC
trust anchors should be either maintained in accordance with the distro-wide
policy, or automatically maintained by the resolver itself.

In practice this means that you can forget about it and your favorite Linux
distribution will take care of it for you.

Following functions allow to modify DNSSEC configuration *if you really have to*:


.. function:: trust_anchors.add_file(keyfile[, readonly = false])

   :param string keyfile: path to the file.
   :param readonly: if true, do not attempt to update the file.

   The format is standard zone file, though additional information may be persisted in comments.
   Either DS or DNSKEY records can be used for TAs.
   If the file does not exist, bootstrapping of *root* TA will be attempted.
   If you want to use bootstrapping, install `lua-http`_ library.

   Each file can only contain records for a single domain.
   The TAs will be updated according to :rfc:`5011` and persisted in the file (if allowed).

   Example output:

   .. code-block:: lua

      > trust_anchors.add_file('root.key')
      [ ta ] new state of trust anchors for a domain:
      .                       165488  DS      19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
      nil

      [ ta ] key: 19036 state: Valid

.. function:: trust_anchors.remove(zonename)

   Remove specified trust anchor from trusted key set. Removing trust anchor for the root zone effectivelly disables DNSSEC validation (unless you configured another trust anchor).

   .. code-block:: lua

      > trust_anchors.remove('.')
      true

   If you want to disable DNSSEC validation for a particular domain but keep it enabled for the rest of DNS tree, use :func:`trust_anchors.set_insecure`.

.. envvar:: trust_anchors.hold_down_time = 30 * day

   :return: int (default: 30 * day)

   Modify RFC5011 hold-down timer to given value. Intended only for testing purposes. Example: ``30 * sec``

.. envvar:: trust_anchors.refresh_time = nil

   :return: int (default: nil)

   Modify RFC5011 refresh timer to given value (not set by default), this will force trust anchors
   to be updated every N seconds periodically instead of relying on RFC5011 logic and TTLs.
   Intended only for testing purposes.
   Example: ``10 * sec``

.. envvar:: trust_anchors.keep_removed = 0

   :return: int (default: 0)

   How many ``Removed`` keys should be held in history (and key file) before being purged.
   Note: all ``Removed`` keys will be purged from key file after restarting the process.


.. function:: trust_anchors.set_insecure(nta_set)

   :param table nta_list: List of domain names (text format) representing NTAs.

   When you use a domain name as an *negative trust anchor* (NTA), DNSSEC validation will be turned off at/below these names.
   Each function call replaces the previous NTA set. You can find the current active set in ``trust_anchors.insecure`` variable.
   If you want to disable DNSSEC validation completely use :func:`trust_anchors.remove` function instead.

   Example output:

   .. code-block:: lua

      > trust_anchors.set_insecure({ 'bad.boy', 'example.com' })
      > trust_anchors.insecure
      [1] => bad.boy
      [2] => example.com

   .. warning:: If you set NTA on a name that is not a zone cut,
      it may not always affect names not separated from the NTA by a zone cut.

.. function:: trust_anchors.add(rr_string)

   :param string rr_string: DS/DNSKEY records in presentation format (e.g. ``. 3600 IN DS 19036 8 2 49AAC11...``)

   Inserts DS/DNSKEY record(s) into current keyset. These will not be managed or updated, use it only for testing
   or if you have a specific use case for not using a keyfile.

   .. note:: Static keys are very error-prone and should not be used in production. Use :func:`trust_anchors.add_file` instead.

   Example output:

   .. code-block:: lua

      > trust_anchors.add('. 3600 IN DS 19036 8 2 49AAC11...')

.. function:: trust_anchors.summary()

   Return string with summary of configured DNSSEC trust anchors, including negative TAs.

.. _lua-http: https://luarocks.org/modules/daurnimator/http
