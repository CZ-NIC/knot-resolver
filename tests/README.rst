.. SPDX-License-Identifier: GPL-3.0-or-later

Unit tests
==========

The unit tests depend on cmocka_.

.. code-block:: bash

	$ make check

.. todo:: Writing tests.

Integration tests
=================

The integration tests are using Deckard, the `DNS test harness <deckard>`_.
It requires Jinja2_ and Python, `socket_wrapper`_, libfaketime_ are embedded in the build (cmake is required for `socket_wrapper`_).

Execute the tests by:

.. code-block:: bash

	$ make check-integration

See deckard_ documentation on how to write additional tests.

.. _cmocka: https://cmocka.org/
.. _`socket_wrapper`: https://cwrap.org/socket_wrapper.html
.. _`libfaketime`: https://github.com/wolfcw/libfaketime
.. _deckard: https://gitlab.nic.cz/knot/deckard
