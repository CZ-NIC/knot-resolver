.. SPDX-License-Identifier: GPL-3.0-or-later

Modules
=======

Knot Resolver functionality consists of separate modules, which allow you
to mix-and-match features you need without slowing down operation
by features you do not use.

This practically means that you need to load module before using features contained in it, for example:

.. code-block:: lua

        -- load module and make dnstap features available
        modules.load('dnstap')
        -- configure dnstap features
        dnstap.config({
                socket_path = "/tmp/dnstap.sock"
        })

Obviously ordering matters, so you have to load module first and configure it after it is loaded.

Here is full reference manual for module configuration:


.. function:: modules.list()

   :return: List of loaded modules.

.. function:: modules.load(name)

   :param string name: Module name, e.g. "hints"
   :return: ``true`` if modules was (or already is) loaded, error otherwise.

   Load a module by name.

.. function:: modules.unload(name)

   :param string name: Module name, e.g. "detect_time_jump"
   :return: ``true`` if modules was unloaded, error otherwise.

   Unload a module by name. This is useful for unloading modules loaded by default, mainly for debugging purposes.

