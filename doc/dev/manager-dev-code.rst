.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-dev-code:

****************************
The manager's code structure
****************************

The manager's code is split into several distinct logical components:

- controllers
    - the HTTP API server (*the server*, ``server.py``)
    - high-level coordinator of ``kresd``'s (*the manager*, ``kres_manager.py``)
    - subprocess controller for launching and stopping ``kresd`` processes (*the subprocess controller*, ``kresd_controller/``)
- data
    - schema validation and definition (*the datamodel*, ``datamodel/``)
    - utilities, mainly general schema validation and parsing logic (*utils*, ``utils/``)
- ``kresctl`` utility (*kresctl*, ``cli/``)

When running, *the server* receives all inputs from the outside, passes them onto *the manager*,
which applies the requested changes through the use of *the subprocess controller*.
In all stages, we use *the datamodel* to pass current configuration around.


The subprocess controllers
==========================

Internally, the subprocess controllers are hidden behind an interface and there can be multiple implementations. In practice, there is only one and that is `supervisord <http://supervisord.org>`_. Historically, we tried to support systemd as well, but due to privilege escalation issues, we started focusing only on supervisord.

The supervisord subprocess controller actually extends supervisord with new functionality, especially it reimplements ``sd_notify`` semantics from systemd. Supervisord is extended through loading plugins, which in turn modify few internal components of supervisord. Due to the maturity of the supervisord project, we believe this will be reasonably stable even with updates for supervisord.

We want to have the Manager restarted if it fails, so that one mishandled API request can't bring everything down. We want the subprocess controllers to control the execution of the Manager and restart it, if needed. Therefore, there is a circular dependency. To solve it, the subprocess controller implementations are allowed to ``exec()`` into anything else while starting. To give an example of how the startup works with supervisord:

1. *the server* loads the config, initiates *the manager* and *the supervisord subprocess controller*
2. *the supervisord subprocess controller* detects, that there is no supervisord running at the moment, generates new supervisord config and exec's supervisord
3. supervisord starts, loads its config and starts *the server* again
4. *the server* loads the config, initiates *the manager* and *the supervisord subprocess controller*
5. *the supervisord subprocess controller* detects, that there is a supervisord instance running, generates new config for it and reloads it
6. *the manager* starts new workers based on the initial configuration
7. *the server* makes it's API available to use and the Manager is fully running


Processing of config change requests
====================================

1. a change request is received by *the server*
2. the raw text input is parsed and verified into a configuration object using *the datamodel*
3. *the manager* is asked to apply new configuration
4. *the manager* starts a canary process with the new config (Lua config generated from the configration object), monitoring for failures
5. *the manager* restarts all ``kresd`` instances one by one
6. *the server* returns a success
