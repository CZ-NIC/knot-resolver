.. SPDX-License-Identifier: GPL-3.0-or-later

===========================
Manager's development guide
===========================

In this guide, we will setup a development environment, discuss tooling and high-level code architecture.


Development environment
=======================

The Manager is written in Python 3 with the goal of supporting multiple versions of Python available in current Linux distributions. For example, at the time of writing, this means we support Python 3.7 and newer. These compatibility requirements also force us not to rely heavily on modern runtime libraries such as Pydantic.

Tools
-----

To start working on the Manager, you need to install the following tools:

- Python, preferably the oldest supported version. You can use `pyenv <https://github.com/pyenv/pyenv>`_ to install and manage multiple Python versions on your system. Alternatively, some distros ship packages for older Python versions as well.
- `Poetry <https://python-poetry.org/>`_. We use it to manage our dependencies and virtual environments.


First run of the Manager from source
------------------------------------

1. clone `the Knot Resolver repository <https://gitlab.nic.cz/knot/knot-resolver>`_
2. enter the directory ``manager/`` in the repository, all following tasks will be performed from within that directory
3. run ``poetry env use $(which python3.7)`` to configure Poetry to use a different Python interpreter than the default
4. run ``poetry install`` to install all dependencies into a newly created virtual environment
5. run ``./poe run`` to run the Manager in dev mode (Ctrl+C to exit)

Helper scripts
--------------

In the previous section, you saw the use of the ``./poe`` command. `PoeThePoet <https://github.com/nat-n/poethepoet>`_ is a task runner which we use to simplify invoking common commands. You can run it by invoking ``./poe``, or you can install it system-wide via ``pip install poethepoet`` and invoke it just by calling ``poe`` (without the leading ``./``). When invoked globally, you don't have to worry about virtual environments and such, PoeThePoet figures that out for you and commands always run in the appropriate virtual environment.

To list the available commands, you can run ``poe help``. The most important ones for everyday development are:

- ``poe run`` to compile ``kresd`` and run the Manager
- ``poe run-debug`` same as ``run``, but also injects ``debugpy`` into the process to allow remote debugging on port 5678
- ``poe kresctl`` to run the Manager's CLI tool
- ``poe check`` to run static code analysis (enforced by our CI)
- ``poe test`` to run unit tests (enforced by our CI)
- ``poe format`` to autoformat the source code


The commands are defined in the ``pyproject.toml`` file.


Code editor
-----------

Feel free to use any text editor you like. However, we recommend using `Visual Studio Code <https://code.visualstudio.com/>`_ with `Pylance <https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance>`_ extension. That's what we use to work on the Manager and we know that it works really well for us. Just make sure to configure the extension so that it uses Poetry's virtual environment. We have a helper for that - ``poe config-vscode``, but your mileage may vary when using it.


Code structure
==============

The Manager's code is split into several distinct logical components:

- controllers
    - the HTTP API server (*the server*, ``server.py``)
    - high-level coordinator of ``kresd``'s (*the manager*, ``kres_manager.py``)
    - subprocess controller for launching and stopping ``kresd`` processes (*the subprocess controller*, ``kresd_controller/``)
- data
    - schema validation and definition (*the datamodel*, ``datamodel/``)
    - utilities, mainly general schema validation and parsing logic (*utils*, ``utils/``)
- ``kresctl`` utility (*kresctl*, ``cli/``)

When running, *the server* receives all inputs from the outside, passes them onto *the manager*, which applies the requested changes through the use of *the subprocess controller*. In all stages, we use *the datamodel* to pass current configuration around.


The subprocess controllers
--------------------------

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
------------------------------------

1. a change request is received by *the server*
2. the raw text input is parsed and verified into a configuration object using *the datamodel*
3. *the manager* is asked to apply new configuration
4. *the manager* starts a canary process with the new config (Lua config generated from the configration object), monitoring for failures
5. *the manager* restarts all ``kresd`` instances one by one
6. *the server* returns a success


Packaging
=========

Packaging is handled by `apkg <https://apkg.readthedocs.io/en/latest/>`_ cooperating with Poetry. To allow for backwards compatibility with Python tooling not supporting `PEP-517 <https://peps.python.org/pep-0517/>`_, we generate ``setup.py`` file with the command ``poe gen-setuppy``, so our project is compatible with ``setuptools`` as well.


Testing
=======

The manager has two suits of tests - unit tests and packaging tests, all residing in the ``manager/tests/`` directory. The units tests are run by `pytest <https://docs.pytest.org/>`_, while the packaging tests are distro specific and are using `apkg test <https://apkg.readthedocs.io/en/latest/commands/#test>`_.



