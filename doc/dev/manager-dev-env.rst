.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-dev-env:

*******************************
Manager development environment
*******************************

In this guide, we will setup a development environment and discuss tooling.

The manager is written in Python 3 with the goal of supporting multiple versions of Python (3.9 or newer) available in current Linux distributions.
These compatibility requirements also force us not to rely heavily on modern runtime libraries such as Pydantic.


Reproducible development environment
====================================

Because we want to support multiple versions of Python with one codebase,
we develop against the oldest supported version and then check in our CI that it works for newer versions of Python.
In your distro, there may be a Python runtime of a different version than the one we are targeting.
So we try to isolate everything from the system we are running on.

To start working on the manager, you just need to install Python and create virtualenvironment.
You may optionally use `pyenv <https://github.com/pyenv/pyenv#installation>`_ to install and manage multiple versions of Python without affecting your system.
Alternatively, some Linux distributions ship packages for older Python versions as well.


Running the manager from source for the first time
==================================================

1. Clone the Knot Resolver `GitLab repository <https://gitlab.nic.cz/knot/knot-resolver>`_.
2. Use ``apkg build-dep`` as described in the :ref:`kresd-dep` section to automatically install development dependencies for the Knot Resolver daemon.
3. Create virtual environment for your choosen Python version: ``python3 -m venv .venv``.

   As mentioned above it is possible to use ``pyenv`` to manage other Python versions.
   Then virtualenv needs to be told where to look for that version of Python, e.g.:

   .. code-block:: bash

      $ ~/.pyenv/versions/3.9.25/bin/python3.9 -m venv .venv

4. Activate virtualenvironment: ``source .venv/bin/activate``
5. Upgrade ``pip`` to the latest version: ``pip install --upgrade pip``
6. Install all development dependencies: ``pip install -e ".[watchdog,prometheus]" --group all``
   All dependencies can be seen in ``pyproject.toml``.
7. Use ``./poe configure`` to set up the build directory of the Knot Resolver daemon (``kresd``).
   This command optionally takes the same arguments as ``meson configure``, but may just as well be run with none to get some sane defaults.
8. Use ``./poe run`` to run the manager in development mode (Ctrl+C to exit).
   The manager is started with the configuration located in ``manager/etc/knot-resolver/config.dev.yaml``.


Advanced workspace directory setup
==================================

It may get annoying to have to juggle changes to the ``config.dev.yaml`` file in Git while using the setup described above.
For this reason, we also allow specifying some paths via environment variables so that you can use a specialized separate workspace directory for development and testing:

* ``KRES_MANAGER_RUNTIME`` specifies the working directory containing the cache, unix sockets and more.
  Since these files are mostly temporary, but relatively frequently written into, it is best to keep them in a ``tmpfs`` filesystem, like ``/dev/shm`` or ``/tmp``.
* ``KRES_MANAGER_CONFIG`` specifies the path to a ``config.yaml`` to be used by the manager.

You may create a separate workspace directory containing a custom run script,
which may look something like this, to make your life easier:

.. code-block:: bash

   #!/usr/bin/env bash
   script_dir="$(dirname $(realpath $BASH_SOURCE[0]))"
   shm_dir="/dev/shm/kresd6"

   mkdir -p "$shm_dir"
   export KRES_MANAGER_RUNTIME="$shm_dir"
   export KRES_MANAGER_CONFIG="$script_dir/config.yaml"
   exec $path_to_knot_resolver/poe "$@"


Commands
========

In the previous section, you saw the use of the ``./poe`` command.
`PoeThePoet <https://github.com/nat-n/poethepoet>`_ is a task runner which we use to simplify invoking common commands.

You can run it by invoking ``./poe``, or you can install it system-wide via ``pip install poethepoet`` and invoke it just by calling ``poe`` (without the leading ``./``).
When invoked globally, you don't have to worry about virtual environments and such, PoeThePoet figures that out for you and commands always run in the appropriate virtual environment.

Or, you can create a symlink to the ``./poe`` script without installing PoeThePoet, e.g. ``ln -s path_to_the_repository/manager/poe /usr/bin/poe``.

To list all the available commands, you can run ``poe help``.
The commands are defined in the ``pyproject.toml`` file of the ``tool.poe.tasks
`` section.

With this environment, **everything else should just work**.
You can run the same checks that CI runs, all the commands listed below should pass.
If something fails and you have done all the steps above, please [open a new issue](https://gitlab.nic.cz/knot/knot-resolver-manager/-/issues/new).


Contributing
============

Before committing, please ensure that ``poe check-files``, ``poe check-code`` and ``poe test-unit`` pass.
Those commands are both run on the CI and if they don't pass, CI fails.


Minimal development environment
===============================

The only global tools that are strictly required are ``Python`` and ``pip`` (or other way to install PyPI packages).
You can have a look at the ``pyproject.toml`` file, manually install all other dependencies that you need and be done with that.
All ``poe`` commands can be run manually too, see their definition in ``pyproject.toml``.
We can't however guarantee, that there won't be any errors.

Please note that Python's development files are also required, since the manager also includes a C module that interacts with it. I.e.,
for distros that package development files separately, you will typically need to install ``-dev`` or ``-devel`` packages of your current Python version as well.


Packaging
=========

Packaging is handled by `apkg <https://apkg.readthedocs.io/en/latest/>`_ cooperating with Setuptools.
To allow for backwards compatibility with Python tooling not supporting `PEP-517 <https://peps.python.org/pep-0517/>`_,
we generate ``setup.py`` file with the command ``poe gen-setuppy``.


Testing
=======

The manager has two suits of tests - unit tests and packaging tests, all residing in the ``manager/tests/`` directory.
The units tests are run by `pytest <https://docs.pytest.org/>`_, while the packaging tests are distro specific and are using `apkg test <https://apkg.readthedocs.io/en/latest/commands/#test>`_.


Code editor
===========

Feel free to use any text editor you like.
However, we recommend using `Visual Studio Code <https://code.visualstudio.com/>`_ with `Pylance <https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance>`_ extension.
That's what we use to work on the manager and we know that it works really well for us.
Just make sure to configure the extension so that it uses virtual environment.


FAQ
===

What all those dev dependencies for?
------------------------------------

Short answer - mainly for managing other dependencies. By using dependency management systems within the project, anyone can start developing after installing just a few core tools. Everything else will be handled automagically. The main concept behind it is that there should be nothing that can be run only in CI.

Core dependencies which you have to install manually:

- **pyenv**: A tools which allows you to install any version of Python regardless of your system's default.
  The version used by default in the project is configured in the file `.python-version`.

  We should be all developing on the same version, because otherwise we might not be able to reproduce each others bug's.

  Written in pure shell, no dependencies on Python.
  Should therefore work on any Unix-like system.

- **PoeThePoet**: A task management system, or in other words glorified switch statement calling other tools.
  Used for simplifying interactions with the project.

- ``pytest``, ``pytest-cov``: unit testing
- ``ruff``: linting and formatting
- ``mypy``: type checking
