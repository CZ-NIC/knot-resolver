# Knot Resolver Manager

Knot Resolver Manager is a configuration tool for [Knot Resolver](https://gitlab.nic.cz/knot/knot-resolver). The Manager hides the complexity of running several independent resolver processes while ensuring zero-downtime reconfiguration with YAML/JSON declarative configuration and an optional HTTP API for dynamic changes.

## Development environment

### Reproducible development environment

Because we want to support multiple versions of Python with one codebase, we develop against the oldest supported version and then check in our CI that it works for newer Python versions. In your distro, there might be a Python runtime of a different version than what we target. We therefore attempt to isolate everything from the system we are running on.

Install these tools:
* [pyenv](https://github.com/pyenv/pyenv#installation) - a tool for switching between Python versions without affecting the system (can be installed using distro's package manager)
* [Poetry](https://python-poetry.org/docs/#installation) - dependency management (note: do not install the package via pip, follow instructions in Poetry's official documentation)

Be careful, that you need the latest version of Poetry. The setup was tested with Poetry version 1.1.7. Due to it's ability to switch between Python versions, it has to be installed separately to work correctly. Make sure to follow [the latest setup guide](https://python-poetry.org/docs/#installation).

After installing the tools above, the actual fully-featured development environment can be setup using these commands:

```sh
pyenv install 3.6.12
pyenv install 3.7.9
pyenv install 3.8.7
pyenv install 3.9.1
poetry env use $(pyenv which python)
poetry install
```

With this environment, **everything else should just work**. You can run the same checks the CI runs, all commands listed bellow should pass. If something fails and you did all the steps above, please [open a new issue](https://gitlab.nic.cz/knot/knot-resolver-manager/-/issues/new).

### Minimal development environment

The only global tools that are strictly required are `Python` and `pip` (or other way to install PyPI packages). You can have a look at the `pyproject.toml` file, manually install all other dependencies that you need and be done with that. All `poe` commands (see bellow) can be run manually too, see their definition in `pyproject.toml`. We can't however guarantee, that there won't be any errors.

### Common tasks and interactions with the project

After setting up the environment, you should be able to interract with the project by using `./poe` script. Common actions are:

* `poe run` - runs the manager from the source
* `poe docs` - creates HTML documentation
* `poe test` - unit tests
* `poe tox` - unit tests in all supported Python versions (must not be run outside of virtualenv, otherwise it fails to find multiple versions of Python)
* `poe check` - static code analysis
* `poe format` - runs code formater
* `poe fixdeps` - update installed dependencies according to the project's configuration
* `poe clean` - cleanup the repository from unwanted files
* `poe integration` - run the integration tests

All possible commands can be listed by running the `poe` command without arguments. The definition of these commands can be found in the `pyproject.toml` file.

If you don't want to be writing the `./` prefix, you can install [PoeThePoet](https://github.com/nat-n/poethepoet) Python package globally and call `poe` directly. I would also recommend setting up its tab completition. Instructions can be found on [their GitHub page](https://github.com/nat-n/poethepoet#enable-tab-completion-for-your-shell).

### Contributing

Before commiting, please ensure that both `poe check` and `poe test` pass. Those commands are both run on the CI and if they don't pass, CI fails.

### Packaging

This project uses [`apkg`](https://gitlab.nic.cz/packaging/apkg) for packaging. See [`distro/README.md`](distro/README.md) for packaging specific instructions.

## FAQ

### What all those dev dependencies for?

Short answer - mainly for managing other dependencies. By using dependency management systems within the project, anyone can start developing after installing just a few core tools. Everything else will be handled automagically. The main concept behind it is that there should be nothing that can be run only in CI.

* core dependencies which you have to install manually
  * pyenv
    * A tools which allows you to install any version of Python regardless of your system's default. The version used by default in the project is configured in the file `.python-version`.
    * We should be all developing on the same version, because otherwise we might not be able to reproduce each others bug's.
    * Written in pure shell, no dependencies on Python. Should therefore work on any Unix-like system.
  * Poetry
    * A dependency management system for Python libraries. Normally, all libraries in Python are installed system-wide and dependent on system's Python version. By using virtual environments managed by Poetry, configured to use a the correct Python version through pyenv, we can specify versions of the dependencies in any way we like.
    * Follows PEP 518 and uses the `pyproject.toml` file for all of it's configuration.
    * Written in Python, therefore it's problematic if installed system-wide as an ordinary Python package (because it would be unavailable in its own virtual environment).
* automatically managed dependencies
  * PoeThePoet - A task management system, or in other words glorified switch statement calling other tools. Used for simplifying interractions with the project.
  * pytest, pytest-cov - unit testing
  * pylint, flake8 - linting
  * black - autoformatter (might be removed in the future if not used in practice)
  * tox - testing automation
  * tox-pyenv - plugin for tox that makes use of pyenv provided Python binaries

### Why Poetry? Why should I learn a new tool?

This blog post explains it nicely - https://muttdata.ai/blog/2020/08/21/a-poetic-apology.html.
