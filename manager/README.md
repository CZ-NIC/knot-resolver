# Knot Resolver Manager

## Development environment

### Reproducible development environment

Because we want to support multiple versions of Python with one codebase, we develop against the oldest supported version and then check in our CI that it works for newer Python versions.

Install these tools:
* [pyenv](https://github.com/pyenv/pyenv#installation)
* [Poetry](https://python-poetry.org/docs/#installation)
* [Yarn](https://yarnpkg.com/) (See FAQ for why do we need JS in Python project) or NPM

The actual development environment can be setup using these commands:

```sh
pyenv install
poetry env use $(pyenv which python)
poetry install
yarn install # or npm install
```

### Common tasks and interactions with the project

After setting up the environment, you should be able to interract with the project by using the `./poe` script. Common actions are:

* `poe run` - runs the manager from the source
* `poe test` - unit tests
* `poe tox` - unit tests in all supported Python versions
* `poe check` - static code analysis
* `poe fixdeps` - update installed dependencies according to the project's configuration
* `poe clean` - cleanup the repository from unwanted files

All possible commands can be listed by running the `poe` command without arguments. The definition of these commands can be found in the `pyproject.toml` file.

If you don't want to be writing the `./` prefix, you can install [PoeThePoet](https://github.com/nat-n/poethepoet) Python package globally and call `poe` directly. I would also recommend setting up its tab completition. Instructions can be found on [their GitHub page](https://github.com/nat-n/poethepoet#enable-tab-completion-for-your-shell).

### Contributing

Before commiting, please ensure that both `poe check` and `poe test` pass.

### Packaging

Not yet properly implemented. Ideal situation would be a command like `poe package` which would create all possible packages.

Temporary solution to build a wheel/sdist - just call `poetry build`. The result will be in the `dist/` directory.

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
  * Yarn or NPM
    * Dependency management systems from JavaScript development.
    * Used for installing pyright - the type checker we use.
* automatically managed dependencies
  * PoeThePoet - A task management system, or in other words glorified switch statement calling other tools. Used for simplifying interractions with the project.
  * pytest, pytest-cov - unit testing
  * pylint, flake8 - linting
  * pyright - type checking, compatible with VSCode using the Pylance extension
  * black - autoformatter (might be removed in the future if not used in practice)
  * tox - testing automation
  * tox-pyenv - plugin for tox that makes use of pyenv provided Python binaries

### Why do we need JavaScript in Python project?

We would like to use a type checker. As of writing this, there are 4 possible options:

* [mypy](http://mypy-lang.org/) - oldest, slowest, reports correct code as broken, no advanced features, written in Python, works
* [pytype](https://github.com/google/pytype) - supports type inference, written in Python, does not work in Python 3.9, Python versions > 3.7 are not yet supported
* [pyre](https://pyre-check.org/) - supports type inference, contains security focused static analysis tool, written in Python, does not work in Python 3.6
* [pyright](https://github.com/Microsoft/pyright) - not that advanced as pyre and pytype, written in TypeScript, faster than mypy, great integration with VSCode, works regardless of current Python version

... and that's how we ended up with JS in a Python project.