# Knot Resolver Manager

## Development environment

### Reproducible development environment

Because we want to support multiple versions of Python with one codebase, we develop against the oldest supported version and then check in our CI that it works for newer Python versions.

Install these tools:
* [pyenv](https://github.com/pyenv/pyenv#installation)
* [Poetry](https://python-poetry.org/docs/#installation)
* [Yarn](https://yarnpkg.com/) (See FAQ for why do we need JS in Python project)

The actual development environment can be setup using these commands:

```sh
pyenv install
poetry env use $(pyenv which python)
poetry install
yarn install
```

### Common tasks and interactions with the project

After setting up the environment, you should be able to interract with the project by using the `./poe` script. Common actions are:

* `poe run` - runs the manager from the source
* `poe test` - unit tests
* `poe check` - static code analysis
* `poe fixdeps` - update installed dependencies according to the project's configuration

All possible commands can be listed by running the `poe` command without arguments. The definition of these commands can be found in the `pyproject.toml` file.

If you don't want to be writing the `./` prefix, you can install [PoeThePoet](https://github.com/nat-n/poethepoet) Python package globally and call `poe` directly. I would also recommend setting up its tab completition. Instructions can be found on [their GitHub page](https://github.com/nat-n/poethepoet#enable-tab-completion-for-your-shell).

### Contributing

Before commiting, please ensure that both `poe check` and `poe test` pass.

## FAQ
### Why do we need JavaScript in Python project?

We would like to use a type checker. As of writing this, there are 4 possible options:

* [mypy](http://mypy-lang.org/) - oldest, slowest, reports correct code as broken, no advanced features, written in Python, works
* [pytype](https://github.com/google/pytype) - supports type inference, written in Python, does not work in Python 3.9, Python versions > 3.7 are not yet supported
* [pyre](https://pyre-check.org/) - supports type inference, contains security focused static analysis tool, written in Python, does not work in Python 3.6
* [pyright](https://github.com/Microsoft/pyright) - not that advanced as pyre and pytype, written in TypeScript, faster than mypy, great integration with VSCode, works regardless of current Python version

... and that's how we ended up with JS in a Python project.