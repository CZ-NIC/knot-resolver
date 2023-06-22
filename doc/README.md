## Documentation

Each directory contains a README.md with the basic information, examples and usage.
It does not however contain API documentation, which is built separately in this directory.

### Requirements

To generate documentation you need to install [meson][meson] and [ninja][ninja].

The code is documented with [Doxygen][doxygen] JavaDoc style, a prettified documentation
also requires [breathe][breathe], [Sphinx][sphinx], [Sphinx tabs][sphinx-tabs] and [Sphinx Read the Docs theme][sphinx_rtd_theme] for building sane documentation pages.

[meson]: https://mesonbuild.com/
[ninja]: https://ninja-build.org/
[doxygen]:https://www.stack.nl/~dimitri/doxygen/manual/index.html
[breathe]: https://github.com/michaeljones/breathe
[sphinx]: http://sphinx-doc.org/
[sphinx-tabs]: https://sphinx-tabs.readthedocs.io/
[sphinx_rtd_theme]: https://sphinx-rtd-theme.readthedocs.io/en/stable/

You can install dependencies with pip:

```sh
pip install -U Sphinx sphinx-tabs sphinx_rtd_theme breathe
# Alternatively
pip install -r doc/requirements.txt
```

### Building documentation

If you satisfy the requirements, the documentation will be generated to `doc/html` directory.
You must be in the root directory of the project.

It may be needed to initialize git submodules `git submodule update --init --recursive`.

```sh
$ meson setup build_dir -Ddoc=enabled
$ ninja -C build_dir doc
```
