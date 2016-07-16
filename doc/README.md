## Documentation

Each directory contains a README.md with the basic information, examples and usage.
It does not however contain API documentation, which is built separately in this directory.

### Requirements

The code is documented with [Doxygen][doxygen] JavaDoc style, a prettified documentation
also requires [breathe][breathe] and [Sphinx][sphinx] for building sane documentation pages.
It is not however required.

[doxygen]:https://www.stack.nl/~dimitri/doxygen/manual/index.html
[breathe]: https://github.com/michaeljones/breathe
[sphinx]: http://sphinx-doc.org/

You can get the extra dependencies with pip:

```sh
pip install -U Sphinx breathe
# Alternatively
pip -r doc/requirements.txt
```

### Building documentation

If you satisfy the requirements, it's as easy as `make doc`, which builds the documentation in this folder.

