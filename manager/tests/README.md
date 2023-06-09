# Testing infrastructure

## Unit tests

The unit tests use `pytest` and can be invoked by the command `poe test`. They reside in the `unit` subdirectory. They can be run from freshly cloned repository and they should suceed.

## Integration tests

The integration tests spawn a full manager with `kresd` instances (which it expects to be installed). The tests are implemented by a custom script and they can be invoked by `poe integration` command.