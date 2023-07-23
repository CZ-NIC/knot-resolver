******
Manual
******

The Knot Resolver can be started with the command ``knot-resolver``. You can provide an optional argument ``--config path/to/config.yaml`` to load a different than default configuration file.

The resolver does not have any external runtime dependencies and it should be able to run in most environments. It should be possible to wrap it with any container technology.


Multiple instances on a single server
=====================================

The only limitation for running multiple instances of Knot Resolver is that all instances must have a different runtime directory. There are however safeguards in place that should prevent accidental runtime directory conflicts.

It is possible to share cache between multiple instances, just make sure that all instances have the same cache config and there is only a single garbage collector running (disable it in all but one config file).
