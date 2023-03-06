******
Manual
******

The Knot Resolver can be started with the command ``knot-resolver``. You can provide an optional argument ``--config path/to/config.yml`` to load a different than default configuration file.

The resolver does not have any external runtime dependencies and it should be able to run in most environments. The resolver does not interact with cgroups or namespaces and you can run it multiple times as long as you use a different runtime directory in the configuration.