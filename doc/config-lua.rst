
Advanced configuration (Lua)
============================

Knot Resolver can be configured declaratively by using YAML files or YAML/JSON HTTP API. However, there is another option. The actual worker processes (the ``kresd`` executable) speaks a different configuration language, it internally uses the Lua runtime and the respective programming language.

Essentially, the declarative configuration is only used for validation and as an external interface. After validation, a Lua configuration is generated and passed into individual ``kresd`` instances. You can see the generated configuration files within the Resolver's working directory or you can manually run the conversion of declarative configuration with the ``kresctl convert`` command.

.. warning::
        While there are no plans of ever removing the Lua configuration, we do not guarantee absence of backwards incompatible changes. Starting with Knot Resolver version 6 and later, we consider the Lua interface internal and a subject to change. While we don't have any breaking changes planned for the foreseeable future, they might come.

        **Therefore, use this only when you don't have any other option. And please let us know about it and we might try to accomodate your usecase in the declarative configuration.**

.. toctree::
   :maxdepth: 2
   
   config-lua-overview
   config-network
   config-performance
   config-policy
   config-logging-monitoring
   config-dnssec
   config-experimental