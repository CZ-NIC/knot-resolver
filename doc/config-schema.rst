Configuration schema
====================


The configuration schema describes the structure of accepted configuration files (or objects via the API). While originally specified in Python source code, it can be visualized as a `JSON schema <https://json-schema.org/>_`.

Getting the JSON schema
-----------------------

1. The JSON schema can be obtained from a running Resolver by sending a HTTP GET request to the path ``/schema`` on the management socket (by default a Unix socket at ``/var/run/knot-resolver/manager.sock``).
2. The ``kresctl schema`` command outputs the schema of the currently installed version as well. It does not require a running resolver.
3. JSON schema for the most recent Knot Resolver version can be `downloaded here <_static/config.schema.json>_`.

Validating you configuration
----------------------------

As mentioned above, the JSON schema is NOT used to validate the configuration in the Knot Resolver. It's the other way around, the validation process can generate JSON schema that can help you understand the configuration structure. Some validation steps are however dynamic (for example resolving of interface names) and can not be expressed using JSON schema and cannot be even completed without running full Resolver.

.. note::
    When using the API to change configuration in runtime, your change can be rejected by the validation step even though Knot Resolver would start just fine with the given changed configuration. Some validation steps within the Resolver are dynamic and they are dependent on both your previous configuration and the new one. For example, if you try to change the management socket, the validation will fail even though the new provided address is perfectly valid. Chaning the management socket while running is not supported.

Most of the validation is however static and you can use the ``kresctl validate`` command to check your configuration file for most errors before actually running the Resolver.


Interactive visualization
-------------------------

The following visualization is interactive and offers good overview of the configuration structure. 

.. raw:: html

    <a href="_static/schema_doc.html" target="_blank">Open in a new tab.</a>
    <iframe src="_static/schema_doc.html" width="100%" style="height: 30vh;"></iframe>


Text-based configuration schema description
-------------------------------------------

Following, you can find the JSON schema flattened textual representation. It's not meant to be read top-to-bottom, however it can be used as a quick lookup reference.

.. mdinclude:: config-schema-body.md

