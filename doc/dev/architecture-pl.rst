*************
policy-loader
*************

The ``policy-loader`` is a new special kresd instance ensuring that configured policies are loaded into the rules database where they are made available to all running kresd workers. 
If the policies are loaded successfully, the ``policy-loader`` exits automatically, otherwise it exits with an error code that is detected by Supervisor.


The ``policy-loader`` is only triggered when there are the policies relevant configuration changes, or when the resolver is cold started.
This eliminates the need to restart all running kresd workers if only the policies have changed.
The running kresd workers are only notified of changes in the rules database by their control socket using the ``kr_rules_reset()`` function.
The policies are all configuration options located under the ``views``, ``local-data`` and ``forward`` sections.


The kresd workers are only fully restarted when a relevant configuration change is made to them (everything else outside the policies), or when the resolver is cold started.
The same as for the kresd workers applies to the kresd canary process, which is always run before the kresd workers to validate the new configuration.
The manager always waits for the ``policy-loader`` to finish before working with other processes.


The resolver's cold start
-------------------------

First, the ``policy-loader`` is started and the manager waits for the policies to finish loading into the rules database.
Then the kresd canary process is started to validate the configuration, and then all the kresd workers are started.
The resolver will not start if any of the operations fail.
