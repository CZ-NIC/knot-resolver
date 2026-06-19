*************
policy-loader
*************

The ``policy-loader`` is a new special kresd instance ensuring that configured policies are loaded into the rules database where they are made available to all running kresd workers. 
If the policies are loaded successfully, the ``policy-loader`` exits automatically, otherwise it exits with an error code that is detected by Supervisor.

The ``policy-loader`` is triggered on every reload or a cold start to recompile the LMDB of rules,
as changes to external files are not tracked (e.g. RPZ or /etc/hosts).
This eliminates the need to restart kresd workers if only the policies have changed.
In that case the running kresd workers are only notified of changes in the rules database by their control socket using the ``kr_rules_reset()`` function.

The kresd workers are only restarted when a relevant configuration change is made.
In particular, options located under the ``views`` and ``local-data`` do not need kresd restarts.
The same as for the kresd workers applies to the kresd canary process, which is always run before the kresd workers to validate the new configuration.
The manager always waits for the ``policy-loader`` to finish before working with other processes.


The resolver's cold start
-------------------------

First, the ``policy-loader`` is started and the manager waits for the policies to finish loading into the rules database.
Then the kresd canary process is started to validate the configuration, and then all the kresd workers are started.
The resolver will not start if any of the operations fail.


Memory usage design
-------------------
Originally the policy-updater was always doing everything as a trivial RW transaction in the ruledb
which first cleared everything and then filled it up.  Though the old data should be unreferenced
immediately after all workers rolled over to the new ones, the LMDB file usually grew
to about 3x of the clear-load size.  Using that much RAM permanently didn't seem great
when used with very large local-data (typically RPZs).

Now if configured with /local-data/tmp-db-dir, we first produce a fresh DB into a separate location
which should be disk-backed, and then remove the old one and move the new DB file on its place.
This should guarantee never going over 2x and almost all time taking only 1x.

One caveat for further improvements is that the transaction is apparently held in-memory
until committed, so we'd have to commit more often - which we could now,
as we're writing into a separate DB.  (We could also use MDB_NOSYNC to hope for saving disk I/O.)

After that we might apply the very likely tiny diff between the DBs
as a transaction into the in-RAM DB, instead of replacing.
