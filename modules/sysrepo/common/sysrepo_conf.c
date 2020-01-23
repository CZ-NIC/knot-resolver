# include "sysrepo_conf.h"

int sysrepo_repo_config()
{
	/*
	This function will probably be called on knot-resolver
	installation or by `kres-watcher` when something
	wents wrong with sysrepo.

	Configures sysrepo:
		1. install/import YANG modules
		2. enable features
		3. import json data to startup datastore
		4. clean up any stale connections of clients that no longer exist
	 */

	return 0;
}