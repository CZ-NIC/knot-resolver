#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <lua.h>
#include <sysrepo.h>

#include "lib/module.h"

KR_EXPORT
int nsid_init(struct kr_module *module) {

	return kr_ok();
}

KR_EXPORT
int nsid_deinit(struct kr_module *module) {

	return kr_ok();
}

KR_MODULE_EXPORT(sysrepo)
