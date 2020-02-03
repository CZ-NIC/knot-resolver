#include <sys/sysinfo.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <assert.h>
#include <uv.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "kresconfig.h"
#include "lib/utils.h"
#include "watcher.h"
#include "sysrepo_client.h"
#include "sdbus_client.h"
#include "modules/sysrepo/common/sysrepo_utils.h"

#define STICKET_SECRET_CYCLE 500
#define STICKET_MIN_SIZE 10


/* default Knot Resolver processes configuration */
struct server_conf server_conf = {
	.start_on_boot = false,
	.start_cache_gc = true,
	.kresd_inst = 0
};

struct watcher_ctx the_watcher_value;
struct watcher_ctx *the_watcher = NULL;

int watcher_init(uv_loop_t *loop)
{
	int ret = 0;
	//struct watcher_ctx *watcher = &the_watcher_value;
	the_watcher = &the_watcher_value;
	the_watcher->loop = loop;

	/* sysrepo init */
	ret = sysrepo_client_init(loop);
	/* sdbus init */
	if (!ret) ret = sdbus_client_init(loop);

	/* other watchers here */

	return ret;
}

int watcher_deinit(uv_loop_t *loop)
{
	int ret = 0;
	struct watcher_ctx *watcher = the_watcher;

	sysrepo_client_deinit(loop);
	sdbus_client_deinit(loop);

	return ret;
}

int watcher_run(uv_loop_t *loop)
{
	int ret = 0;
	ret = uv_run(loop, UV_RUN_DEFAULT);

	return ret;
}