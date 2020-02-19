
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <unistd.h>

#include "systemd/sd-bus.h"

//--------------------
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <uv.h>

#include "lib/utils.h"
#include "sdbus_client.h"
#include "watcher.h"

#define DBUS_SD_NAME		"org.freedesktop.systemd1"
#define DBUS_SD_PATH		"/org/freedesktop/systemd1"

#define DBUS_INT_MAN		"org.freedesktop.systemd1.Manager"
#define DBUS_INT_PROP		"org.freedesktop.DBus.Properties"
#define DBUS_INT_UNIT		"org.freedesktop.systemd1.Unit"

#define SERVICE_KRESD		"kresd@%s.service"
#define SERVICE_CACHE_GC	"kres-cache-gc.service"

#define DBUS_PATH_KRESD		"/org/freedesktop/systemd1/unit/kresd_40%s_2eservice"
#define DBUS_PATH_GC		"/org/freedesktop/systemd1/unit/kres_2dcache_2dgc_2eservice"


// static inline const char *strna(const char *s) {
// 		return s ?: "n/a";
// }

static int kresd_watching_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	printf("kresd\n");

	return 0;
}

static int cache_gc_watching_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	int ret = 0;
	sd_bus *bus = the_watcher->sdbus->bus;
	sd_bus_error err = SD_BUS_ERROR_NULL;
    char *msg;
	printf("kres-cache-gc\n");

	ret = sd_bus_get_property_string(
        bus,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1/unit/kres_2dcache_2dgc_2eservice",
        "org.freedesktop.systemd1.Unit",
        "ActiveState",
        &err,
        &msg
    );

	printf("%s\n", msg);

	free(msg);

	return 0;
}

/* kresd@{instance} Unit */
static int kresd_unit_method_call(sd_bus *bus, const char *method, const int inst_num)
{
	char *instance_service;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	asprintf(&instance_service, "kresd@%d.service", inst_num);

	int err = sd_bus_call_method(bus, DBUS_SD_NAME, DBUS_SD_PATH, DBUS_INT_MAN,
	method, &error, &reply, "ss", instance_service, "replace");
	if (err < 0) {
		kr_log_error(
			"[sdbus] failed to issue method call '%s' %s: %s\n",
			method, instance_service, error.message);
		goto cleanup;
	}

	kr_log_info("[sdbus] %s %s\n", method, instance_service);

	cleanup:
	free(instance_service);
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return err;
}

/* cache-gc Unit */
static int cache_gc_unit_method_call(sd_bus *bus, const char *method)
{
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	int err = sd_bus_call_method(bus, DBUS_SD_NAME, DBUS_SD_PATH, DBUS_INT_MAN,
	method, &error, &reply, "ss", SERVICE_CACHE_GC, "replace");
	if (err < 0) {
		kr_log_error(
			"[sdbus] failed to issue method call '%s' %s: %s\n",
			method, SERVICE_CACHE_GC, error.message);
		goto cleanup;
	}

	kr_log_info("[sdbus] %s %s\n", method, SERVICE_CACHE_GC);

	cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);
	return err;
}

int kresd_ctl(sd_bus *bus, const char *method, const char *instance)
{
	int ret = 0;
	char *instance_service;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	asprintf(&instance_service, SERVICE_KRESD, instance);

	ret = sd_bus_call_method(bus, DBUS_SD_NAME, DBUS_SD_PATH, DBUS_INT_MAN,
	method, &error, &reply, "ss", instance_service, "replace");
	if (ret < 0) {
		kr_log_error(
			"[sdbus] failed to issue method call '%s' %s: %s\n",
			method, instance_service, error.message);
		goto cleanup;
	}

	kr_log_info("[sdbus] %s %s\n", method, instance_service);

	cleanup:
	free(instance_service);
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return ret;
}

int cache_gc_ctl(sd_bus *bus, const char *method)
{
	int ret = 0;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	int err = sd_bus_call_method(bus, DBUS_SD_NAME, DBUS_SD_PATH, DBUS_INT_MAN,
	method, &error, &reply, "ss", SERVICE_CACHE_GC, "replace");
	if (err < 0) {
		kr_log_error(
			"[sdbus] failed to issue method call '%s' %s: %s\n",
			method, SERVICE_CACHE_GC, error.message);
		goto cleanup;
	}

	kr_log_info("[sdbus] %s %s\n", method, SERVICE_CACHE_GC);

	cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return ret;
}

int watch_kresd(sd_bus *bus, sd_bus_slot **slot, const char *instance)
{
	int ret = 0;
	char *instance_path;
	asprintf(&instance_path, DBUS_PATH_KRESD, instance);

	ret = sd_bus_match_signal(bus, slot, DBUS_SD_NAME, instance_path,
	DBUS_INT_PROP, "PropertiesChanged", kresd_watching_cb, NULL);

	free(instance_path);
	return ret;
}

int watch_cache_gc(sd_bus *bus, sd_bus_slot **slot)
{
	int ret = 0;
	ret = sd_bus_match_signal(bus, slot, DBUS_SD_NAME, DBUS_PATH_GC,
		DBUS_INT_PROP, "PropertiesChanged", cache_gc_watching_cb, NULL);

	return ret;
}

/*----------------------------------------------------------------------------*/

static void sdbus_finish_closing(uv_handle_t *handle)
{
	sdbus_uv_ctx_t *sdbus = handle->data;
	assert(sdbus);
	free(sdbus);
}

static void sdbus_ctx_free(sdbus_uv_ctx_t *bus_ctx)
{
	assert(bus_ctx);
	sd_bus_unref(bus_ctx->bus);
	uv_close((uv_handle_t *)&bus_ctx->uv_handle, sdbus_finish_closing);
}

static void sdbus_cb_tramp(uv_poll_t *handle, int status, int events)
{
	sdbus_uv_ctx_t *sdbus = handle->data;
	sdbus->callback(sdbus, status);
}

static void sdbus_prop_change_cb(sdbus_uv_ctx_t *sdbus_ctx, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
	sd_bus_wait(sdbus_ctx->bus, UINT64_MAX);
	sd_bus_process(sdbus_ctx->bus,NULL);
}

sdbus_uv_ctx_t *sdbus_watcher_create(uv_loop_t *loop)
{
	int ret = 0;
	sd_bus *bus;

	ret = sd_bus_default_system(&bus);
	if (ret < 0){
		kr_log_error(
			"[sysrepo] failed to initialize sdbus:  %s\n",
			strerror(errno));
		return NULL;
	}

	for(int i=0; i < config.kresd_instances_num; i++){

		char *instance;
		sd_bus_slot *kresd_slot;

		asprintf(&instance, "%d", i);

		ret = kresd_unit_method_call(bus, UNIT_START, i);
		ret = watch_kresd(bus, &kresd_slot, instance);

		free(instance);
	}

	if (config.cache_gc.auto_start){
		/* listening for cache garbage collector properties changes */
		sd_bus_slot *gc_slot;

		ret = cache_gc_unit_method_call(bus, UNIT_START);
		ret = watch_cache_gc(bus, &gc_slot);

		config.cache_gc.slot = gc_slot;
	}

	/* create new context */
	struct sdbus_uv_ctx *sdbus_ctx = malloc(sizeof(struct sdbus_uv_ctx));
	sdbus_ctx->bus = bus;
	sdbus_ctx->callback = sdbus_prop_change_cb;

	int fd;
	fd = sd_bus_get_fd(bus);
	if (fd < 0) {
		kr_log_error("[sdbus] failed to get sd-bus fd:  %s\n", strerror(errno));
		free(sdbus_ctx);
		return NULL;
	}

	ret = sd_bus_get_events(bus);

	ret = uv_poll_init(loop, &sdbus_ctx->uv_handle, fd);
	if (ret) {
		kr_log_error("[libuv] failed to initialize uv_poll:  %s\n", uv_strerror(ret));
		free(sdbus_ctx);
		return NULL;
	}
	sdbus_ctx->uv_handle.data = sdbus_ctx;
	ret = uv_poll_start(&sdbus_ctx->uv_handle, UV_READABLE, sdbus_cb_tramp);
	if (ret) {
		kr_log_error("[libuv] failed to start uv_poll:  %s\n", uv_strerror(ret));
		sdbus_ctx_free(sdbus_ctx);
		return NULL;
	}
	return sdbus_ctx;
}

int sdbus_watcher_init(uv_loop_t *loop)
{
	sdbus_watcher_deinit(the_watcher->sdbus);

	sdbus_uv_ctx_t *sdbus_ctx  = sdbus_watcher_create(loop);
	the_watcher->sdbus = sdbus_ctx;
	if (the_watcher->tst_secret == NULL) {
		kr_log_error("[sdbus] failed to create sd-bus watcher context");
		return 1;
	}

	return 0;
}

void sdbus_watcher_deinit(sdbus_uv_ctx_t *bus_ctx)
{
	if (bus_ctx == NULL) {
		return;
	}
	sdbus_ctx_free(bus_ctx);
}
