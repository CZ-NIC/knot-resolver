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

#define DBUS_NAME			"org.freedesktop.systemd1"
#define DBUS_PATH			"/org/freedesktop/systemd1"
#define DBUS_INTERFACE		"org.freedesktop.systemd1.Manager"

#define SERVICE_KRESD		"kresd@%d.service"
#define SERVICE_CACHE_GC	"kres-cache-gc.service"


/* kresd@{instance} Unit */
static int kresd_unit_method_call(sd_bus *bus, const char *method, const int inst_num)
{
	char *instance_service;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	asprintf(&instance_service, SERVICE_KRESD, inst_num);

	int err = sd_bus_call_method(bus, DBUS_NAME, DBUS_PATH, DBUS_INTERFACE,
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

	int err = sd_bus_call_method(bus, DBUS_NAME, DBUS_PATH, DBUS_INTERFACE,
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

int control_knot_resolver(const char *method)
{
	int ret = 0;
	sd_bus *bus = the_watcher->bus;
	ret = sd_bus_open_system(&bus);

	/* if kresd_inst = 0, get number of configured machine's CPUs */
	if (!server_conf.kresd_inst){
		server_conf.kresd_inst = get_nprocs_conf();
		kr_log_info("[conf] discovered %d CPUs\n", server_conf.kresd_inst);
	}

	for(int i=0; i < server_conf.kresd_inst; i++){
		ret = kresd_unit_method_call(bus, method, i);
	}

	/* if start cache garbage collector is true and  */
	if(server_conf.start_cache_gc){
		ret = cache_gc_unit_method_call(bus, method);
	}
	else {
		kr_log_info(
			"[sdbus] kres-cache-gc.service is not configured to start automaticly");
	}

	sd_bus_unref(bus);

	return ret;
}

int control_cache_gc(const char *method)
{
	int ret = 0;
	sd_bus *bus = the_watcher->bus;
	ret = sd_bus_open_system(&bus);

	ret = cache_gc_unit_method_call(bus, method);

	sd_bus_unref(bus);

	return ret;
}

int sdbus_client_init(uv_loop_t *loop)
{
	int ret = 0;
	sd_bus *bus = NULL;

	/* Connect to the system bus */
	ret = sd_bus_open_system(&bus);
	if (ret < 0) {
		kr_log_error("[sdbus] failed to connect to system bus: %s\n", strerror(-ret));
	}

	if (bus)
		the_watcher->bus = bus;

	return ret;
}

int sdbus_client_deinit(uv_loop_t *loop)
{
	sd_bus *bus = the_watcher->bus;

	sd_bus_unref(bus);

	return 0;
}
