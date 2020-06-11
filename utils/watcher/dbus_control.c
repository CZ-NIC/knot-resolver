
#include "lib/utils.h"
#include "systemd/sd-bus.h"

#include "dbus_control.h"

#define DBUS_SD_NAME		"org.freedesktop.systemd1"
#define DBUS_SD_PATH		"/org/freedesktop/systemd1"

#define DBUS_INT_MAN		"org.freedesktop.systemd1.Manager"
#define DBUS_INT_PROP		"org.freedesktop.DBus.Properties"
#define DBUS_INT_UNIT		"org.freedesktop.systemd1.Unit"

#define SERVICE_KRESD		"kresd@%s.service"
#define SERVICE_CACHE_GC	"kres-cache-gc.service"

#define DBUS_PATH_KRESD		"/org/freedesktop/systemd1/unit/kresd_40%s_2eservice"
#define DBUS_PATH_GC		"/org/freedesktop/systemd1/unit/kres_2dcache_2dgc_2eservice"


int kresd_get_status(const char *instance, char **status)
{
	sd_bus* bus = NULL;
	void* userdata = NULL;
	char *instance_service;
	sd_bus_error err = SD_BUS_ERROR_NULL;

	int ret = sd_bus_default_system(&bus);

	asprintf(&instance_service, SERVICE_KRESD, instance);

	ret = sd_bus_get_property_string(
		bus,
		DBUS_SD_NAME,
		DBUS_PATH_GC,
		DBUS_INT_UNIT,
		"ActiveState",
		&err,
		status
	);
	free(instance_service);
	return ret;
}

int cache_gc_get_status(char **status)
{
	sd_bus* bus = NULL;
	void* userdata = NULL;
	sd_bus_error err = SD_BUS_ERROR_NULL;

	int ret = sd_bus_default_system(&bus);

	ret = sd_bus_get_property_string(
		bus,
		DBUS_SD_NAME,
		DBUS_PATH_GC,
		DBUS_INT_UNIT,
		"ActiveState",
		&err,
		status
	);
	return ret;
}

int kresd_ctl(const char *method, const char *instance)
{
	sd_bus* bus = NULL;
	char *instance_service;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	int ret = sd_bus_default_system(&bus);

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

int cache_gc_ctl(const char *method)
{
	sd_bus* bus = NULL;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	int ret = sd_bus_default_system(&bus);

	ret = sd_bus_call_method(bus, DBUS_SD_NAME, DBUS_SD_PATH, DBUS_INT_MAN,
	method, &error, &reply, "ss", SERVICE_CACHE_GC, "replace");
	if (ret < 0) {
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