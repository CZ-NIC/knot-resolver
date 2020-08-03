#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>

#include "contrib/ccan/asprintf/asprintf.h"
#include "dbus_control.h"

#define DBUS_NAME_SYSTEMD   "org.freedesktop.systemd1"
/* DBus services paths. */
#define DBUS_PATH_SYSTEMD   "/org/freedesktop/systemd1"
#define DBUS_PATH_KRESD     DBUS_PATH_SYSTEMD"/unit/kresd_40%s_2eservice"
#define DBUS_PATH_GC        DBUS_PATH_SYSTEMD"/unit/kres_2dcache_2dgc_2eservice"
/* DBus interfaces. */
#define DBUS_INTF_BASE      "org.freedesktop"
#define DBUS_INTR_MAN       DBUS_INTF_BASE".systemd1.Manager"
#define DBUS_INTR_PROP      DBUS_INTF_BASE".DBus.Properties"
#define DBUS_INTR_UNIT      DBUS_INTF_BASE".systemd1.Unit"
/* Services names. */
#define SERVICE_KRESD       "kresd@%s.service"
#define SERVICE_CACHE_GC    "kres-cache-gc.service"


/* Convert method_t(enum) to string. */
static const char *strmethod(method_t method)
{
	static const char *method_string[] = {
		"StartUnit",
		"StopUnit",
		"RestartUnit",
		"ReloadUnit"
	};
	return method_string[method];
}

void dbus_clean(void)
{
	sd_bus* bus = NULL;
	sd_bus_default_system(&bus);
	sd_bus_flush(bus);
	sd_bus_close(bus);
}

int kresd_status(const char *instance, char **status)
{
	sd_bus* bus = NULL;
	void* userdata = NULL;
	char *instance_service;
	sd_bus_error err = SD_BUS_ERROR_NULL;

	int ret = sd_bus_default_system(&bus);

	asprintf(&instance_service, DBUS_PATH_KRESD, instance);

	ret = sd_bus_get_property_string(
		bus,
		DBUS_NAME_SYSTEMD,
		instance_service,
		DBUS_INTR_UNIT,
		"ActiveState",
		&err,
		status
	);
	free(instance_service);

	return ret;
}

int cache_gc_status(char **status)
{
	sd_bus* bus = NULL;
	void* userdata = NULL;
	sd_bus_error err = SD_BUS_ERROR_NULL;

	int ret = sd_bus_default_system(&bus);

	ret = sd_bus_get_property_string(
		bus,
		DBUS_NAME_SYSTEMD,
		DBUS_PATH_GC,
		DBUS_INTR_UNIT,
		"ActiveState",
		&err,
		status
	);
	return ret;
}

int kresd_control(method_t method, const char *instance)
{
	sd_bus* bus = NULL;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	char *instance_service;
	const char *unit_method = strmethod(method);
	asprintf(&instance_service, SERVICE_KRESD, instance);

	int ret = sd_bus_default_system(&bus);

	ret = sd_bus_call_method(
		bus,
		DBUS_NAME_SYSTEMD,
		DBUS_PATH_SYSTEMD,
		DBUS_INTR_MAN,
		unit_method,
		&error, &reply,
		"ss",
		instance_service,
		"replace"
	);

	if (ret < 0) {
		printf(
			"[sdbus] failed to issue method call '%s' %s: %s\n",
			strmethod(method), instance_service, error.message);
		goto cleanup;
	}

	printf("[sdbus] %s %s\n", strmethod(method), instance_service);

	cleanup:
	free(instance_service);
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return ret;
}

int cache_gc_control(method_t method)
{
	sd_bus* bus = NULL;
	sd_bus_message *reply = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;

	const char *unit_method = strmethod(method);

	int ret = sd_bus_default_system(&bus);

	ret = sd_bus_call_method(
		bus,
		DBUS_NAME_SYSTEMD,
		DBUS_PATH_SYSTEMD,
		DBUS_INTR_MAN,
		unit_method,
		&error,
		&reply,
		"ss",
		SERVICE_CACHE_GC,
		"replace"
	);

	if (ret < 0) {
		printf(
			"[sdbus] failed to issue method call '%s' %s: %s\n",
			unit_method, SERVICE_CACHE_GC, error.message);
		goto cleanup;
	}

	printf("[sdbus] %s %s\n", unit_method, SERVICE_CACHE_GC);

	cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return ret;
}