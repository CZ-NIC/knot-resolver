#pragma once

#include <systemd/sd-bus.h>


/** Enumeration of operations, that can be used to control units(services). */
typedef enum method_e {
	UNIT_START,     /** Start unit(service). */
	UNIT_STOP,      /** Stop unit(service). */
	UNIT_RESTART,   /** Restart unit(service). */
	UNIT_RELOAD     /** Reload unit(service). */
} method_t;

/** Cleans all unclosed DBus connections. */
void dbus_clean(void);

/** Get status of specific kresd instance. */
int kresd_status(const char *instance, char **status);

/** Get status of cache garbage collector. */
int cache_gc_status(char **status);

/** Control specific kresd instance. */
int kresd_control(method_t method, const char *instance);

/** Control cache garbage collector. */
int cache_gc_control(method_t method);
