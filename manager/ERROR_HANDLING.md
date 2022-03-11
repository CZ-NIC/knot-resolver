# Assumptions

Our main design goal is, that **the manager MUST NOT BE a required component.** Domains must be resolveable even in the absense of the manager. We want this, because of backwards compatibility with the way `kresd` has worked before. But another good reason is that `kresd` has been battle tested and is reasonably reliable. We can't say the same about manager as we do not have practical experiences with it at the time of writing.

This goal leads to usage of external service managers like systemd. Manager is therefore "just" a tool for configuring service managers. If we crash, the `kresd`'s will keep running.

# When can we expect errors

Majority of errors can meaningfully happen only when changing configuration which we do at different lifecycle stages of manager. We are changing configuration of the service managers on manager's startup and shutdown, and when change of configuration is requested (by a signal or HTTP request). Each of these situations can have a different error handling mechanisms to match user's expectations.

Additional to the errors mentioned above, we can sometimes detect, that future configuration changes will fail. Manager has a periodic watchdog monitoring health of the system and detecting failures before they actually happen.

To sum it up, errors can be raised:
* on configuration changes
    * during startup
    * in response to a config change request
    * on shutdown
* proactively from our periodic watchdog


# How should we handle errors

## Errors on startup

**All errors should be fatal.** If something goes wrong, it's better to stop immediately before we make anything worse. Also, if we fail to start, the user will more likely notice.

## Error handling after config change requests

**All errors, that stem from the configuration change, should be reported and the manager should keep running.** Before the actual change though, watchdog should be manually invoked.

## Error handling during shutdown

**All errors should be fatal.** It does not make sense to try to correct any problems at that point.

## Error handling from watchdog

```
error_counter = 0

on error:
    if error_counter > ERROR_COUNTER_THRESHOLD:
        raise a fatal error
    
    error_counter += 1
    try to fix the situation
    if unsucessful, fatal error


every ERROR_COUNTER_DECREASE_INTERVAL:
    if error_counter > 0:
        error_counter -= 1
```

Reasonable constants are probably:
```
ERROR_COUNTER_THRESHOLD = 2
ERROR_COUNTER_DECREASE_INTERVAL = 30min
```
    

