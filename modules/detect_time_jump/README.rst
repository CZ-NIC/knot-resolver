.. _mod-detect_time_jump:

Detect discontinuous jumps in the system time
---------------------------------------------

This module detect discontinuous jumps in the system time when resolver
is running. It clears cache when some time jumps occurs. 

Time jumps is ussualy created by NTP time change or by admin intervention.
These change can affect cache records as they store timestamp and TTL in real 
time.

If you want to preserve cache during time travel you should disable
this module by ``modules.unload('detect_time_jump')``.
