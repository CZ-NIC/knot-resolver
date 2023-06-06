*****************
``kres-cache-gc``
*****************

The garbage collector is a simple component which keeps the shared cache from overfilling.
Every second it estimates cache usage and if over 80%, records get deleted in order to free 10%.  (Parameters can be configured.)

The freeing happens in a few passes.  First all items are classified by their estimated usefulness, in a simple way based on remaining TTL, type, etc.
From this histogram it's computed which "level of usefulness" will become the threshold, so that roughly the planned total size gets freed.
Then all items are passed to collect the set of keys to delete, and finally the deletion is performed.
As longer transactions can cause issues in LMDB, all passes are split into short batches.

