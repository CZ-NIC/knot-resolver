********
cache-gc
********

The garbage collector is a simple component that keeps the shared cache from filling up.
Every second it estimates the cache usage and if it is over 80%, it deletes records to free up 10%.
These parameters are configurable.

The freeing happens in a few passes. First all items are classified by their estimated usefulness, in a simple way based on remaining TTL, type, etc.
From this histogram, it's calculated which "level of usefulness" will become the threshold, so that roughly the planned total size will be freed.
Then all items are passed to collect the set of keys to be deleted, and finally the deletion is performed.
Since longer transactions can cause problems in the LMDB cache, all passes are split into short batches.
