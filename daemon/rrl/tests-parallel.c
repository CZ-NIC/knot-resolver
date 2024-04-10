/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

static void the_tests(void **state);

#include "daemon/rrl/tests.inc.c"

#define THREADS 4

#define BATCH_QUERIES_LOG  3   // threads acquire queries in batches of 8
#define HOSTS_LOG          3   // at most 6 attackers + 2 wildcard addresses for normal users
#define TICK_QUERIES_LOG  13   // at most 1024 queries per host per tick

// Expected range of limits for parallel test.
#define RANGE_INST(Vx, prefix)   INST(Vx, prefix) - 1,   INST(Vx, prefix) + THREADS - 1
#define RANGE_RATEM(Vx, prefix)  RATEM(Vx, prefix) - 1,  RATEM(Vx, prefix)
#define RANGE_UNLIM(queries)     queries,                queries

struct host {
	uint32_t queries_per_tick;
	int addr_family;
	char *addr_format;
	uint32_t min_passed, max_passed;
	_Atomic uint32_t passed;
};

struct stage {
	uint32_t first_tick, last_tick;
	struct host hosts[1 << HOSTS_LOG];
};

struct runnable_data {
	int prime;
	_Atomic uint32_t *queries_acquired, *queries_done;
	struct stage *stages;
};


static void *runnable(void *arg)
{
	struct runnable_data *d = (struct runnable_data *)arg;
	size_t si = 0;

	char addr_str[40];
	struct sockaddr_storage addr;

	uint8_t wire[KNOT_WIRE_MIN_PKTSIZE] = { 0 };
	knot_pkt_t answer = { .wire = wire };
	struct kr_request req = {
		.qsource.addr = (struct sockaddr *) &addr,
		.answer = &answer
	};

	while (true) {
		uint32_t qi1 = atomic_fetch_add(d->queries_acquired, 1 << BATCH_QUERIES_LOG);

		/* increment time if needed; sync on incrementing using spinlock */
		uint32_t tick = qi1 >> TICK_QUERIES_LOG;
		for (size_t i = 1; tick != fakeclock_tick; i++) {
			if ((*d->queries_done >> TICK_QUERIES_LOG) >= tick) {
				fakeclock_tick = tick;
			}
			if (i % (1<<14) == 0) sched_yield();
			__sync_synchronize();
		}

		/* increment stage if needed */
		while (tick > d->stages[si].last_tick) {
			++si;
			if (!d->stages[si].first_tick) return NULL;
		}

		if (tick >= d->stages[si].first_tick) {
			uint32_t qi2 = 0;
			do {
				uint32_t qi = qi1 + qi2;

				/* perform query qi */
				uint32_t hi = qi % (1 << HOSTS_LOG);
				if (!d->stages[si].hosts[hi].queries_per_tick) continue;
				uint32_t hqi = (qi % (1 << TICK_QUERIES_LOG)) >> HOSTS_LOG;  // host query index within tick
				if (hqi >= d->stages[si].hosts[hi].queries_per_tick) continue;
				hqi += (qi >> TICK_QUERIES_LOG) * d->stages[si].hosts[hi].queries_per_tick;  // across ticks
				(void)snprintf(addr_str, sizeof(addr_str), d->stages[si].hosts[hi].addr_format,
				         hqi % 0xff, (hqi >> 8) % 0xff, (hqi >> 16) % 0xff);
				kr_straddr_socket_set((struct sockaddr *)&addr, addr_str, 0);

				if (!kr_rrl_request_begin(&req)) {
					atomic_fetch_add(&d->stages[si].hosts[hi].passed, 1);
				}

			} while ((qi2 = (qi2 + d->prime) % (1 << BATCH_QUERIES_LOG)));
		}
		atomic_fetch_add(d->queries_done, 1 << BATCH_QUERIES_LOG);
	}
}


static void the_tests(void **state)
{
	/* parallel tests */
	struct stage stages[] = {
		/* first tick, last tick, hosts */
		{32, 32, {
			/* queries per tick, family, address, min passed, max passed */
			{1024, AF_INET,  "%d.%d.%d.1",   RANGE_UNLIM (  1024   )},
			{1024, AF_INET,  "3.3.3.3",      RANGE_INST  ( V4,  32 )},
			{ 512, AF_INET,  "4.4.4.4",      RANGE_INST  ( V4,  32 )},
			{1024, AF_INET6, "%x%x:%x00::1", RANGE_UNLIM (  1024   )},
			{1024, AF_INET6, "3333::3333",   RANGE_INST  ( V6, 128 )},
			{ 512, AF_INET6, "4444::4444",   RANGE_INST  ( V6, 128 )}
		}},
		{33, 255, {
			{1024, AF_INET,  "%d.%d.%d.1",   RANGE_UNLIM (  1024   )},
			{1024, AF_INET,  "3.3.3.3",      RANGE_RATEM ( V4,  32 )},
			{ 512, AF_INET,  "4.4.4.4",      RANGE_RATEM ( V4,  32 )},
			{1024, AF_INET6, "%x%x:%x00::1", RANGE_UNLIM (  1024   )},
			{1024, AF_INET6, "3333::3333",   RANGE_RATEM ( V6, 128 )},
			{ 512, AF_INET6, "4444::4444",   RANGE_RATEM ( V6, 128 )},
		}},
		{256, 511, {
			{1024, AF_INET,  "3.3.3.3",      RANGE_RATEM ( V4,  32 )},
			{1024, AF_INET6, "3333::3333",   RANGE_RATEM ( V6, 128 )}
		}},
		{512, 512, {
			{1024, AF_INET,  "%d.%d.%d.1",   RANGE_UNLIM (  1024   )},
			{1024, AF_INET,  "3.3.3.3",      RANGE_RATEM ( V4,  32 )},
			{ 512, AF_INET,  "4.4.4.4",      RANGE_INST  ( V4,  32 )},
			{1024, AF_INET6, "%x%x:%x00::1", RANGE_UNLIM (  1024   )},
			{1024, AF_INET6, "3333::3333",   RANGE_RATEM ( V6, 128 )},
			{ 512, AF_INET6, "4444::4444",   RANGE_INST  ( V6, 128 )}
		}},
		{0}
	};

	pthread_t thr[THREADS];
	struct runnable_data rd[THREADS];
	_Atomic uint32_t queries_acquired = 0, queries_done = 0;
	int primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61};
	assert(sizeof(primes)/sizeof(*primes) >= THREADS);

	for (unsigned i = 0; i < THREADS; ++i) {
		rd[i].queries_acquired = &queries_acquired;
		rd[i].queries_done = &queries_done;
		rd[i].prime = primes[i];
		rd[i].stages = stages;
		pthread_create(thr + i, NULL, &runnable, rd + i);
	}
	for (unsigned i = 0; i < THREADS; ++i) {
		pthread_join(thr[i], NULL);
	}

	unsigned si = 0;
	do {
		struct host * const h = stages[si].hosts;
		uint32_t ticks = stages[si].last_tick - stages[si].first_tick + 1;
		for (size_t i = 0; h[i].queries_per_tick; i++) {
			assert_int_between(h[i].passed, ticks * h[i].min_passed, ticks * h[i].max_passed,
				"parallel stage %d, addr %-25s", si, h[i].addr_format);
		}
	} while (stages[++si].first_tick);
}
