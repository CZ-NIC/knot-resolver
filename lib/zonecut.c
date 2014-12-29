#include <libknot/dnssec/random.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/packet/wire.h>

#include "lib/zonecut.h"
#include "lib/utils.h"
#include "lib/rplan.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[z-cut] " fmt, ## __VA_ARGS__)

/* \brief Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	const char *addr;
};

/* Initialize with SBELT name servers. */
#define U8(x) (const uint8_t *)(x)
#define HINT_COUNT 13
static const struct hint_info SBELT[HINT_COUNT] = {
        { U8("\x01""a""\x0c""root-servers""\x03""net"), "198.41.0.4" },
        { U8("\x01""b""\x0c""root-servers""\x03""net"), "192.228.79.201" },
        { U8("\x01""c""\x0c""root-servers""\x03""net"), "192.33.4.12" },
        { U8("\x01""d""\x0c""root-servers""\x03""net"), "199.7.91.13" },
        { U8("\x01""e""\x0c""root-servers""\x03""net"), "192.203.230.10" },
        { U8("\x01""f""\x0c""root-servers""\x03""net"), "192.5.5.241" },
        { U8("\x01""g""\x0c""root-servers""\x03""net"), "192.112.36.4" },
        { U8("\x01""h""\x0c""root-servers""\x03""net"), "128.63.2.53" },
        { U8("\x01""i""\x0c""root-servers""\x03""net"), "192.36.148.17" },
        { U8("\x01""j""\x0c""root-servers""\x03""net"), "192.58.128.30" },
        { U8("\x01""k""\x0c""root-servers""\x03""net"), "193.0.14.129" },
        { U8("\x01""l""\x0c""root-servers""\x03""net"), "199.7.83.42" },
        { U8("\x01""m""\x0c""root-servers""\x03""net"), "202.12.27.33" }
};

/*! \brief Fetch address record for nameserver. */
static int prefetch_ns_addr(struct kr_zonecut *cut, knot_rrset_t *cached_rr, namedb_txn_t *txn, uint32_t timestamp)
{
	/* Fetch nameserver address from cache. */
	cached_rr->type = KNOT_RRTYPE_A;
	if (kr_cache_query(txn, cached_rr, &timestamp) != KNOT_EOK) {
		cached_rr->type = KNOT_RRTYPE_AAAA;
		if (kr_cache_query(txn, cached_rr, &timestamp) != KNOT_EOK) {
			return KNOT_ENOENT;
		}
	}

	return kr_rrset_to_addr(&cut->addr, cached_rr);
}

/*! \brief Fetch best NS for zone cut. */
static int fetch_ns(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp)
{
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)name, KNOT_RRTYPE_NS, KNOT_CLASS_IN);
	int ret = kr_cache_query(txn, &cached_rr, &timestamp);
	if (ret == KNOT_EOK) {
		/* Accept only if has address records cached. */
		kr_set_zone_cut(cut, name, knot_ns_name(&cached_rr.rrs, 0));
		knot_rrset_init(&cached_rr, cut->ns, 0, KNOT_CLASS_IN);
		ret = prefetch_ns_addr(cut, &cached_rr, txn, timestamp);
	}

	return ret;
}

/*! \brief Set zone cut to '.' and choose a random root nameserver from the SBELT. */
static int set_sbelt_zone_cut(struct kr_zonecut *cut)
{
	const unsigned hint_id = knot_random_uint16_t() % HINT_COUNT;
	const struct hint_info *hint = &SBELT[hint_id];

	kr_set_zone_cut(cut, KR_DNAME_ROOT, hint->name);

	/* Prefetch address. */
	return sockaddr_set(&cut->addr, AF_INET, hint->addr, 53);
}

int kr_set_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, const knot_dname_t *ns)
{
	if (cut == NULL || name == NULL) {
		return KNOT_EINVAL;
	}

	/* Set current NS and zone cut. */
	knot_dname_to_wire(cut->name, name, KNOT_DNAME_MAXLEN);
	knot_dname_to_wire(cut->ns, ns, KNOT_DNAME_MAXLEN);

	/* Invalidate address. */
	cut->addr.ss_family = AF_UNSPEC;

	char zonecut_str[KNOT_DNAME_MAXLEN], ns_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(ns_str, cut->ns, sizeof(ns_str));
	knot_dname_to_str(zonecut_str, cut->name, sizeof(zonecut_str));
	DEBUG_MSG("zone cut set '%s' ns '%s'\n", zonecut_str, ns_str);

	return KNOT_EOK;
}

int kr_find_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp)
{
	if (cut == NULL || name == NULL) {
		return KNOT_EINVAL;
	}


	/* No cache, start with SBELT. */
	if (txn == NULL) {
		return set_sbelt_zone_cut(cut);
	}

	/* Start at QNAME. */
	while (true) {
		if (fetch_ns(cut, name, txn, timestamp) == KNOT_EOK) {
			return KNOT_EOK;
		}
		/* Subtract label from QNAME. */
		if (name[0] == '\0') {
			break;
		}
		name = knot_wire_next_label(name, NULL);
	}

	/* Name server not found, start with SBELT. */
	return set_sbelt_zone_cut(cut);
}
