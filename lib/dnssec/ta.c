/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>

#include <contrib/ucw/mempool.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/internal/base64.h>
#include <libknot/rdataset.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rdname.h>

#include "lib/defines.h"
#include "lib/dnssec/ta.h"

static int dname_parse(knot_dname_t **dname, const char *dname_str, mm_ctx_t *pool)
{
	if (!dname) {
		return kr_error(EINVAL);
	}

	knot_dname_t *owner = mm_alloc(pool, KNOT_DNAME_MAXLEN);
	if (owner == NULL) {
		return kr_error(ENOMEM);
	}
	knot_dname_t *aux = knot_dname_from_str(owner, dname_str, KNOT_DNAME_MAXLEN);
	if (aux == NULL) {
		mm_free(pool, owner);
		return kr_error(ENOMEM);
	}

	assert(!*dname);
	*dname = owner;
	return 0;
}

static int uint_parse(const char *str, unsigned *u)
{
	char *err_pos;
	long num = strtol(str, &err_pos, 10);
	if ((*err_pos != '\0') || (num < 0)) {
		return kr_error(EINVAL);
	}
	*u = (unsigned) num;
	return 0;
}

static int strcicmp(char const *a, char const *b)
{
	if (!a && !b) {
		return 0;
	}
	if (!a) {
		return -1;
	}
	if (!b) {
		return 1;
	}
	for ( ; ; ++a, ++b) {
		int d = tolower(*a) - tolower(*b);
		if ((d != 0) || (*a == '\0')) {
			return d;
		}
	}
}

static int algorithm_parse(const char *str, unsigned *u)
{
	int ret = uint_parse(str, u);
	if (ret == 0) {
		return 0;
	}

	const lookup_table_t *item = knot_dnssec_alg_names;
	while (item->id) {
		if (strcicmp(str, item->name) == 0) {
			break;
		}
		++item;
	}

	if (!item->id) {
		return kr_error(ENOENT);
	}

	*u = (unsigned) item->id;
	return 0;
}

static int hex2value(const char hex)
{
	if ((hex >= '0') && (hex <= '9')) {
		return hex - '0';
	} else if ((hex >= 'a') && (hex <= 'f')) {
		return hex - 'a' + 10;
	} else if ((hex >= 'A') && (hex <= 'F')) {
		return hex - 'A' + 10;
	} else {
		return -1;
	}
}

static int hex2byte(const char hex[2], uint8_t *u)
{
	int d0, d1;
	d0 = hex2value(hex[0]);
	d1 = hex2value(hex[1]);

	if ((d0 == -1) || (d1 == -1)) {
		return kr_error(EINVAL);
	}

	*u = ((d0 & 0x0f) << 4) | (d1 & 0x0f);
	return 0;
}

static int ta_ds_parse(uint8_t *rd, size_t *rd_written, size_t rd_maxsize, const char *seps, char **saveptr)
{
	if (!rd || !rd_written || !seps || !saveptr) {
		return kr_error(EINVAL);
	}

	int ret = 0;
	const char *token;
	unsigned aux;

	/* Key tag. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint16_t key_tag = aux;

	/* Algorithm. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = algorithm_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t algorithm = aux;

	/* Digest type. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t digest_type = aux;

	size_t rd_pos = 0;
	if (rd_maxsize >= 4) {
		* (uint16_t *) (rd + rd_pos) = htons(key_tag); rd_pos += 2;
		*(rd + rd_pos++) = algorithm;
		*(rd + rd_pos++) = digest_type;
	} else {
		return kr_error(EINVAL);
	}

	char hexbuf[2];
	int i = 0;
	while ((token = strtok_r(NULL, seps, saveptr)) != NULL) {
		for (int j = 0; j < strlen(token); ++j) {
			hexbuf[i++] = token[j];
			if (i == 2) {
				uint8_t byte;
				ret = hex2byte(hexbuf, &byte);
				if (ret != 0) {
					return ret;
				}
				i = 0;

				if (rd_pos < rd_maxsize) {
					*(rd + rd_pos++) = byte;
				} else {
					return kr_error(ENOMEM);
				}
			}
		}
	}

	if (i != 0) {
		return kr_error(EINVAL);
	}

	*rd_written = rd_pos;
	return 0;
}

static int base2bytes(const uint8_t base[4], uint8_t bytes[3], unsigned *valid)
{
	int32_t decoded = base64_decode(base, 4, bytes, 3);
	if (decoded < 0) {
		return kr_error(EINVAL);
	}
	*valid = decoded;
	return 0;
}

static int ta_dnskey_parse(uint8_t *rd, size_t *rd_written, size_t rd_maxsize, const char *seps, char **saveptr)
{
	fprintf(stderr, "%s()\n", __func__);

	if (!rd || !rd_written || !seps || !saveptr) {
		return kr_error(EINVAL);
	}

	int ret = 0;
	const char *token;
	unsigned aux;

	/* Flags. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint16_t flags = aux;

	/* Protocol. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t protocol = aux;
	if (protocol != 3) {
		return kr_error(EINVAL);
	}

	/* Algorithm. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = algorithm_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t algorithm = aux;

	size_t rd_pos = 0;
	if (rd_maxsize >= 4) {
		* (uint16_t *) (rd + rd_pos) = htons(flags); rd_pos += 2;
		*(rd + rd_pos++) = protocol;
		*(rd + rd_pos++) = algorithm;
	} else {
		return kr_error(EINVAL);
	}

	uint8_t basebuf[4];
	uint8_t databuf[3];
	int i = 0;
	while ((token = strtok_r(NULL, seps, saveptr)) != NULL) {
		for (int j = 0; j < strlen(token); ++j) {
			basebuf[i++] = token[j];
			if (i == 4) {
				unsigned written;
				ret = base2bytes(basebuf, databuf, &written);
				if (ret != 0) {
					return ret;
				}
				i = 0;

				if ((rd_pos + written) < rd_maxsize) {
					memcpy(rd + rd_pos, databuf, written);
					rd_pos += written;
				} else {
					return kr_error(ENOMEM);
				}
			}
		}
	}

	if (i != 0) {
		return kr_error(EINVAL);
	}

	*rd_written = rd_pos;
	return 0;
}

int kr_ta_parse(knot_rrset_t **rr, const char *ds_str, mm_ctx_t *pool)
{
#define SEPARATORS " \t\n\r"
#define RDATA_MAXSIZE 640
	int ret = 0;

	if (!rr || !ds_str || !pool) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	char *ds_cpy = NULL;
	knot_dname_t *owner = NULL;
	knot_rdata_t *rdata = NULL;
	knot_rrset_t *ds_set = NULL;

	size_t ds_len = strlen(ds_str) + 1;
	ds_cpy = mm_alloc(pool, ds_len);
	if (!ds_cpy) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	memcpy(ds_cpy, ds_str, ds_len);
	char *saveptr = NULL, *token;

	/* Owner name. */
	token = strtok_r(ds_cpy, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = dname_parse(&owner, token, pool);
	if (ret != 0) {
		goto fail;
	}

	/* Class. */
	uint16_t class;
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = knot_rrclass_from_string(token, &class);
	if (ret != 0) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	/* Type. */
	uint16_t type;
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = knot_rrtype_from_string(token, &type);
	if ((ret != 0) ||
	    ((type != KNOT_RRTYPE_DS) && (type != KNOT_RRTYPE_DNSKEY))) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	/* Construct RDATA. */
	rdata = mm_alloc(pool, RDATA_MAXSIZE);
	if (!rdata) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	size_t rd_written = 0;

	switch (type) {
	case KNOT_RRTYPE_DS:
		ret = ta_ds_parse(rdata, &rd_written, RDATA_MAXSIZE, SEPARATORS, &saveptr);
		break;
	case KNOT_RRTYPE_DNSKEY:
		ret = ta_dnskey_parse(rdata, &rd_written, RDATA_MAXSIZE, SEPARATORS, &saveptr);
		break;
	default:
		assert(0);
		ret = kr_error(EINVAL);
		break;
	}
	if (ret != 0) {
		goto fail;
	}

	ds_set = knot_rrset_new(owner, type, class, pool);
	if (!ds_set) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	ret = knot_rrset_add_rdata(ds_set, rdata, rd_written, 0, pool);
	if (ret != 0) {
		goto fail;
	}

	*rr = ds_set;
	ds_set = NULL;

#ifdef WITH_DEBUG
//	char buff[1024];
//	knot_rrset_txt_dump(*rr, buff, 1024, &KNOT_DUMP_STYLE_DEFAULT);
//	fprintf(stderr, "%s() '%s'\n", __func__, buff);
#endif

fail:
	knot_rrset_free(&ds_set, pool);
	mm_free(pool, rdata);
	knot_dname_free(&owner, pool);
	mm_free(pool, ds_cpy);
	return ret;
#undef RDATA_MAXSIZE
#undef SEPARATORS
}

#define MAX_ANCHORS 16
struct trust_anchors_nolock {
	mm_ctx_t pool;
	knot_rrset_t *anchors[MAX_ANCHORS];
	int used;
};

struct trust_anchors {
	struct trust_anchors_nolock locked;
	pthread_rwlock_t rwlock;
};

struct trust_anchors global_trust_anchors = {
	.locked.pool = {0, },
	.locked.anchors = {0, },
	.locked.used = 0,
};

static int ta_init(struct trust_anchors_nolock *tan)
{
	assert(tan);

	memset(tan, 0, sizeof(*tan));
	tan->pool.ctx = mp_new(4 * CPU_PAGE_SIZE);
	tan->pool.alloc = (mm_alloc_t) mp_alloc;
	tan->used = 0;

	return kr_ok();
}

static void ta_deinit(struct trust_anchors_nolock *tan)
{
	assert(tan);

	if (tan->pool.ctx) {
		mp_delete(tan->pool.ctx);
		tan->pool.ctx = NULL;
	}
}

int kr_ta_init(struct trust_anchors *tas)
{
	if (!tas) {
		return kr_error(EINVAL);
	}

	int ret = ta_init(&tas->locked);
	if (ret != 0) {
		return ret;
	}

	ret = pthread_rwlock_init(&tas->rwlock, NULL);
	if (ret != 0) {
		ta_deinit(&tas->locked);
		return kr_error(ret);
	}
	return kr_ok();
}

void kr_ta_deinit(struct trust_anchors *tas)
{
	if (!tas) {
		return;
	}

	while (pthread_rwlock_destroy(&tas->rwlock) == EBUSY);

	ta_deinit(&tas->locked);
}

static int ta_reset(struct trust_anchors_nolock *tan, const char *ta_str)
{
	assert(tan);

	ta_deinit(tan);
	int ret = ta_init(tan);
	if (ret != 0) {
		return ret;
	}

	if (!ta_str || (ta_str[0] == '\0')) {
		return kr_ok();
	}

	knot_rrset_t *ta = NULL;
	ret = kr_ta_parse(&ta, ta_str, &tan->pool);
	if (ret != 0) {
		return ret;
	}

	assert(ta);

	tan->anchors[tan->used++] = ta;

	return kr_ok();
}

int kr_ta_reset(struct trust_anchors *tas, const char *ta_str)
{
	if (!tas) {
		return kr_error(ENOENT);
	}

	int ret = pthread_rwlock_wrlock(&tas->rwlock);
	if (ret != 0) {
		return kr_error(ret);
	}

	ret = ta_reset(&tas->locked, ta_str);

	pthread_rwlock_unlock(&tas->rwlock);
	return ret;
}

static knot_rrset_t *ta_find(struct trust_anchors_nolock *tan, const knot_dname_t *name)
{
	assert(tan && name);

	knot_rrset_t *found = NULL;

	int i;
	for (i = 0; i < tan->used; ++i) {
		if (knot_dname_is_equal(tan->anchors[i]->owner, name)) {
			found = tan->anchors[i];
			break;
		}
	}

	return found;
}

static int ta_add(struct trust_anchors_nolock *tan, const char *ta_str)
{
	assert(tan && ta_str);

	if (tan->used >= MAX_ANCHORS) {
		return kr_error(ENOMEM);
	}

	knot_rrset_t *ta = NULL;
	int ret = kr_ta_parse(&ta, ta_str, &tan->pool);
	if (ret != 0) {
		return ret;
	}
	assert(ta);

	knot_rrset_t *found = ta_find(tan, ta->owner);
	if (!found) {
		tan->anchors[tan->used++] = ta;
		return kr_ok();
	}

	if (found->type != ta->type) {
		knot_rrset_free(&ta, &tan->pool);
		return kr_error(EINVAL);
	}

	ret = knot_rdataset_merge(&found->rrs, &ta->rrs, &tan->pool);
	knot_rrset_free(&ta, &tan->pool);
	if (ret != 0) {
		return ret;
	}

	return kr_ok();
}

int kr_ta_add(struct trust_anchors *tas, const char *ta_str)
{
	if (!tas || !ta_str) {
		return kr_error(EINVAL);
	}

	int ret = pthread_rwlock_wrlock(&tas->rwlock);
	if (ret != 0) {
		return kr_error(ret);
	}

	ret = ta_add(&tas->locked, ta_str);

	pthread_rwlock_unlock(&tas->rwlock);
	return ret;
}

static int ta_get(knot_rrset_t **ta, struct trust_anchors_nolock *tan, const knot_dname_t *name, mm_ctx_t *pool)
{
	assert(ta && tan && name);

	knot_rrset_t *copy = ta_find(tan, name);
	if (!copy) {
		kr_error(ENOENT);
	}

	copy = knot_rrset_copy(copy, pool);
	if (!copy) {
		kr_error(ENOMEM);
	}

	*ta = copy;

	return kr_ok();
}

int kr_ta_get(knot_rrset_t **ta, struct trust_anchors *tas, const knot_dname_t *name, mm_ctx_t *pool)
{
	if (!ta || !tas || !name) {
		return kr_error(EINVAL);
	}

	int ret = pthread_rwlock_rdlock(&tas->rwlock);
	if (ret != 0) {
		return kr_error(ret);
	}

	ret = ta_get(ta, &tas->locked, name, pool);

	pthread_rwlock_unlock(&tas->rwlock);
	return ret;
}

int kr_ta_rdlock(struct trust_anchors *tas)
{
	if (!tas) {
		return kr_error(EINVAL);
	}

	return pthread_rwlock_rdlock(&tas->rwlock);
}

int kr_ta_unlock(struct trust_anchors *tas)
{
	if (!tas) {
		return kr_error(EINVAL);
	}

	return pthread_rwlock_unlock(&tas->rwlock);
}

int kr_ta_rrs_count_nolock(struct trust_anchors *tas)
{
	if (!tas) {
		return kr_error(EINVAL);
	}

	return tas->locked.used;
}

int kr_ta_rrs_at_nolock(const knot_rrset_t **ta, struct trust_anchors *tas, size_t pos)
{
	if (!tas || !ta) {
		return kr_error(EINVAL);
	}

	if (pos >= tas->locked.used) {
		return kr_error(EINVAL);
	}

	*ta = tas->locked.anchors[pos];
	return kr_ok();
}
