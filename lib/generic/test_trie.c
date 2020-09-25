/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/generic/trie.h"
#include "tests/unit/test.h"

static const char *dict[] = {
	"catagmatic", "prevaricator", "statoscope", "workhand", "benzamide",
	"work", "workhands", // have some keys that are prefixes of each other
	"alluvia", "fanciful", "bladish", "Tarsius", "unfast", "appropriative",
	"seraphically", "monkeypod", "deflectometer", "tanglesome", "zodiacal",
	"physiologically", "economizer", "forcepslike", "betrumpet",
	"Danization", "broadthroat", "randir", "usherette", "nephropyosis",
	"hematocyanin", "chrysohermidin", "uncave", "mirksome", "podophyllum",
	"siphonognathous", "indoor", "featheriness", "forwardation",
	"archruler", "soricoid", "Dailamite", "carmoisin", "controllability",
	"unpragmatical", "childless", "transumpt", "productive",
	"thyreotoxicosis", "oversorrow", "disshadow", "osse", "roar",
	"pantomnesia", "talcer", "hydrorrhoea", "Satyridae", "undetesting",
	"smoothbored", "widower", "sivathere", "pendle", "saltation",
	"autopelagic", "campfight", "unexplained", "Macrorhamphosus",
	"absconsa", "counterflory", "interdependent", "triact", "reconcentration",
	"oversharpness", "sarcoenchondroma", "superstimulate", "assessory",
	"pseudepiscopacy", "telescopically", "ventriloque", "politicaster",
	"Caesalpiniaceae", "inopportunity", "Helion", "uncompatible",
	"cephaloclasia", "oversearch", "Mahayanistic", "quarterspace",
	"bacillogenic", "hamartite", "polytheistical", "unescapableness",
	"Pterophorus", "cradlemaking", "Hippoboscidae", "overindustrialize",
	"perishless", "cupidity", "semilichen", "gadge", "detrimental",
	"misencourage", "toparchia", "lurchingly", "apocatastasis"
};
#define KEY_LEN(x) (strlen(x) + 1)
static const int dict_size = sizeof(dict) / sizeof(const char *);

static void test_init(void **state)
{
	trie_t *t = trie_create(NULL);
	assert_non_null(t);
	*state = t;
}

static void test_insert(void **state)
{
	trie_t *t = *state;

	for (int i = 0; i < dict_size; ++i) {
		trie_val_t *data = trie_get_ins(t, dict[i], KEY_LEN(dict[i]));
		assert_non_null(data);
		assert_null(*data);
		*data = (char *)NULL + i; // yes, ugly
		assert_ptr_equal(trie_get_try(t, dict[i], KEY_LEN(dict[i])), data);
	}
	assert_int_equal(trie_weight(t), dict_size);
}

static void test_missing(void **state)
{
	trie_t *t = *state;
	const char *notin = "p";
	assert_null(trie_get_try(t, notin, KEY_LEN(notin)));
}

static int cmpstringp(const void *p1, const void *p2)
{
	return strcmp(* (char * const *) p1, * (char * const *) p2);
}

static void test_iter(void **state)
{
	// prepare sorted dictionary
	char *dict_sorted[dict_size];
	memcpy(dict_sorted, dict, sizeof(dict));
	qsort(dict_sorted, dict_size, sizeof(dict[0]), cmpstringp);

	// iterate and check the order is consistent
	trie_t *t = *state;
	trie_it_t *it = trie_it_begin(t);
	for (int i = 0; i < dict_size; ++i, trie_it_next(it)) {
		assert_false(trie_it_finished(it));
		size_t len;
		const char *key = trie_it_key(it, &len);
		assert_int_equal(KEY_LEN(key), len);
		assert_string_equal(key, dict_sorted[i]);
		assert_ptr_equal(dict[(char *)*trie_it_val(it) - (char *)NULL],
				 dict_sorted[i]);
	}
	assert_true(trie_it_finished(it));
	trie_it_free(it);
}

static void test_queue(void **state)
{
	trie_t *t = *state;
	// remove all the elements in ascending order
	for (int i = 0; i < dict_size; ++i) {
		char *key;
		uint32_t len;
		trie_val_t *data = trie_get_first(t, &key, &len);
		assert_non_null(key);
		assert_int_equal(len, KEY_LEN(key));
		assert_non_null(data);
		ptrdiff_t key_i = (char *)*data - (char *)NULL;
		assert_string_equal(key, dict[key_i]);

		len = 30;
		char key_buf[len];
		ptrdiff_t key_i_new;
		int ret = trie_del_first(t, key_buf, &len, (trie_val_t *)&key_i_new);
		assert_int_equal(ret, kr_ok());
		assert_int_equal(KEY_LEN(key_buf), len);
		assert_int_equal(key_i, key_i_new);
		assert_string_equal(dict[key_i], key_buf);
	}
}

static void test_leq_bug(void **state)
{
	/* We use different contents of the trie,
	 * so that the particular bug would've been triggered. */
	trie_t *t = trie_create(NULL);
	char key = 'a';
	trie_get_ins(t, &key, sizeof(key));

	key = (char)0xff;
	trie_val_t *val;
	int ret = trie_get_leq(t, &key, sizeof(key), &val);
	assert_int_equal(ret, 1);
	trie_free(t);
}

static void test_deinit(void **state)
{
	trie_t *t = *state;
	trie_free(t);
	*state = NULL;
}

/* Program entry point */
int main(int argc, char **argv)
{
	const UnitTest tests[] = {
	        group_test_setup(test_init),
	        unit_test(test_insert),
		unit_test(test_leq_bug),
		unit_test(test_missing),
		unit_test(test_iter),
		unit_test(test_queue),
	        group_test_teardown(test_deinit)
	};

	return run_group_tests(tests);
}

