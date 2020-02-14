/*
 * critbit89 - A crit-bit tree implementation for strings in C89
 * Written by Jonas Gehring <jonas@jgehring.net>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tests/unit/test.h"
#include "lib/generic/set.h"
#include "lib/utils.h"


/*
 * Sample dictionary: 100 random words from /usr/share/dict/words
 * Generated using random.org:
 * MAX=`wc -l < /usr/share/dict/words | tr -d " "`
 * for i in `curl "http://www.random.org/integers/?num=100&min=1&max=$MAX&col=1&base=10&format=plain&rnd=new"`; do
 *   nl /usr/share/dict/words | grep -w $i | tr -d "0-9\t "
 * done
 */
static const char *dict[] = {
	"catagmatic", "prevaricator", "statoscope", "workhand", "benzamide",
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

/* Insertions */
static void test_insert(void **state)
{
	set_t *set = *state;
	int dict_size = sizeof(dict) / sizeof(const char *);
	int i;

	for (i = 0; i < dict_size; i++) {
		assert_int_equal(set_add(set, dict[i]), 0);
	}
}

/* Insertion of duplicate element */
static void test_insert_dup(void **state)
{
	set_t *set = *state;
	int dict_size = sizeof(dict) / sizeof(const char *);
	int i;

	for (i = 0; i < dict_size; i++) {
		if (!set_contains(set, dict[i])) {
			continue;
		}
		assert_int_equal(set_add(set, dict[i]), 1);
	}
}

/* Searching */
static void test_contains(void **state)
{
	set_t *set = *state;
	char *in;
	const char *notin = "not in set";

	in = malloc(strlen(dict[23])+1);
	strcpy(in, dict[23]);

	assert_true(set_contains(set, in));
	assert_false(set_contains(set, notin));
	assert_false(set_contains(set, ""));
	in[strlen(in)/2] = '\0';
	assert_false(set_contains(set, in));

	free(in);
}

/* Count number of items */
static int count_cb(const char *s, void *_, void *n) { (*(int *)n)++; return 0; }
static void test_complete(set_t *set, int n)
{
	int i = 0;
	if (set_walk(set, count_cb, &i) != 0) {
		abort();
	}
	if (i != n) {
		abort();
	}
}
static void test_complete_full(void **state) { test_complete(*state, sizeof(dict) / sizeof(const char *)); }
static void test_complete_zero(void **state) { test_complete(*state, 0); }

/* Deletion */
static void test_delete(void **state)
{
	set_t *set = *state;
	assert_int_equal(set_del(set, dict[91]), 0);
	assert_int_equal(set_del(set, "most likely not in set"), 1);
}

/* Complete deletion */
static void test_delete_all(void **state)
{
	set_t *set = *state;
	int dict_size = sizeof(dict) / sizeof(const char *);
	int i;

	for (i = 0; i < dict_size; i++) {
		if (!set_contains(set, dict[i])) {
			continue;
		}
		assert_int_equal(set_del(set, dict[i]), 0);
	}
}

/* Fake allocator */
static void *fake_malloc(void *b, size_t s) { return NULL; }
static void test_allocator(void **state)
{
	knot_mm_t fake_pool = { .ctx = NULL, .alloc = fake_malloc, .free = NULL };
	set_t set = set_make(&fake_pool);
	assert_int_equal(set_add(&set, dict[0]), ENOMEM);
}

/* Empty set */
static void test_empty(void **state)
{
	set_t *set = *state;
	assert_int_equal(set_contains(set, dict[1]), 0);
	assert_int_not_equal(set_del(set, dict[1]), 0);
}

/* Prefix walking */
static void test_prefixes(void **state)
{
	set_t *set = *state;
	int i = 0;
	if ((set_add(set, "1str") != 0) ||
			(set_add(set, "11str2") != 0) ||
			(set_add(set, "12str") != 0) ||
			(set_add(set, "11str") != 0)) {
		assert_int_equal(1, 0);
	}

	assert_int_equal(set_walk_prefixed(set, "11", count_cb, &i), 0);
	assert_int_equal(i, 2);
	i = 0;
	assert_int_equal(set_walk_prefixed(set, "13", count_cb, &i), 0);
	assert_int_equal(i, 0);
	i = 0;
	assert_int_equal(set_walk_prefixed(set, "12345678", count_cb, &i), 0);
	assert_int_equal(i, 0);
	i = 0;
	assert_int_equal(set_walk_prefixed(set, "11str", count_cb, &i), 0);
	assert_int_equal(i, 2);
}

static void test_clear(void **state)
{
	set_t *set = *state;
	set_clear(set);
}

static void test_init(void **state)
{
	static set_t set;
	set = set_make(NULL);
	*state = &set;
	assert_non_null(*state);
}

static void test_deinit(void **state)
{
	set_t *set = *state;
	set_clear(set);
}

/* Program entry point */
int main(int argc, char **argv)
{
	const UnitTest tests[] = {
	        group_test_setup(test_init),
	        unit_test(test_insert),
	        unit_test(test_complete_full),
	        unit_test(test_insert_dup),
	        unit_test(test_contains),
		unit_test(test_delete),
		unit_test(test_clear),
		unit_test(test_insert),
		unit_test(test_complete_full),
		unit_test(test_delete_all),
		unit_test(test_complete_zero),
		unit_test(test_allocator),
		unit_test(test_clear),
		unit_test(test_empty),
		unit_test(test_insert),
		unit_test(test_prefixes),
	        group_test_teardown(test_deinit)
	};

	return run_group_tests(tests);
}
