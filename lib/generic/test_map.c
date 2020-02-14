/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tests/unit/test.h"
#include "lib/generic/map.h"

/*
 * Sample dictionary
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
	map_t *tree = *state;
	int dict_size = sizeof(dict) / sizeof(const char *);
	int i;

	for (i = 0; i < dict_size; i++) {
		assert_int_equal(map_set(tree, dict[i], (void *)dict[i]), 0);
	}
}

/* Searching */
static void test_get(void **state)
{
	map_t *tree = *state;
	char *in;
	const char *notin = "not in tree";

	in = malloc(strlen(dict[23])+1);
	strcpy(in, dict[23]);

	assert_true(map_get(tree, in) == dict[23]);
	assert_true(map_get(tree, notin) == NULL);
	assert_true(map_get(tree, "") == NULL);
	in[strlen(in)/2] = '\0';
	assert_true(map_get(tree, in) == NULL);

	free(in);
}

/* Deletion */
static void test_delete(void **state)
{
	map_t *tree = *state;
	assert_int_equal(map_del(tree, dict[91]), 0);
	assert_false(map_contains(tree, dict[91]));
	assert_int_equal(map_del(tree, "most likely not in tree"), 1);
}

/* Test null value existence */
static void test_null_value(void **state)
{
	map_t *tree = *state;
	char *key = "foo";

	assert_int_equal(map_set(tree, key, (void *)0), 0);
	assert_true(map_contains(tree, key));
	assert_int_equal(map_del(tree, key), 0);
}

static void test_init(void **state)
{
	static map_t tree;
	tree = map_make(NULL);
	*state = &tree;
	assert_non_null(*state);
}

static void test_deinit(void **state)
{
	map_t *tree = *state;
	map_clear(tree);
}

/* Program entry point */
int main(int argc, char **argv)
{
	const UnitTest tests[] = {
	        group_test_setup(test_init),
	        unit_test(test_insert),
		unit_test(test_get),
		unit_test(test_delete),
		unit_test(test_null_value),
	        group_test_teardown(test_deinit)
	};

	return run_group_tests(tests);
}
