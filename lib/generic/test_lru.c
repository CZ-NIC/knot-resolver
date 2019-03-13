/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tests/unit/test.h"
#include "lib/generic/lru.h"

typedef lru_t(int) lru_int_t;
#define HASH_SIZE 1024
#define KEY_LEN(x) (strlen(x) + 1)

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

static void test_insert(void **state)
{
	lru_int_t *lru = *state;
	int dict_size = sizeof(dict) / sizeof(const char *);
	int i;

	for (i = 0; i < dict_size; i++) {
		int *data = lru_get_new(lru, dict[i], KEY_LEN(dict[i]), NULL);
		if (!data) {
			continue;
		}
		*data = i;
		assert_true(*lru_get_try(lru, dict[i], KEY_LEN(dict[i])) == i);
	}
}

static void test_missing(void **state)
{
	lru_int_t *lru = *state;
	const char *notin = "not in lru";
	assert_true(lru_get_try(lru, notin, KEY_LEN(notin)) == NULL);
}

static void test_eviction(void **state)
{
	lru_int_t *lru = *state;
	char key[16];
	for (unsigned i = 0; i < HASH_SIZE; ++i) {
		test_randstr(key, sizeof(key));
		int *data = lru_get_new(lru, key, sizeof(key), NULL);
		if (!data) {
			continue;
		}
		*data = i;
		if (*lru_get_try(lru, key, sizeof(key)) != i) {
			assert_true(0);
		}
	}
}

static void test_init(void **state)
{
	lru_int_t *lru;
	lru_create(&lru, HASH_SIZE, NULL, NULL);
	assert_non_null(lru);
	*state = lru;
}

static void test_deinit(void **state)
{
	lru_int_t *lru = *state;
	lru_free(lru);
}

/* Program entry point */
int main(int argc, char **argv)
{
	const UnitTest tests[] = {
	        group_test_setup(test_init),
	        unit_test(test_insert),
		unit_test(test_missing),
		unit_test(test_eviction),
	        group_test_teardown(test_deinit)
	};

	return run_group_tests(tests);
}
