/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <contrib/cleanup.h>
#include "tests/unit/test.h"
#include "lib/rules/api.h"

static void write_tmp(char *path_buf, const char *content)
{
	strcpy(path_buf, "/tmp/kr_uuids_XXXXXX");
	int fd = mkstemp(path_buf);
	assert_true(fd >= 0);
	size_t len = strlen(content);
	assert_int_equal(write(fd, content, len), (ssize_t)len);
	close(fd);
}

#define UUID_OK "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
static const uint8_t UUID_OK_BIN[KR_UUID_BYTES] = {
	0xaa,0xaa,0xaa,0xaa, 0xbb,0xbb, 0xcc,0xcc,
	0xdd,0xdd, 0xee,0xee,0xee,0xee,0xee,0xee,
};
#define UUID_OK2 "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"
static const uint8_t UUID_OK2_BIN[KR_UUID_BYTES] = {
	0xaa,0xaa,0xaa,0xaa, 0xbb,0xbb, 0xcc,0xcc,
	0xdd,0xdd, 0xff,0xff,0xff,0xff,0xff,0xff,
};

static const uint8_t UUID_ABSENT[KR_UUID_BYTES] = {
	0xff,0xff,0xff,0xff, 0xff,0xff, 0xff,0xff,
	0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,
};

static void test_uuids_valid(void **state)
{
	char path[64];
	write_tmp(path, UUID_OK "\n" UUID_OK2 "\n");
	assert_int_equal(kr_view_load_uuids(path), 0);
	unlink(path);
}

static void test_uuids_malformed(void **state)
{
	static const char *bad[] = {
		"garbage\n",
		"aaaaaaaa-bbbb-cccc-dddd\n",
		"gggggggg-bbbb-cccc-dddd-eeeeeeeeeeee\n",
		UUID_OK "extra\n",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
		char path[64];
		write_tmp(path, bad[i]);
		assert_int_not_equal(kr_view_load_uuids(path), 0);
		unlink(path);
	}
}

static void test_uuids_nonexistent(void **state)
{
	assert_int_not_equal(kr_view_load_uuids("/nonexistent/path/xyz"), 0);
}

static void test_uuid_lookup(void **state)
{
	char path[64];
	write_tmp(path, UUID_OK "\n" UUID_OK2 "\n");
	assert_int_equal(kr_view_load_uuids(path), 0);

	assert_true(kr_view_uuid_allowed(UUID_OK_BIN));
	assert_true(kr_view_uuid_allowed(UUID_OK2_BIN));
	assert_false(kr_view_uuid_allowed(UUID_ABSENT));
	unlink(path);
}

static int group_setup(void **state)
{
	return kr_rules_init(NULL, 0, false);
}

static int group_teardown(void **state)
{
	kr_rules_deinit();
	return 0;
}

int main(int argc, char *argv[])
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_uuids_valid),
		cmocka_unit_test(test_uuids_malformed),
		cmocka_unit_test(test_uuids_nonexistent),
		cmocka_unit_test(test_uuid_lookup),
	};
	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
