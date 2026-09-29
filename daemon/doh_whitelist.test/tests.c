/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <contrib/cleanup.h>
#include "tests/unit/test.h"
#include "lib/rules/api.h"

struct doh_whitelist_state {
	char path1[64];
	char path2[64];
	int fd1;
	int fd2;
};

static int create_files(struct doh_whitelist_state *s)
{
	strcpy(s->path1, "/tmp/kr_uuids_XXXXXX");
	s->fd1 = mkstemp(s->path1);
	if (s->fd1 < 0)
		return kr_error(EACCES);

	strcpy(s->path2, "/tmp/kr_uuids_XXXXXX");
	s->fd2 = mkstemp(s->path2);
	if (s->fd2 < 0) {
		close(s->fd1);
		unlink(s->path1);
		return kr_error(EACCES);
	}

	return 0;
}

static void close_files(struct doh_whitelist_state *s)
{
	if (s->fd1 > -1) {
		close(s->fd1);
	}
	if (s->fd2 > -1) {
		close(s->fd2);
	}
	s->fd1 = -1;
	s->fd2 = -1;
	unlink(s->path1);
	unlink(s->path2);
}

static void write_content(int fd, const char *content)
{
	size_t len = strlen(content);
	assert_int_equal(write(fd, content, len), (ssize_t)len);
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

#define UUID_A "11111111-1111-1111-1111-111111111111"
static const uint8_t UUID_A_BIN[KR_UUID_BYTES] = {
	0x11,0x11,0x11,0x11, 0x11,0x11, 0x11,0x11,
	0x11,0x11, 0x11,0x11,0x11,0x11,0x11,0x11,
};
#define UUID_B "22222222-2222-2222-2222-222222222222"
static const uint8_t UUID_B_BIN[KR_UUID_BYTES] = {
	0x22,0x22,0x22,0x22, 0x22,0x22, 0x22,0x22,
	0x22,0x22, 0x22,0x22,0x22,0x22,0x22,0x22,
};

static void test_uuids_valid(void **state)
{
	struct doh_whitelist_state *s = *state;		
	write_content(s->fd1, UUID_OK "\n" UUID_OK2 "\n");
	assert_int_equal(kr_view_load_uuids(s->path1, "refuse"), 0);
}

static void test_uuids_malformed(void **state)
{
	struct doh_whitelist_state *s = *state;		
	static const char *bad[] = {
		"garbage\n",
		"aaaaaaaa-bbbb-cccc-dddd\n",
		"gggggggg-bbbb-cccc-dddd-eeeeeeeeeeee\n",
		UUID_OK "extra\n",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
		close_files(s);
		assert_int_equal(create_files(s), 0);
		write_content(s->fd1, bad[i]);
		assert_int_not_equal(kr_view_load_uuids(s->path1, "allow"), 0);
	}
}

static void test_uuid_lookup(void **state)
{
	struct doh_whitelist_state *s = *state;		
	static const char ACTION[] = "policy.tags_assign_bitmaps(1,0)";
	write_content(s->fd1, UUID_OK "\n" UUID_OK2 "\n");
	assert_int_equal(kr_view_load_uuids(s->path1, ACTION), 0);

	knot_db_val_t val;

	assert_int_equal(kr_view_uuid_select_action(UUID_OK_BIN, &val), 0);
	assert_int_equal(val.len, sizeof(ACTION) - 1);
	assert_memory_equal(val.data, ACTION, val.len);

	assert_int_equal(kr_view_uuid_select_action(UUID_OK2_BIN, &val), 0);
	assert_memory_equal(val.data, ACTION, val.len);

	static const char DENY[] = "policy.REFUSE";
	assert_int_equal(kr_view_uuid_select_action(UUID_ABSENT, &val), 0);
	assert_int_equal(val.len, sizeof(DENY) - 1);
	assert_memory_equal(val.data, DENY, val.len);

	assert_int_equal(kr_view_uuid_select_action(NULL, &val), 0);
	assert_memory_equal(val.data, DENY, val.len);
}

static void test_two_files_distinct_actions(void **state)
{
	struct doh_whitelist_state *s = *state;		
	static const char ACT_A[] = "policy.tags_assign_bitmaps(1,0)";
	static const char ACT_B[] = "policy.tags_assign_bitmaps(2,0)";

	write_content(s->fd1, UUID_A "\n");
	write_content(s->fd2, UUID_B "\n");
	assert_int_equal(kr_view_load_uuids(s->path1, ACT_A), 0);
	assert_int_equal(kr_view_load_uuids(s->path2, ACT_B), 0);

	knot_db_val_t val;
	assert_int_equal(kr_view_uuid_select_action(UUID_A_BIN, &val), 0);
	assert_memory_equal(val.data, ACT_A, val.len);
	assert_int_equal(val.len, sizeof(ACT_A) - 1);

	assert_int_equal(kr_view_uuid_select_action(UUID_B_BIN, &val), 0);
	assert_memory_equal(val.data, ACT_B, val.len);
}

static void test_duplicate_uuid_across_files(void **state)
{
	struct doh_whitelist_state *s = *state;		
	static const char ACT_A[] = "policy.tags_assign_bitmaps(1,0)";
	static const char ACT_B[] = "policy.tags_assign_bitmaps(2,0)";
	write_content(s->fd1, UUID_A "\n");
	write_content(s->fd2, UUID_A "\n");
	assert_int_equal(kr_view_load_uuids(s->path1, ACT_A), 0);
	assert_int_equal(kr_view_load_uuids(s->path2, ACT_B), 0);

	knot_db_val_t val;
	assert_int_equal(kr_view_uuid_select_action(UUID_A_BIN, &val), 0);
	assert_memory_equal(val.data, ACT_A, val.len);
}

static void test_uuids_file_formatting(void **state)
{
	struct doh_whitelist_state *s = *state;		
	static const struct { const char *content; bool ok; } cases[] = {
		{ "", false },
		{ UUID_OK, true },
		{ UUID_OK "\r\n", true },
		{ "\n\n" UUID_OK "\n", true },
		{ "# comment\n" UUID_OK "\n", true },
		{ "  " UUID_OK "  \n", false },
		{ UUID_OK "\n" UUID_OK "\n", true },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		close_files(s);
		assert_int_equal(create_files(s), 0);
		write_content(s->fd1, cases[i].content);
		if (cases[i].ok) {
			assert_int_equal(kr_view_load_uuids(s->path1, 
						"allow"), 0);
		} else {
			assert_int_not_equal(kr_view_load_uuids(s->path1,
						"allow"), 0);
		}
	}
}

static int setup_unit_test_state(void **state)
{
	struct doh_whitelist_state *s = *state;		
	if (create_files(s) != 0)
		return kr_error(ENOENT);
	return kr_rules_init(NULL, 0, true);
}

static int teardown_unit_test_state(void **state)
{
	struct doh_whitelist_state *s = *state;		
	close_files(s);
	kr_rules_deinit();
	return 0;
}

static int setup(void **state)
{
	*state = NULL;
	*state = calloc(1, sizeof(struct doh_whitelist_state));
	return *state ? 0 : kr_error(ENOMEM);
}
	
static int teardown(void **state)
{
	struct doh_whitelist_state *s = *state;
	free(s);
	return 0;
}

int main(int argc, char *argv[])
{
	#define c_u_t(test_fun) cmocka_unit_test_setup_teardown(test_fun, \
			setup_unit_test_state, teardown_unit_test_state)

	const struct CMUnitTest tests[] = {
		c_u_t(test_uuids_valid),
		c_u_t(test_uuid_lookup),
		c_u_t(test_uuids_malformed),
		c_u_t(test_two_files_distinct_actions),
		c_u_t(test_duplicate_uuid_across_files),
		c_u_t(test_uuids_file_formatting),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
