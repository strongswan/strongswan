/*
 * Copyright (C) 2014 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "test_suite.h"

#include <unistd.h>

#include <utils/settings.h>
#include <utils/chunk.h>
#include <utils/utils.h>

static char *path = "/tmp/strongswan-settings-test";
static settings_t *settings;

static void create_settings(chunk_t contents)
{
	ck_assert(chunk_write(contents, path, 0022, TRUE));
	settings = settings_create(path);
}

START_SETUP(setup_base_config)
{
	create_settings(chunk_from_str(
		"main {\n"
		"	key1 = val1\n"
		"	# this gets overridden below\n"
		"	key2 = val2\n"
		"	none = \n"
		"	sub1 {\n"
		"		key = value\n"
		"		key2 = value2\n"
		"		subsub {\n"
		"			foo = bar\n"
		"		}\n"
		"		# subsub is a section and a value\n"
		"		subsub = section value\n"
		"	}\n"
		"	sub% {\n"
		"		id = %any\n"
		"	}\n"
		"	key2 = with spaces\n"
		"}\n"
		"out = side\n"
		"other {\n"
		"	key1 = other val\n"
		"}"));
}
END_SETUP

START_TEARDOWN(teardown_config)
{
	settings->destroy(settings);
	unlink(path);
}
END_TEARDOWN

#define verify_string(expected, key, ...) \
	ck_assert_str_eq(expected, settings->get_str(settings, key, NULL, ##__VA_ARGS__))
#define verify_null(key, ...) \
	ck_assert(!settings->get_str(settings, key, NULL, ##__VA_ARGS__))

START_TEST(test_get_str)
{
	verify_string("val1", "main.key1");
	verify_string("with spaces", "main.key2");
	verify_string("value", "main.sub1.key");
	verify_string("value2", "main.sub1.key2");
	verify_string("bar", "main.sub1.subsub.foo");
	verify_string("section value", "main.sub1.subsub");
	verify_string("%any", "main.sub%%.id");
	verify_string("side", "out");
	verify_string("other val", "other.key1");

	/* FIXME: should this rather be undefined i.e. return the default value? */
	verify_string("", "main.none");

	verify_null("main.key3");
	verify_null("other.sub");
}
END_TEST

enum {
	KEY1,
	SUB1
} settings_test_enum;

enum_name_t *test_settings_test_names;

ENUM_BEGIN(test_settings_test_names, KEY1, SUB1,
	"key1", "sub1");
ENUM_END(test_settings_test_names, SUB1);

START_TEST(test_get_str_printf)
{
	verify_string("val1", "%s.key1", "main");
	verify_string("val1", "%s.%s", "main", "key1");
	verify_string("val1", "%s.%N", "main", test_settings_test_names, KEY1);
	verify_string("val1", "%s.%s%d", "main", "key", 1);
	verify_string("bar", "%s.sub1.%s.foo", "main", "subsub");
	verify_string("bar", "%s.%N.%s.foo", "main", test_settings_test_names, SUB1, "subsub");
	verify_string("bar", "%s.sub%d.%s.foo", "main", 1, "subsub");
	verify_string("%any", "%s.sub%%.id", "main");

	/* FIXME: this is a bit inconsistent, while this works */
	verify_string("value2", "main.%s%u.key2", "sub", 1);
	/* this won't because no argument is consumed for %u so key1 will be tried
	 * granted, we never actually used any other specifiers, but we should
	 * probably document it at least */
	verify_null("main.%s%u.key%d", "sub", 1, 2);

	verify_null("%s.%s%d", "main", "key", 3);
}
END_TEST

START_SETUP(setup_bool_config)
{
	create_settings(chunk_from_str(
		"main {\n"
		"	key1 = yes\n"
		"	key2 = true\n"
		"	key3 = Enabled\n"
		"	key4 = 1\n"
		"	key5 = no\n"
		"	key6 = FALSE\n"
		"	key7 = disabled\n"
		"	key8 = 0\n"
		"	key9 = 5\n"
		"	none = \n"
		"	foo = bar\n"
		"}"));
}
END_SETUP

#define verify_bool(expected, def, key, ...) \
	ck_assert(expected == settings->get_bool(settings, key, def, ##__VA_ARGS__))

START_TEST(test_get_bool)
{
	verify_bool(TRUE, FALSE, "main.key1");
	verify_bool(TRUE, FALSE, "main.key2");
	verify_bool(TRUE, FALSE, "main.key3");
	verify_bool(TRUE, FALSE, "main.key4");
	verify_bool(FALSE, TRUE, "main.key5");
	verify_bool(FALSE, TRUE, "main.key6");
	verify_bool(FALSE, TRUE, "main.key7");
	verify_bool(FALSE, TRUE, "main.key8");

	verify_bool(FALSE, FALSE, "main.none");
	verify_bool(TRUE, TRUE, "main.none");
	verify_bool(FALSE, FALSE, "main.foo");
	verify_bool(TRUE, TRUE, "main.foo");

	verify_bool(FALSE, FALSE, "main.key9");
	verify_bool(TRUE, TRUE, "main.key9");
	verify_bool(FALSE, FALSE, "main");
	verify_bool(TRUE, TRUE, "main");

}
END_TEST

START_SETUP(setup_int_config)
{
	create_settings(chunk_from_str(
		"main {\n"
		"	key1 = 5\n"
		"	# gets cut off\n"
		"	key2 = 5.5\n"
		"	key3 = -42\n"
		"	none = \n"
		"	foo1 = bar\n"
		"	foo2 = bar13\n"
		"	foo3 = 13bar\n"
		"}"));
}
END_SETUP

#define verify_int(expected, def, key, ...) \
	ck_assert_int_eq(expected, settings->get_int(settings, key, def, ##__VA_ARGS__))

START_TEST(test_get_int)
{
	verify_int(5, 0, "main.key1");
	verify_int(5, 0, "main.key2");
	verify_int(-42, 0, "main.key3");

	/* FIXME: do we want this behavior? */
	verify_int(0, 11, "main.none");
	verify_int(0, 11, "main.foo1");
	verify_int(0, 11, "main.foo2");
	verify_int(13, 11, "main.foo3");

	verify_int(13, 13, "main.key4");
	verify_int(-13, -13, "main");
}
END_TEST

START_SETUP(setup_double_config)
{
	create_settings(chunk_from_str(
		"main {\n"
		"	key1 = 5\n"
		"	key2 = 5.5\n"
		"	key3 = -42\n"
		"	key4 = -42.5\n"
		"	none = \n"
		"	foo1 = bar\n"
		"	foo2 = bar13.5\n"
		"	foo3 = 13.5bar\n"
		"}"));
}
END_SETUP

#define verify_double(expected, def, key, ...) \
	ck_assert(expected == settings->get_double(settings, key, def, ##__VA_ARGS__))

START_TEST(test_get_double)
{
	verify_double(5, 0, "main.key1");
	verify_double(5.5, 0, "main.key2");
	verify_double(-42, 0, "main.key3");
	verify_double(-42.5, 0, "main.key4");

	/* FIXME: do we want this behavior? */
	verify_double(0, 11.5, "main.none");
	verify_double(0, 11.5, "main.foo1");
	verify_double(0, 11.5, "main.foo2");
	verify_double(13.5, 11.5, "main.foo3");

	verify_double(11.5, 11.5, "main.key5");
	verify_double(-11.5, -11.5, "main");
}
END_TEST

START_SETUP(setup_time_config)
{
	create_settings(chunk_from_str(
		"main {\n"
		"	key1 = 5s\n"
		"	key2 = 5m\n"
		"	key3 = 5h\n"
		"	key4 = 5d\n"
		"	none = \n"
		"	foo1 = bar\n"
		"	foo2 = bar13\n"
		"	foo3 = 13bar\n"
		"}"));
}
END_SETUP

#define verify_time(expected, def, key, ...) \
	ck_assert_int_eq(expected, settings->get_time(settings, key, def, ##__VA_ARGS__))

START_TEST(test_get_time)
{
	verify_time(5, 0, "main.key1");
	verify_time(300, 0, "main.key2");
	verify_time(18000, 0, "main.key3");
	verify_time(432000, 0, "main.key4");

	/* FIXME: do we want this behavior? */
	verify_time(0, 11, "main.none");
	verify_time(0, 11, "main.foo1");
	verify_time(0, 11, "main.foo2");
	verify_time(13, 11, "main.foo3");

	verify_time(11, 11, "main.key5");
	verify_time(11, 11, "main");
}
END_TEST

Suite *settings_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("settings");

	tc = tcase_create("get/set_str (basic behavior)");
	tcase_add_checked_fixture(tc, setup_base_config, teardown_config);
	tcase_add_test(tc, test_get_str);
	tcase_add_test(tc, test_get_str_printf);
	suite_add_tcase(s, tc);

	tc = tcase_create("get/set_bool");
	tcase_add_checked_fixture(tc, setup_bool_config, teardown_config);
	tcase_add_test(tc, test_get_bool);
	suite_add_tcase(s, tc);

	tc = tcase_create("get/set_int");
	tcase_add_checked_fixture(tc, setup_int_config, teardown_config);
	tcase_add_test(tc, test_get_int);
	suite_add_tcase(s, tc);

	tc = tcase_create("get/set_double");
	tcase_add_checked_fixture(tc, setup_double_config, teardown_config);
	tcase_add_test(tc, test_get_double);
	suite_add_tcase(s, tc);

	tc = tcase_create("get/set_time");
	tcase_add_checked_fixture(tc, setup_time_config, teardown_config);
	tcase_add_test(tc, test_get_time);
	suite_add_tcase(s, tc);

	return s;
}
