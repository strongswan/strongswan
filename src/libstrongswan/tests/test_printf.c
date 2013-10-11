/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include <errno.h>
#include <math.h>

static void verify(char *expected, char *format, ...)
{
	FILE *mem;
	char buf[128];
	va_list args;

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	ck_assert_str_eq(expected, buf);
	va_end(args);

	mem = fmemopen(buf, sizeof(buf), "w");
	va_start(args, format);
	vfprintf(mem, format, args);
	va_end(args);
	fclose(mem);
	ck_assert_str_eq(expected, buf);
}

START_TEST(test_printf_strings)
{
	verify("a bc def", "%s %s %s", "a", "bc", "def");
	verify("asd", "%.3s", "asdfg");
	verify("asdf", "%.*s", (int)4, "asdfg");
	verify("  asdf", "%6s", "asdf");
	verify("  asdf", "%+6s", "asdf");
	verify("asdf  ", "%-6s", "asdf");
}
END_TEST

START_TEST(test_printf_err)
{
	errno = EINVAL;
	verify((char*)strerror(errno), "%m");
}
END_TEST

START_TEST(test_printf_unsigned)
{
	verify("1 23 456", "%u %lu %llu", 1, (u_long)23, (u_int64_t)456);
	verify("65535 255", "%hu %hhu", 0x1ffff, 0x1ff);
	verify("123456789", "%zu", (size_t)123456789);
	verify("   12", "%5u", 12);
	verify("12   ", "%-5u", 12);
	verify("0012", "%04u", 12);
	verify("0012", "%.4u", 12);
}
END_TEST

START_TEST(test_printf_signed)
{
	verify("-1 -23 -456", "%d %ld %lld", -1, (long)-23, (int64_t)-456);
	verify("-1 -1", "%hd %hhd", 0x1ffff, 0x1ff);
	verify("123456789", "%zd", (ssize_t)123456789);
	verify("  -12", "%5d", -12);
	verify("-12  ", "%-5d", -12);
	verify("-012", "%04d", -12);
	verify("-0012", "%.4d", -12);
}
END_TEST

START_TEST(test_printf_hex)
{
	verify("1 23 456", "%x %lx %llx", 1, (u_long)0x23, (u_int64_t)0x456);
	verify("12abcdef 12ABCDEF", "%x %X", 0x12ABCDEF, 0x12ABCDEF);
	verify("ffff ff", "%hx %hhx", 0x1ffff, 0x1ff);
	verify("23456789", "%zx", (size_t)0x23456789);
	verify("   ab", "%5x", 0xab);
	verify("ab   ", "%-5x", 0xab);
	verify("00ab", "%04x", 0xab);
	verify("00ab", "%.4x", 0xab);
}
END_TEST

START_TEST(test_printf_float)
{
	verify("0.000000", "%f", 0.0);
	verify("1.000000", "%f", 1.0);
	verify("12345.1", "%.1f", 12345.123);
	verify("1", "%.0f", 1.0);
	verify("1.3", "%.1f", 1.346789);
	verify("1.23", "%.2f", 1.23456789);
	verify("1.123", "%.3f", 1.123456789);
	verify("1.0123", "%.4f", 1.0123456789);

	verify("-1.000000", "%f", -1.0);
	verify("-12345.1", "%.1f", -12345.123);
	verify("-1", "%.0f", -1.0);
	verify("-1.3", "%.1f", -1.3456789);
	verify("-1.23", "%.2f", -1.23456789);
	verify("-1.123", "%.3f", -1.123456789);
	verify("-1.0123", "%.4f", -1.0123456789);

	verify("  1.2", "%5.1f", 1.234);
	verify("001.2", "%05.1f", 1.234);
	verify("1.2  ", "%-5.1f", 1.234);

	verify("12346", "%.0f", 12345.6789);
	verify("2", "%.0f", 1.5);
	verify("1", "%.0f", 1.49);
	verify("1.2", "%.1f", 1.151);
	verify("1.1", "%.1f", 1.149);
	verify("1.13", "%.2f", 1.1251);
	verify("1.12", "%.2f", 1.1249);
	verify("1.124", "%.3f", 1.12351);
	verify("1.123", "%.3f", 1.12349);

	verify("-12346", "%.0f", -12345.6789);
	verify("-2", "%.0f", -1.51);
	verify("-1", "%.0f", -1.49);
	verify("-1.2", "%.1f", -1.151);
	verify("-1.1", "%.1f", -1.149);
	verify("-1.13", "%.2f", -1.1251);
	verify("-1.12", "%.2f", -1.1249);
	verify("-1.124", "%.3f", -1.12351);
	verify("-1.123", "%.3f", -1.12349);

#ifdef NAN
	verify("nan", "%.3f", NAN);
	verify("  nan", "%5.3f", NAN);
	verify("NAN", "%.3F", NAN);
	verify("NAN  ", "%-5.3F", NAN);
#endif
#ifdef INFINITY
	verify("inf", "%.3f", INFINITY);
	verify("-inf", "%.4f", -INFINITY);
	verify("INF", "%.3F", INFINITY);
	verify("-INF", "%.4F", -INFINITY);
#endif
}
END_TEST

Suite *printf_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("printf");

	tc = tcase_create("strings");
	tcase_add_test(tc, test_printf_strings);
	suite_add_tcase(s, tc);

	tc = tcase_create("err");
	tcase_add_test(tc, test_printf_err);
	suite_add_tcase(s, tc);

	tc = tcase_create("unsiged");
	tcase_add_test(tc, test_printf_unsigned);
	suite_add_tcase(s, tc);

	tc = tcase_create("siged");
	tcase_add_test(tc, test_printf_signed);
	suite_add_tcase(s, tc);

	tc = tcase_create("hex");
	tcase_add_test(tc, test_printf_hex);
	suite_add_tcase(s, tc);

	tc = tcase_create("float");
	tcase_add_test(tc, test_printf_float);
	suite_add_tcase(s, tc);

	return s;
}
