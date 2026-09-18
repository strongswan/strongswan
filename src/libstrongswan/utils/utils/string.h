/*
 * Copyright (C) 2008-2026 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

/**
 * @defgroup string_i string
 * @{ @ingroup utils_i
 */

#ifndef STRING_H_
#define STRING_H_

#include <ctype.h>

/**
 * Helper function that compares two strings for equality
 */
static inline bool streq(const char *x, const char *y)
{
	return (x == y) || (x && y && strcmp(x, y) == 0);
}

/**
 * Helper function that compares two strings for equality, length limited
 */
static inline bool strneq(const char *x, const char *y, size_t len)
{
	return (x == y) || (x && y && strncmp(x, y, len) == 0);
}

/**
 * Helper function that checks if a string starts with a given prefix
 */
static inline bool strpfx(const char *x, const char *prefix)
{
	return strneq(x, prefix, strlen(prefix));
}

/**
 * Helper function that compares two strings for equality ignoring case
 */
static inline bool strcaseeq(const char *x, const char *y)
{
	return (x == y) || (x && y && strcasecmp(x, y) == 0);
}

/**
 * Helper function that compares two strings for equality ignoring case, length limited
 */
static inline bool strncaseeq(const char *x, const char *y, size_t len)
{
	return (x == y) || (x && y && strncasecmp(x, y, len) == 0);
}

/**
 * Helper function that checks if a string starts with a given prefix
 */
static inline bool strcasepfx(const char *x, const char *prefix)
{
	return strncaseeq(x, prefix, strlen(prefix));
}

/**
 * NULL-safe strdup variant
 */
static inline char *strdupnull(const char *s)
{
	return s ? strdup(s) : NULL;
}

/**
 * Translates the characters in the given string, searching for characters
 * in 'from' and mapping them to characters in 'to'.
 * The two characters sets 'from' and 'to' must contain the same number of
 * characters.
 */
char *translate(char *str, const char *from, const char *to);

/**
 * Replaces all occurrences of search in the given string with replace.
 *
 * Allocates memory only if anything is replaced in the string.  The original
 * string is also returned if any of the arguments are invalid (e.g. if search
 * is empty or any of them are NULL).
 *
 * @param str		original string
 * @param search	string to search for and replace
 * @param replace	string to replace found occurrences with
 * @return			allocated string, if anything got replaced, str otherwise
 */
char *strreplace(const char *str, const char *search, const char *replace);

/**
 * Parse an unsigned 64-bit integer from a string, wrapping strtoull().
 *
 * It rejects the following:  empty/no-digit input, a leading '-' (which
 * strtoull() would wrap modulo 2^64) and out-of-range values.
 *
 * Only the prefix is parsed, \p end (if given) points to the first unconsumed
 * character so callers can scan suffixes.  To ensure a plain number,
 * additionally check <tt>*end == '\0'</tt>.
 *
 * Prefer base 10 (with the settings_t-style explicit 0x-check for hex) because
 * base 0 additionally enables octal, which silently reinterprets zero-padded
 * input ("010" => 8).
 *
 * @param str		string to parse (NULL-safe)
 * @param end		first unconsumed character on success (optional)
 * @param base		numeric base, same as strtoull()
 * @param[out] out	parsed value on success, unchanged otherwise (required)
 * @return			TRUE if at least one digit converted without range error
 */
bool uint64_from_string(const char *str, char **end, int base, uint64_t *out);

/**
 * Parse an unsigned 32-bit integer from a string, wrapping strtoull().
 *
 * @copydetails uint64_from_string
 */
static inline bool uint32_from_string(const char *str, char **end, int base,
									  uint32_t *out)
{
	char *endptr;
	uint64_t val;

	if (out && uint64_from_string(str, &endptr, base, &val) &&
		val <= UINT32_MAX)
	{
		if (end)
		{
			*end = endptr;
		}
		*out = val;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse an unsigned 16-bit integer from a string, wrapping strtoull().
 *
 * @copydetails uint64_from_string
 */
static inline bool uint16_from_string(const char *str, char **end, int base,
									  uint16_t *out)
{
	char *endptr;
	uint64_t val;

	if (out && uint64_from_string(str, &endptr, base, &val) &&
		val <= UINT16_MAX)
	{
		if (end)
		{
			*end = endptr;
		}
		*out = val;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse an unsigned 8-bit integer from a string, wrapping strtoull().
 *
 * @copydetails uint64_from_string
 */
static inline bool uint8_from_string(const char *str, char **end, int base,
									 uint8_t *out)
{
	char *endptr;
	uint64_t val;

	if (out && uint64_from_string(str, &endptr, base, &val) && val <= UINT8_MAX)
	{
		if (end)
		{
			*end = endptr;
		}
		*out = val;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse a signed 64-bit integer from a string, wrapping strtoll().
 *
 * It rejects the following:  empty/no-digit input and out-of-range values.
 * A leading -/+ is accepted as the value's sign.
 *
 * Only the prefix is parsed, \p end (if given) points to the first unconsumed
 * character so callers can scan suffixes.  To ensure a plain number,
 * additionally check <tt>*end == '\0'</tt>.
 *
 * Prefer base 10 (with the settings_t-style explicit 0x-check for hex) because
 * base 0 additionally enables octal, which silently reinterprets zero-padded
 * input ("010" => 8).
 *
 * @param str		string to parse (NULL-safe)
 * @param end		first unconsumed character on success (optional)
 * @param base		numeric base, same as strtoll()
 * @param[out] out	parsed value on success, unchanged otherwise (required)
 * @return			TRUE if at least one digit converted without range error
 */
bool int64_from_string(const char *str, char **end, int base, int64_t *out);

/**
 * Parse a signed 32-bit integer from a string, wrapping strtoll().
 *
 * @copydetails int64_from_string
 */
static inline bool int32_from_string(const char *str, char **end, int base,
									 int32_t *out)
{
	char *endptr;
	int64_t val;

	if (out && int64_from_string(str, &endptr, base, &val) &&
		val <= INT32_MAX && val >= INT32_MIN)
	{
		if (end)
		{
			*end = endptr;
		}
		*out = val;
		return TRUE;
	}
	return FALSE;
}

/**
 * Determine the base when parsing integer strings.
 *
 * We generally only want to parse integers in base 10 and 16 (with 0x prefix).
 *
 * @param str		string to parse (NULL-safe)
 * @return			base determined based on the given string, defaults to 10
 */
static inline int base_from_string(const char *str)
{
	while (str && isspace((u_char)*str))
	{
		str++;
	}
	if (str && (*str == '-' || *str == '+'))
	{
		str++;
	}
	return strcasepfx(str, "0x") ? 16 : 10;
}

#endif /** STRING_H_ @} */
