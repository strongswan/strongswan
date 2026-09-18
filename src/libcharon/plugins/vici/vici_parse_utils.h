/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2026 Florian Jung
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
 * @defgroup vici_parse_util vici_parse_util
 * @{ @ingroup vici
 */

#ifndef VICI_PARSE_UTILS_H_
#define VICI_PARSE_UTILS_H_

#include "vici_message.h"

typedef struct vici_parse_rule_t vici_parse_rule_t;
typedef struct vici_enum_map_t vici_enum_map_t;

/**
 * Callback invoked to parse key/value or list items.
 *
 * A rule's storage location is passed directly as first argument.
 *
 * @param out		location to store a result on success
 * @param value		the value to parse
 */
typedef bool (*vici_parse_cb_t)(void *out, chunk_t value);

/**
 * A rule to parse a key/value or list item in a vici message.
 */
struct vici_parse_rule_t {

	/**
	 * Name of the key/value or list to match.
	 */
	const char *name;

	/**
	 * Where to store the parsed result.
	 *
	 * The type of the pointer has to match that of the rule exactly.  It's
	 * passed to the callback as is.
	 */
	void *out;

	/**
	 * Parse callback function.
	 *
	 * The rule's storage location is passed directly as first argument.
	 *
	 * @param out		location to store a result on success
	 * @param value		the value to parse
	 */
	vici_parse_cb_t parse;
};

/**
 * Parse a value as a string.
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_string(char **out, chunk_t value);

/**
 * Parse a value as a boolean, normalizing "yes", "true", 1 etc.
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_bool(bool *out, chunk_t value);

/**
 * Parse a value as an unsigned 64-bit integer (base 10 and 16).
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_uint64(uint64_t *out, chunk_t value);

/**
 * Parse a value as an unsigned 32-bit integer (base 10 and 16).
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_uint32(uint32_t *out, chunk_t value);

/**
 * Parse a value as an unsigned 16-bit integer (base 10 and 16).
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_uint16(uint16_t *out, chunk_t value);

/**
 * Parse a value as an unsigned 8-bit integer (base 10 and 16).
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_uint8(uint8_t *out, chunk_t value);

/**
 * Parse a value as an unsigned 8-bit integer (only base 2).
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_uint8_bin(uint8_t *out, chunk_t value);

/**
 * Parse a value as an unsigned 64-bit integer that represents
 * a time in seconds.
 *
 * The suffixes "m", "h" and "d" translate a value given in minutes, hours or
 * days, respectively, into seconds.
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_time(uint64_t *out, chunk_t value);

/**
 * Parse a value as an unsigned 32-bit integer that represents
 * a time in seconds.
 *
 * The suffixes "m", "h" and "d" translate a value given in minutes, hours or
 * days, respectively, into seconds.
 *
 * @param out			location to store the result
 * @param value			value to parse
 * @return				TRUE on success
 */
bool vici_parse_time32(uint32_t *out, chunk_t value);

/**
 * Define a rule to parse a value with a custom function.
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			object passed to the callback to store the result
 * @param cb			custom parse function
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_CUSTOM(name, out, cb) vici_rule_custom(name, out, cb)

/**
 * Implementation for \ref VICI_RULE_CUSTOM, use that macro instead.
 * @copydetails VICI_RULE_CUSTOM
 * @see VICI_RULE_CUSTOM
 */
static inline vici_parse_rule_t vici_rule_custom(const char *name, void *out,
												 vici_parse_cb_t cb)
{
	return (vici_parse_rule_t){ name, out, cb };
}

/**
 * Define a rule to parse a value as a string.
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_STRING(name, out) vici_rule_string(name, out)

/**
 * Implementation for \ref VICI_RULE_STRING, use that macro instead.
 * @copydetails VICI_RULE_STRING
 * @see VICI_RULE_STRING
 */
static inline vici_parse_rule_t vici_rule_string(const char *name, char **out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_string };
}

/**
 * Define a rule to parse a value as a boolean.
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_BOOL(name, out) vici_rule_bool(name, out)

/**
 * Implementation for \ref VICI_RULE_BOOL, use that macro instead.
 * @copydetails VICI_RULE_BOOL
 * @see VICI_RULE_BOOL
 */
static inline vici_parse_rule_t vici_rule_bool(const char *name, bool *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_bool };
}

/**
 * Define a rule to parse a value as a 64-bit integer (base 10 and 16).
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_UINT64(name, out) vici_rule_uint64(name, out)

/**
 * Implementation for \ref VICI_RULE_UINT64, use that macro instead.
 * @copydetails VICI_RULE_UINT64
 * @see VICI_RULE_UINT64
 */
static inline vici_parse_rule_t vici_rule_uint64(const char *name,
												 uint64_t *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_uint64 };
}

/**
 * Define a rule to parse a value as a 32-bit integer (base 10 and 16).
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_UINT32(name, out) vici_rule_uint32(name, out)

/**
 * Implementation for \ref VICI_RULE_UINT32, use that macro instead.
 * @copydetails VICI_RULE_UINT32
 * @see VICI_RULE_UINT32
 */
static inline vici_parse_rule_t vici_rule_uint32(const char *name,
												 uint32_t *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_uint32 };
}

/**
 * Define a rule to parse a value as a 16-bit integer (base 10 and 16).
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_UINT16(name, out) vici_rule_uint16(name, out)

/**
 * Implementation for \ref VICI_RULE_UINT16, use that macro instead.
 * @copydetails VICI_RULE_UINT16
 * @see VICI_RULE_UINT16
 */
static inline vici_parse_rule_t vici_rule_uint16(const char *name,
												 uint16_t *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_uint16 };
}

/**
 * Define a rule to parse a value as an 8-bit integer (base 10 and 16).
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_UINT8(name, out) vici_rule_uint8(name, out)

/**
 * Implementation for \ref VICI_RULE_UINT8, use that macro instead.
 * @copydetails VICI_RULE_UINT8
 * @see VICI_RULE_UINT8
 */
static inline vici_parse_rule_t vici_rule_uint8(const char *name,
												uint8_t *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_uint8 };
}

/**
 * Define a rule to parse a value as an 8-bit integer (only base 2).
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_UINT8_BIN(name, out) vici_rule_uint8_bin(name, out)

/**
 * Implementation for \ref VICI_RULE_UINT8_BIN, use that macro instead.
 * @copydetails VICI_RULE_UINT8_BIN
 * @see VICI_RULE_UINT8_BIN
 */
static inline vici_parse_rule_t vici_rule_uint8_bin(const char *name,
													uint8_t *out)
{
	return (vici_parse_rule_t){ name, out,
								(vici_parse_cb_t)vici_parse_uint8_bin };
}

/**
 * Define a rule to parse a value as an unsigned 64-bit integer that represents
 * a time in seconds.
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_TIME(name, out) vici_rule_time(name, out)

/**
 * Implementation for \ref VICI_RULE_TIME, use that macro instead.
 * @copydetails VICI_RULE_TIME
 * @see VICI_RULE_TIME
 */
static inline vici_parse_rule_t vici_rule_time(const char *name, uint64_t *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_time };
}

/**
 * Define a rule to parse a value as an unsigned 32-bit integer that represents
 * a time in seconds.
 *
 * @hideinitializer
 * @param name			key/list name to match
 * @param out			location to store the result
 * @return				rule, to be used in a vici_parse_rule_t array
 */
#define VICI_RULE_TIME32(name, out) vici_rule_time32(name, out)

/**
 * Implementation for \ref VICI_RULE_TIME32, use that macro instead.
 * @copydetails VICI_RULE_TIME32
 * @see VICI_RULE_TIME32
 */
static inline vici_parse_rule_t vici_rule_time32(const char *name,
												 uint32_t *out)
{
	return (vici_parse_rule_t){ name, out, (vici_parse_cb_t)vici_parse_time32 };
}

/**
 * Type to use for arrays that map strings to integers (e.g. enum values).
 */
struct vici_enum_map_t {

	/**
	 * String value to match to.
	 */
	const char *str;

	/**
	 * Resulting integer value.
	 */
	int d;
};

/**
 * Parse key/value or list items using a set of rules.
 *
 * @param rules			parsing rules to apply
 * @param count			amount of rules in \p rules
 * @param name			the current name of the key/value or list to parse
 * @param value			the current value to parse
 * @param reply			reply created on parse error
 * @return				TRUE on success
 */
bool vici_parse_rules(vici_parse_rule_t *rules, int count, char *name,
					  chunk_t value, vici_message_t **reply);

/**
 * Map a string to an integral value.
 *
 * @hideinitializer
 * @param map			the map to use
 * @param count			number of entries in \p map
 * @param out			result that got parsed
 * @param value			the value to parse
 * @return				TRUE if successful
 */
#define VICI_PARSE_MAP(map, count, out, value) ({ \
		typeof(out) _out = (out); \
		bool _ret = FALSE; \
		int _val; \
		if (vici_parse_map((map), (count), &_val, (value))) \
		{ \
			*_out = _val; \
			_ret = TRUE; \
		} \
		_ret; })

/**
 * Implementation of \ref VICI_PARSE_MAP, use that macro instead.
 * @copydetails VICI_PARSE_MAP
 */
bool vici_parse_map(vici_enum_map_t *map, int count, int *out, chunk_t value);

/**
 * Add a bitmap value depending on whether the value parsed as boolean is TRUE
 * or FALSE.
 *
 * @note This is defined as a macro so it works with enums of any size.
 *
 * @hideinitializer
 * @param out			bitmap to modify
 * @param opt			option in the bitmap to set (same type as out)
 * @param value			value to parse
 * @param add_if_true	whether to add the option if the parsed value is TRUE
 *						or FALSE
 * @return				TRUE if value parsed as bool, regardless of whether the
 *						option was set
 */
#define VICI_PARSE_OPTION(out, opt, value, add_if_true) ({ \
	typeof(out) _out = (out); \
	bool _val, _ret = FALSE; \
	if (vici_parse_bool(&_val, (value))) \
	{ \
		if (_val == (add_if_true)) \
		{ \
			*_out |= (opt); \
		} \
		_ret = TRUE; \
	} \
	_ret; })

#endif /** VICI_PARSE_UTILS_H_ @}*/
