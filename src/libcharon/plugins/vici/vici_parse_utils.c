/*
 * Copyright (C) 2026 Florian Jung
 * Copyright (C) 2015-2026 Tobias Brunner
 * Copyright (C) 2015-2018 Andreas Steffen
 * Copyright (C) 2014 Martin Willi
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

#define _GNU_SOURCE

#include "vici_parse_utils.h"

#include <utils/utils.h>

/*
 * Described in header
 */
bool vici_parse_string(char **out, chunk_t value)
{
	if (!chunk_printable(value, NULL, ' '))
	{
		return FALSE;
	}
	free(*out);
	*out = NULL;
	if (asprintf(out, "%.*s", (int)value.len, value.ptr) == -1)
	{
		return FALSE;
	}
	return TRUE;
}

/*
 * Described in header
 */
bool vici_parse_bool(bool *out, chunk_t value)
{
	vici_enum_map_t map[] = {
		{ "yes",		TRUE	},
		{ "true",		TRUE	},
		{ "enabled",	TRUE	},
		{ "1",			TRUE	},
		{ "no",			FALSE	},
		{ "false",		FALSE	},
		{ "disabled",	FALSE	},
		{ "0",			FALSE	},
	};

	return VICI_PARSE_MAP(map, countof(map), out, value);
}

/**
 * Parse an unsigned 64-bit integer using the given base. If base is 0, default
 * to 10 or 16 depending on the prefix to avoid octal encoding.
 */
static bool parse_uint64_base(uint64_t *out, chunk_t v, int base)
{
	char buf[32], *end;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	if (!base)
	{
		base = base_from_string(buf);
	}
	return uint64_from_string(buf, &end, base, out) && *end == '\0';
}

/*
 * Described in header
 */
bool vici_parse_uint64(uint64_t *out, chunk_t value)
{
	return parse_uint64_base(out, value, 0);
}

/*
 * Described in header
 */
bool vici_parse_uint32(uint32_t *out, chunk_t value)
{
	uint64_t l;

	if (parse_uint64_base(&l, value, 0) && l <= UINT32_MAX)
	{
		*out = l;
		return TRUE;
	}
	return FALSE;
}

/*
 * Described in header
 */
bool vici_parse_uint16(uint16_t *out, chunk_t value)
{
	uint64_t l;

	if (parse_uint64_base(&l, value, 0) && l <= UINT16_MAX)
	{
		*out = l;
		return TRUE;
	}
	return FALSE;
}

/**
 * Parse an unsigned 8-bit integer using the given base.
 */
static bool parse_uint8_base(uint8_t *out, chunk_t v, int base)
{
	uint64_t l;

	if (parse_uint64_base(&l, v, base) && l <= UINT8_MAX)
	{
		*out = l;
		return TRUE;
	}
	return FALSE;
}

/*
 * Described in header
 */
bool vici_parse_uint8(uint8_t *out, chunk_t value)
{
	return parse_uint8_base(out, value, 0);
}

/*
 * Described in header
 */
bool vici_parse_uint8_bin(uint8_t *out, chunk_t value)
{
	return parse_uint8_base(out, value, 2);
}

/*
 * Described in header
 */
bool vici_parse_time(uint64_t *out, chunk_t value)
{
	char buf[32], *end;
	uint64_t l;

	if (!vici_stringify(value, buf, sizeof(buf)))
	{
		return FALSE;
	}

	if (!uint64_from_string(buf, &end, 10, &l))
	{
		return FALSE;
	}
	while (*end == ' ')
	{
		end++;
	}
	switch (*end)
	{
		case 'd':
		case 'D':
			if (__builtin_mul_overflow(l, 24, &l))
			{
				return FALSE;
			}
			/* fall */
		case 'h':
		case 'H':
			if (__builtin_mul_overflow(l, 60, &l))
			{
				return FALSE;
			}
			/* fall */
		case 'm':
		case 'M':
			if (__builtin_mul_overflow(l, 60, &l))
			{
				return FALSE;
			}
			/* fall */
		case 's':
		case 'S':
			end++;
			break;
		case '\0':
			break;
		default:
			return FALSE;
	}
	if (*end)
	{
		return FALSE;
	}
	*out = l;
	return TRUE;
}

/*
 * Described in header
 */
bool vici_parse_time32(uint32_t *out, chunk_t value)
{
	uint64_t time;

	if (vici_parse_time(&time, value) && time <= UINT32_MAX)
	{
		*out = time;
		return TRUE;
	}
	return FALSE;
}

/*
 * Described in header
 */
bool vici_parse_map(vici_enum_map_t *map, int count, int *out, chunk_t v)
{
	char buf[BUF_LEN];
	int i;

	if (!vici_stringify(v, buf, sizeof(buf)))
	{
		return FALSE;
	}
	for (i = 0; i < count; i++)
	{
		if (strcaseeq(map[i].str, buf))
		{
			*out = map[i].d;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * Described in header
 */
bool vici_parse_rules(vici_parse_rule_t *rules, int count, char *name,
					  chunk_t value, vici_message_t **reply)
{
	bool ret = FALSE;
	int i;

	for (i = 0; i < count; i++)
	{
		if (streq(name, rules[i].name))
		{
			if (rules[i].parse)
			{
				ret = rules[i].parse(rules[i].out, value);
			}
			if (!ret)
			{
				*reply = vici_create_reply("invalid value for: %s", name);
			}
			return ret;
		}
	}
	*reply = vici_create_reply("unknown option: %s", name);
	return ret;
}
