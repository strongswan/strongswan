/*
 * Copyright (C) 2008-2009 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "chunk.h"
#include "debug.h"

/* required for chunk_hash */
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__))
#define get16bits(d) (*((const u_int16_t*)(d)))
#endif
#if !defined (get16bits)
#define get16bits(d) ((((u_int32_t)(((const u_int8_t*)(d))[1])) << 8)\
                      + (u_int32_t)(((const u_int8_t*)(d))[0]) )
#endif

/**
 * Empty chunk.
 */
chunk_t chunk_empty = { NULL, 0 };

/**
 * Described in header.
 */
chunk_t chunk_create_clone(u_char *ptr, chunk_t chunk)
{
	chunk_t clone = chunk_empty;

	if (chunk.ptr && chunk.len > 0)
	{
		clone.ptr = ptr;
		clone.len = chunk.len;
		memcpy(clone.ptr, chunk.ptr, chunk.len);
	}

	return clone;
}

/**
 * Described in header.
 */
size_t chunk_length(const char* mode, ...)
{
	va_list chunks;
	size_t length = 0;

	va_start(chunks, mode);
	while (TRUE)
	{
		switch (*mode++)
		{
			case 'm':
			case 'c':
			case 's':
			{
				chunk_t ch = va_arg(chunks, chunk_t);
				length += ch.len;
				continue;
			}
			default:
				break;
		}
		break;
	}
	va_end(chunks);
	return length;
}

/**
 * Described in header.
 */
chunk_t chunk_create_cat(u_char *ptr, const char* mode, ...)
{
	va_list chunks;
	chunk_t construct = chunk_create(ptr, 0);

	va_start(chunks, mode);
	while (TRUE)
	{
		bool free_chunk = FALSE, clear_chunk = FALSE;
		chunk_t ch;

		switch (*mode++)
		{
			case 's':
				clear_chunk = TRUE;
				/* FALL */
			case 'm':
				free_chunk = TRUE;
				/* FALL */
			case 'c':
				ch = va_arg(chunks, chunk_t);
				memcpy(ptr, ch.ptr, ch.len);
				ptr += ch.len;
				construct.len += ch.len;
				if (clear_chunk)
				{
					chunk_clear(&ch);
				}
				else if (free_chunk)
				{
					free(ch.ptr);
				}
				continue;
			default:
				break;
		}
		break;
	}
	va_end(chunks);

	return construct;
}

/**
 * Described in header.
 */
void chunk_split(chunk_t chunk, const char *mode, ...)
{
	va_list chunks;
	u_int len;
	chunk_t *ch;

	va_start(chunks, mode);
	while (TRUE)
	{
		if (*mode == '\0')
		{
			break;
		}
		len = va_arg(chunks, u_int);
		ch = va_arg(chunks, chunk_t*);
		/* a null chunk means skip len bytes */
		if (ch == NULL)
		{
			chunk = chunk_skip(chunk, len);
			continue;
		}
		switch (*mode++)
		{
			case 'm':
			{
				ch->len = min(chunk.len, len);
				if (ch->len)
				{
					ch->ptr = chunk.ptr;
				}
				else
				{
					ch->ptr = NULL;
				}
				chunk = chunk_skip(chunk, ch->len);
				continue;
			}
			case 'a':
			{
				ch->len = min(chunk.len, len);
				if (ch->len)
				{
					ch->ptr = malloc(ch->len);
					memcpy(ch->ptr, chunk.ptr, ch->len);
				}
				else
				{
					ch->ptr = NULL;
				}
				chunk = chunk_skip(chunk, ch->len);
				continue;
			}
			case 'c':
			{
				ch->len = min(ch->len, chunk.len);
				ch->len = min(ch->len, len);
				if (ch->len)
				{
					memcpy(ch->ptr, chunk.ptr, ch->len);
				}
				else
				{
					ch->ptr = NULL;
				}
				chunk = chunk_skip(chunk, ch->len);
				continue;
			}
			default:
				break;
		}
		break;
	}
	va_end(chunks);
}

/**
 * Described in header.
 */
bool chunk_write(chunk_t chunk, char *path, char *label, mode_t mask, bool force)
{
	mode_t oldmask;
	FILE *fd;
	bool good = FALSE;

	if (!force && access(path, F_OK) == 0)
	{
		DBG1(DBG_LIB, "  %s file '%s' already exists", label, path);
		return FALSE;
	}
	oldmask = umask(mask);
	fd = fopen(path, "w");
	if (fd)
	{
		if (fwrite(chunk.ptr, sizeof(u_char), chunk.len, fd) == chunk.len)
		{
			DBG1(DBG_LIB, "  written %s file '%s' (%d bytes)",
				 label, path, chunk.len);
			good = TRUE;
		}
		else
		{
			DBG1(DBG_LIB, "  writing %s file '%s' failed: %s",
				 label, path, strerror(errno));
		}
		fclose(fd);
	}
	else
	{
		DBG1(DBG_LIB, "  could not open %s file '%s': %s", label, path,
			 strerror(errno));
	}
	umask(oldmask);
	return good;
}


/** hex conversion digits */
static char hexdig_upper[] = "0123456789ABCDEF";
static char hexdig_lower[] = "0123456789abcdef";

/**
 * Described in header.
 */
chunk_t chunk_to_hex(chunk_t chunk, char *buf, bool uppercase)
{
	int i, len;
	char *hexdig = hexdig_lower;

	if (uppercase)
	{
		hexdig = hexdig_upper;
	}

	len = chunk.len * 2;
	if (!buf)
	{
		buf = malloc(len + 1);
	}
	buf[len] = '\0';

	for (i = 0; i < chunk.len; i++)
	{
		buf[i*2]   = hexdig[(chunk.ptr[i] >> 4) & 0xF];
		buf[i*2+1] = hexdig[(chunk.ptr[i]     ) & 0xF];
	}
	return chunk_create(buf, len);
}

/**
 * convert a signle hex character to its binary value
 */
static char hex2bin(char hex)
{
	switch (hex)
	{
		case '0' ... '9':
			return hex - '0';
		case 'A' ... 'F':
			return hex - 'A' + 10;
		case 'a' ... 'f':
			return hex - 'a' + 10;
		default:
			return 0;
	}
}

/**
 * Described in header.
 */
chunk_t chunk_from_hex(chunk_t hex, char *buf)
{
	int i, len;
	u_char *ptr;
	bool odd = FALSE;

   /* subtract the number of optional ':' separation characters */
	len = hex.len;
	ptr = hex.ptr;
	for (i = 0; i < hex.len; i++)
	{
		if (*ptr++ == ':')
		{
			len--;
		}
	}

	/* compute the number of binary bytes */
	if (len % 2)
	{
		odd = TRUE;
		len++;
	}
	len /= 2;

	/* allocate buffer memory unless provided by caller */
	if (!buf)
	{
		buf = malloc(len);
	}

	/* buffer is filled from the right */
	memset(buf, 0, len);
	hex.ptr += hex.len;

	for (i = len - 1; i >= 0; i--)
	{
		/* skip separation characters */
		if (*(--hex.ptr) == ':')
		{
			--hex.ptr;
		}
		buf[i] = hex2bin(*hex.ptr);
		if (i > 0 || !odd)
		{
			buf[i] |= hex2bin(*(--hex.ptr)) << 4;
		}
	}
	return chunk_create(buf, len);
}

/** base 64 conversion digits */
static char b64digits[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Described in header.
 */
chunk_t chunk_to_base64(chunk_t chunk, char *buf)
{
	int i, len;
	char *pos;

	len = chunk.len + ((3 - chunk.len % 3) % 3);
	if (!buf)
	{
		buf = malloc(len * 4 / 3 + 1);
	}
	pos = buf;
	for (i = 0; i < len; i+=3)
	{
		*pos++ = b64digits[chunk.ptr[i] >> 2];
		if (i+1 >= chunk.len)
		{
			*pos++ = b64digits[(chunk.ptr[i] & 0x03) << 4];
			*pos++ = '=';
			*pos++ = '=';
			break;
		}
		*pos++ = b64digits[((chunk.ptr[i] & 0x03) << 4) | (chunk.ptr[i+1] >> 4)];
		if (i+2 >= chunk.len)
		{
			*pos++ = b64digits[(chunk.ptr[i+1] & 0x0F) << 2];
			*pos++ = '=';
			break;
		}
		*pos++ = b64digits[((chunk.ptr[i+1] & 0x0F) << 2) | (chunk.ptr[i+2] >> 6)];
		*pos++ = b64digits[chunk.ptr[i+2] & 0x3F];
	}
	*pos = '\0';
	return chunk_create(buf, len * 4 / 3);
}

/**
 * convert a base 64 digit to its binary form (inversion of b64digits array)
 */
static int b642bin(char b64)
{
	switch (b64)
	{
		case 'A' ... 'Z':
			return b64 - 'A';
		case 'a' ... 'z':
			return ('Z' - 'A' + 1) + b64 - 'a';
		case '0' ... '9':
			return ('Z' - 'A' + 1) + ('z' - 'a' + 1) + b64 - '0';
		case '+':
		case '-':
			return 62;
		case '/':
		case '_':
			return 63;
		case '=':
			return 0;
		default:
			return -1;
	}
}

/**
 * Described in header.
 */
chunk_t chunk_from_base64(chunk_t base64, char *buf)
{
	u_char *pos, byte[4];
	int i, j, len, outlen;

	len = base64.len / 4 * 3;
	if (!buf)
	{
		buf = malloc(len);
	}
	pos = base64.ptr;
	outlen = 0;
	for (i = 0; i < len; i+=3)
	{
		outlen += 3;
		for (j = 0; j < 4; j++)
		{
			if (*pos == '=')
			{
				outlen--;
			}
			byte[j] = b642bin(*pos++);
		}
		buf[i] = (byte[0] << 2) | (byte[1] >> 4);
		buf[i+1] = (byte[1] << 4) | (byte[2] >> 2);
		buf[i+2] = (byte[2] << 6) | (byte[3]);
	}
	return chunk_create(buf, outlen);
}

/** base 32 conversion digits */
static char b32digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Described in header.
 */
chunk_t chunk_to_base32(chunk_t chunk, char *buf)
{
	int i, len;
	char *pos;

	len = chunk.len + ((5 - chunk.len % 5) % 5);
	if (!buf)
	{
		buf = malloc(len * 8 / 5 + 1);
	}
	pos = buf;
	for (i = 0; i < len; i+=5)
	{
		*pos++ = b32digits[chunk.ptr[i] >> 3];
		if (i+1 >= chunk.len)
		{
			*pos++ = b32digits[(chunk.ptr[i] & 0x07) << 2];
			memset(pos, '=', 6);
			pos += 6;
			break;
		}
		*pos++ = b32digits[((chunk.ptr[i] & 0x07) << 2) |
						   (chunk.ptr[i+1] >> 6)];
		*pos++ = b32digits[(chunk.ptr[i+1] & 0x3E) >> 1];
		if (i+2 >= chunk.len)
		{
			*pos++ = b32digits[(chunk.ptr[i+1] & 0x01) << 4];
			memset(pos, '=', 4);
			pos += 4;
			break;
		}
		*pos++ = b32digits[((chunk.ptr[i+1] & 0x01) << 4) |
						   (chunk.ptr[i+2] >> 4)];
		if (i+3 >= chunk.len)
		{
			*pos++ = b32digits[(chunk.ptr[i+2] & 0x0F) << 1];
			memset(pos, '=', 3);
			pos += 3;
			break;
		}
		*pos++ = b32digits[((chunk.ptr[i+2] & 0x0F) << 1) |
						   (chunk.ptr[i+3] >> 7)];
		*pos++ = b32digits[(chunk.ptr[i+3] & 0x7F) >> 2];
		if (i+4 >= chunk.len)
		{
			*pos++ = b32digits[(chunk.ptr[i+3] & 0x03) << 3];
			*pos++ = '=';
			break;
		}
		*pos++ = b32digits[((chunk.ptr[i+3] & 0x03) << 3) |
						   (chunk.ptr[i+4] >> 5)];
		*pos++ = b32digits[chunk.ptr[i+4] & 0x1F];
	}
	*pos = '\0';
	return chunk_create(buf, len * 8 / 5);
}

/**
 * Described in header.
 */
int chunk_compare(chunk_t a, chunk_t b)
{
	int compare_len = a.len - b.len;
	int len = (compare_len < 0)? a.len : b.len;

	if (compare_len != 0 || len == 0)
	{
		return compare_len;
	}
	return memcmp(a.ptr, b.ptr, len);
};


/**
 * Described in header.
 */
bool chunk_increment(chunk_t chunk)
{
	int i;

	for (i = chunk.len - 1; i >= 0; i--)
	{
		if (++chunk.ptr[i] != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Remove non-printable characters from a chunk.
 */
bool chunk_printable(chunk_t chunk, chunk_t *sane, char replace)
{
	bool printable = TRUE;
	int i;

	if (sane)
	{
		*sane = chunk_clone(chunk);
	}
	for (i = 0; i < chunk.len; i++)
	{
		if (!isprint(chunk.ptr[i]))
		{
			if (sane)
			{
				sane->ptr[i] = replace;
			}
			printable = FALSE;
		}
	}
	return printable;
}

/**
 * Described in header.
 *
 * The implementation is based on Paul Hsieh's SuperFastHash:
 *	 http://www.azillionmonkeys.com/qed/hash.html
 */
u_int32_t chunk_hash_inc(chunk_t chunk, u_int32_t hash)
{
	u_char *data = chunk.ptr;
	size_t len = chunk.len;
	u_int32_t tmp;
	int rem;

	if (!len || data == NULL)
	{
		return 0;
	}

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (; len > 0; --len)
	{
		hash += get16bits(data);
		tmp   = (get16bits(data + 2) << 11) ^ hash;
		hash  = (hash << 16) ^ tmp;
		data += 2 * sizeof(u_int16_t);
		hash += hash >> 11;
	}

	/* Handle end cases */
	switch (rem)
	{
		case 3:
		{
			hash += get16bits(data);
			hash ^= hash << 16;
			hash ^= data[sizeof(u_int16_t)] << 18;
			hash += hash >> 11;
			break;
		}
		case 2:
		{
			hash += get16bits(data);
			hash ^= hash << 11;
			hash += hash >> 17;
			break;
		}
		case 1:
		{
			hash += *data;
			hash ^= hash << 10;
			hash += hash >> 1;
			break;
		}
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

/**
 * Described in header.
 */
u_int32_t chunk_hash(chunk_t chunk)
{
	return chunk_hash_inc(chunk, chunk.len);
}

/**
 * Described in header.
 */
int chunk_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
					  const void *const *args)
{
	chunk_t *chunk = *((chunk_t**)(args[0]));
	bool first = TRUE;
	chunk_t copy = *chunk;
	int written = 0;

	if (!spec->hash)
	{
		u_int chunk_len = chunk->len;
		const void *new_args[] = {&chunk->ptr, &chunk_len};
		return mem_printf_hook(dst, len, spec, new_args);
	}

	while (copy.len > 0)
	{
		if (first)
		{
			first = FALSE;
		}
		else
		{
			written += print_in_hook(dst, len, ":");
		}
		written += print_in_hook(dst, len, "%02x", *copy.ptr++);
		copy.len--;
	}
	return written;
}
