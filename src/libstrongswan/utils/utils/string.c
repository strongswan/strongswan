/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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

#include <utils/utils.h>

/**
 * Described in header.
 */
char* translate(char *str, const char *from, const char *to)
{
	char *pos = str;
	if (strlen(from) != strlen(to))
	{
		return str;
	}
	while (pos && *pos)
	{
		char *match;
		if ((match = strchr(from, *pos)) != NULL)
		{
			*pos = to[match - from];
		}
		pos++;
	}
	return str;
}

/**
 * Described in header.
 */
char* strreplace(const char *str, const char *search, const char *replace)
{
	size_t len, slen, rlen, count = 0;
	char *res, *pos, *found = NULL, *dst;

	if (!str || !*str || !search || !*search || !replace)
	{
		return (char*)str;
	}
	slen = strlen(search);
	rlen = strlen(replace);
	if (slen != rlen)
	{
		for (pos = (char*)str; (pos = strstr(pos, search)); pos += slen)
		{
			found = pos;
			count++;
		}
		if (!count)
		{
			return (char*)str;
		}
		len = (found - str) + strlen(found) + count * (rlen - slen);
	}
	else
	{
		len = strlen(str);
	}
	found = strstr(str, search);
	if (!found)
	{
		return (char*)str;
	}
	dst = res = malloc(len + 1);
	pos = (char*)str;
	do
	{
		len = found - pos;
		memcpy(dst, pos, len);
		dst += len;
		memcpy(dst, replace, rlen);
		dst += rlen;
		pos = found + slen;
	}
	while ((found = strstr(pos, search)));
	strcpy(dst, pos);
	return res;
}

/**
 * Extract a unicode character from a UTF-8 string and update the pointer to point to the next UTF-8 character.
 * In case of error, return the invalid character 0xFFFF
 */
static char32_t extract_char32_utf8(const char** str, const char* end)
{
	const char* rstr = *str;
	if ((*rstr & 0x80) == 0)
	{
		(*str)++;
		return *rstr;
	}
	else if ((*rstr & 0xE0) == 0xC0)
	{
		*str = *str + 2;
		if (rstr + 1 < end) {
			return (((unsigned char)*rstr & ~0xE0) << 6) |
					((unsigned char)*(rstr + 1) & 0x3F) ;
		} else {
			return 0xFFFF;
		}
	}
	else if ((*rstr & 0xF0) == 0xE0)
	{
		*str = *str + 3;
		if (rstr + 2 < end) {
			return ((((unsigned char)*rstr & 0xF) << 12) |
					(((unsigned char)*(rstr + 1) & 0x3F) << 6) |
					((unsigned char)*(rstr + 2) & 0x3F));
		} else {
			return 0xFFFF;
		}
	}
	else if ((*rstr & 0xF8) == 0xF0)
	{
		*str = *str + 4;
		if (rstr + 3 < end) {
			return (((char32_t)(unsigned char)*rstr & 0x7) << 18) |
					(((char32_t)(unsigned char)*(rstr + 1) & 0x3F) << 12) |
					(((char32_t)(unsigned char)*(rstr + 2) & 0x3F) << 6) |
					(((char32_t)(unsigned char)*(rstr + 3) & 0x3F));
		} else {
			return 0xFFFF;
		}
	}
	else {
		return 0xFFFF;
	}
}

/**
 * Extract a unicode character from a UTF-16 big endian string and update the pointer to point to the next UTF-16 character.
 * In case of error, return the invalid character 0xFFFF
 */
static char32_t extract_char32_utf16(const char16_t** str, const char16_t* end)
{
	const char16_t* rstr = *str;
	char16_t rstr0 = ntohs(*rstr);
	if (rstr0 < 0xD800 || rstr0 >= 0xE000 ) {
		++(*str);
		return rstr0;
	} else if ((rstr0 & 0xFC00) == 0xD800){
		*str += 2;
		if ((rstr + 1) < end) {
			char16_t rstr1 = ntohs(*(rstr + 1));
			return ((rstr0 & 0x3FF) + 0x40) << 10  | (rstr1 & 0x3FF);
		} else {
			return 0xFFFF;
		}
	} else {
		++(*str);
		return 0xFFFF;
	}
}


/* FIXME: this implementation should not depend on the length of secret data. We do not know if some of the strings is secret.
 * We should not depend or value of secret data, we might leak it. */


/**
 * See the header
 */
bool strutfwcscmp(const char *str1, size_t len1, const char16_t *str2, size_t len2)
{
	char32_t c1, c2;
	const char* istr1 = str1;
	const char* const str1_end = str1 + len1;
	const char16_t* istr2 = str2;
	const char16_t* const str2_end = str2 + len2;
	bool match = true;
	while (istr1 < str1_end && istr2 < str2_end) {
		c1 = extract_char32_utf8(&istr1, str1_end);
		c2 = extract_char32_utf16(&istr2, str2_end);
		/* do not break from the loop!!! It would create a vulnerability, a timing attack, an attacker that provides the value of str2
		 * could gain the value of str1 by trying with different values and measuring response times */
		match = match && (c1 == c2);
	}
	match = match && istr1 >= str1_end && istr2 >= str2_end;
	return match;
}

