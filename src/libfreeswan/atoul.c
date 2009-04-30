/*
 * convert from ASCII form of unsigned long to binary
 * Copyright (C) 1998, 1999  Henry Spencer.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include "internal.h"
#include "freeswan.h"

/*
 - atoul - convert ASCII substring to unsigned long number
 */
const char *			/* NULL for success, else string literal */
atoul(src, srclen, base, resultp)
const char *src;
size_t srclen;			/* 0 means strlen(src) */
int base;			/* 0 means figure it out */
unsigned long *resultp;
{
	const char *stop;
	static char hex[] = "0123456789abcdef";
	static char uchex[] = "0123456789ABCDEF";
	int d;
	char c;
	char *p;
	unsigned long r;
	unsigned long rlimit;
	int dlimit;

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";

	if (base == 0 || base == 13) {
		if (srclen > 2 && *src == '0' && CIEQ(*(src+1), 'x'))
			return atoul(src+2, srclen-2, 16, resultp);
		if (srclen > 1 && *src == '0' && base != 13)
			return atoul(src+1, srclen-1, 8, resultp);
		return atoul(src, srclen, 10, resultp);
	}
	if (base != 8 && base != 10 && base != 16)
		return "unsupported number base";

	r = 0;
	stop = src + srclen;
	if (base == 16) {
		while (src < stop) {
			c = *src++;
			p = strchr(hex, c);
			if (p != NULL)
				d = p - hex;
			else {
				p = strchr(uchex, c);
				if (p == NULL)
					return "non-hex-digit in hex number";
				d = p - uchex;
			}
			r = (r << 4) | d;
		}
		/* defer length check to catch invalid digits first */
		if (srclen > sizeof(unsigned long) * 2)
			return "hex number too long";
	} else {
		rlimit = ULONG_MAX / base;
		dlimit = (int)(ULONG_MAX - rlimit*base);
		while (src < stop) {
			c = *src++;
			d = c - '0';
			if (d < 0 || d >= base)
				return "non-digit in number";
			if (r > rlimit || (r == rlimit && d > dlimit))
				return "unsigned-long overflow";
			r = r*base + d;
		}
	}

	*resultp = r;
	return NULL;
}
