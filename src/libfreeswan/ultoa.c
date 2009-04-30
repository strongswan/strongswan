/*
 * convert unsigned long to ASCII
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
 - ultoa - convert unsigned long to decimal ASCII
 */
size_t				/* length required for full conversion */
ultoa(n, base, dst, dstlen)
unsigned long n;
int base;
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	char buf[3*sizeof(unsigned long) + 1];
	char *bufend = buf + sizeof(buf);
	size_t len;
	char *p;
	static char hex[] = "0123456789abcdef";

	p = bufend;
	*--p = '\0';
	if (base == 10) {
		do {
			*--p = n%10 + '0';
			n /= 10;
		} while (n != 0);
	} else if (base == 16) {
		do {
			*--p = hex[n&0xf];
			n >>= 4;
		} while (n != 0);
		*--p = 'x';
		*--p = '0';
	} else if (base == 8) {
		do {
			*--p = (n&07) + '0';
			n >>= 3;
		} while (n != 0);
		*--p = '0';
	} else
		*--p = '?';

	len = bufend - p;

	if (dstlen > 0) {
		if (len > dstlen)
			*(p + dstlen - 1) = '\0';
		strcpy(dst, p);
	}
	return len;
}
