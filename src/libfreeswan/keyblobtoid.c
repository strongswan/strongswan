/*
 * generate printable key IDs
 * Copyright (C) 2002  Henry Spencer.
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
 *
 * RCSID $Id$
 */
#include "internal.h"
#include "freeswan.h"

/*
 - keyblobtoid - generate a printable key ID from an RFC 2537/3110 key blob
 * Current algorithm is just to use first nine base64 digits.
 */
size_t
keyblobtoid(src, srclen, dst, dstlen)
const unsigned char *src;
size_t srclen;
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	char buf[KEYID_BUF];
	size_t ret;
#	define	NDIG	9

	if (srclen < (NDIG*6 + 7)/8) {
		strcpy(buf, "?len= ?");
		buf[5] = '0' + srclen;
		ret = 0;
	} else {
		(void) datatot(src, srclen, 64, buf, NDIG+1);
		ret = NDIG+1;
	}

	if (dstlen > 0) {
		if (strlen(buf)+1 > dstlen)
			*(buf + dstlen - 1) = '\0';
		strcpy(dst, buf);
	}
	return ret;
}

/*
 - splitkeytoid - generate a printable key ID from exponent/modulus pair
 * Just constructs the beginnings of a key blob and calls keyblobtoid().
 */
size_t
splitkeytoid(e, elen, m, mlen, dst, dstlen)
const unsigned char *e;
size_t elen;
const unsigned char *m;
size_t mlen;
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	unsigned char buf[KEYID_BUF];	/* ample room */
	unsigned char *bufend = buf + sizeof(buf);
	unsigned char *p;
	size_t n;

	p = buf;
	if (elen <= 255)
		*p++ = elen;
	else if ((elen &~ 0xffff) == 0) {
		*p++ = 0;
		*p++ = (elen>>8) & 0xff;
		*p++ = elen & 0xff;
	} else
		return 0;	/* unrepresentable exponent length */

	n = bufend - p;
	if (elen < n)
		n = elen;
	memcpy(p, e, n);
	p += n;

	n = bufend - p;
	if (n > 0) {
		if (mlen < n)
			n = mlen;
		memcpy(p, m, n);
		p += n;
	}

	return keyblobtoid(buf, p - buf, dst, dstlen);
}



#ifdef KEYBLOBTOID_MAIN

#include <stdio.h>

void regress();

int
main(argc, argv)
int argc;
char *argv[];
{
	typedef unsigned char uc;
	uc hexblob[] = "\x01\x03\x85\xf2\xd6\x76\x9b\x03\x59\xb6\x21\x52";
	uc hexe[] = "\x03";
	uc hexm[] = "\x85\xf2\xd6\x76\x9b\x03\x59\xb6\x21\x52\xef\x85";
	char b64nine[] = "AQOF8tZ2m";
	char b64six[] = "AQOF8t";
	char buf[100];
	size_t n;
	char *b = b64nine;
	size_t bl = strlen(b) + 1;
	int st = 0;

	n = keyblobtoid(hexblob, strlen(hexblob), buf, sizeof(buf));
	if (n != bl) {
		fprintf(stderr, "%s: keyblobtoid returned %d not %d\n",
							argv[0], n, bl);
		st = 1;
	}
	if (strcmp(buf, b) != 0) {
		fprintf(stderr, "%s: keyblobtoid generated `%s' not `%s'\n",
							argv[0], buf, b);
		st = 1;
	}
	n = splitkeytoid(hexe, strlen(hexe), hexm, strlen(hexm), buf,
								sizeof(buf));
	if (n != bl) {
		fprintf(stderr, "%s: splitkeytoid returned %d not %d\n",
							argv[0], n, bl);
		st = 1;
	}
	if (strcmp(buf, b) != 0) {
		fprintf(stderr, "%s: splitkeytoid generated `%s' not `%s'\n",
							argv[0], buf, b);
		st = 1;
	}
	exit(st);
}

#endif /* KEYBLOBTOID_MAIN */
