/*
 * conversion from ASCII forms of addresses to internal ones
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
 * Define NOLEADINGZEROS to interpret 032 as an error, not as 32.  There
 * is deliberately no way to interpret it as 26 (i.e., as octal).
 */

/*
 * Legal characters in a domain name.  Underscore technically is not,
 * but is a common misunderstanding.
 */
static const char namechars[] = "abcdefghijklmnopqrstuvwxyz0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.";

static const char *try8hex(const char *, size_t, struct in_addr *);
static const char *try8hosthex(const char *, size_t, struct in_addr *);
static const char *trydotted(const char *, size_t, struct in_addr *);
static const char *getbyte(const char **, const char *, int *);

/*
 - atoaddr - convert ASCII name or dotted-decimal address to binary address
 */
const char *			/* NULL for success, else string literal */
atoaddr(src, srclen, addrp)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
struct in_addr *addrp;
{
	struct hostent *h;
	struct netent *ne = NULL;
	const char *oops;
#	define	HEXLEN	10	/* strlen("0x11223344") */
#	ifndef ATOADDRBUF
#	define	ATOADDRBUF	100
#	endif
	char namebuf[ATOADDRBUF];
	char *p = namebuf;
	char *q;

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";

	/* might it be hex? */
	if (srclen == HEXLEN && *src == '0' && CIEQ(*(src+1), 'x'))
		return try8hex(src+2, srclen-2, addrp);
	if (srclen == HEXLEN && *src == '0' && CIEQ(*(src+1), 'h'))
		return try8hosthex(src+2, srclen-2, addrp);

	/* try it as dotted decimal */
	oops = trydotted(src, srclen, addrp);
	if (oops == NULL)
		return NULL;		/* it worked */
	if (*oops != '?')
		return oops;		/* it *was* probably meant as a d.q. */

	/* try it as a name -- first, NUL-terminate it */
	if (srclen > sizeof(namebuf)-1) {
		p = (char *) MALLOC(srclen+1);
		if (p == NULL)
			return "unable to allocate temporary space for name";
	}
	p[0] = '\0';
	strncat(p, src, srclen);

	/* next, check that it's a vaguely legal name */
	for (q = p; *q != '\0'; q++)
		if (!isprint(*q))
			return "unprintable character in name";
	if (strspn(p, namechars) != srclen)
		return "illegal (non-DNS-name) character in name";

	/* try as host name, failing that as /etc/networks network name */
	h = gethostbyname(p);
	if (h == NULL)
		ne = getnetbyname(p);
	if (p != namebuf)
		FREE(p);
	if (h == NULL && ne == NULL)
		return "name lookup failed";

	if (h != NULL)
		memcpy(&addrp->s_addr, h->h_addr, sizeof(addrp->s_addr));
	else
		addrp->s_addr = htonl(ne->n_net);
	return NULL;
}

/*
 - try8hosthex - try conversion as an eight-digit host-order hex number
 */
const char *			/* NULL for success, else string literal */
try8hosthex(src, srclen, addrp)
const char *src;
size_t srclen;			/* should be 8 */
struct in_addr *addrp;
{
	const char *oops;
	unsigned long addr;

	if (srclen != 8)
		return "internal error, try8hex called with bad length";

	oops = atoul(src, srclen, 16, &addr);
	if (oops != NULL)
		return oops;

	addrp->s_addr = addr;
	return NULL;
}

/*
 - try8hex - try conversion as an eight-digit network-order hex number
 */
const char *			/* NULL for success, else string literal */
try8hex(src, srclen, addrp)
const char *src;
size_t srclen;			/* should be 8 */
struct in_addr *addrp;
{
	const char *oops;

	oops = try8hosthex(src, srclen, addrp);
	if (oops != NULL)
		return oops;

	addrp->s_addr = htonl(addrp->s_addr);
	return NULL;
}

/*
 - trydotted - try conversion as dotted decimal
 *
 * If the first char of a complaint is '?', that means "didn't look like
 * dotted decimal at all".
 */
const char *			/* NULL for success, else string literal */
trydotted(src, srclen, addrp)
const char *src;
size_t srclen;
struct in_addr *addrp;
{
	const char *stop = src + srclen;	/* just past end */
	int byte;
	const char *oops;
	unsigned long addr;
	int i;
#	define	NBYTES	4
#	define	BYTE	8

	addr = 0;
	for (i = 0; i < NBYTES && src < stop; i++) {
		oops = getbyte(&src, stop, &byte);
		if (oops != NULL) {
			if (*oops != '?')
				return oops;	/* bad number */
			if (i > 1)
				return oops+1;	/* failed number */
			return oops;		/* with leading '?' */
		}
		addr = (addr << BYTE) | byte;
		if (i < 3 && src < stop && *src++ != '.') {
			if (i == 0)
				return "?syntax error in dotted-decimal address";
			else
				return "syntax error in dotted-decimal address";
		}
	}
	addr <<= (NBYTES - i) * BYTE;
	if (src != stop)
		return "extra garbage on end of dotted-decimal address";

	addrp->s_addr = htonl(addr);
	return NULL;
}

/*
 - getbyte - try to scan a byte in dotted decimal
 * A subtlety here is that all this arithmetic on ASCII digits really is
 * highly portable -- ANSI C guarantees that digits 0-9 are contiguous.
 * It's easier to just do it ourselves than set up for a call to atoul().
 *
 * If the first char of a complaint is '?', that means "didn't look like a
 * number at all".
 */
const char *			/* NULL for success, else string literal */
getbyte(srcp, stop, retp)
const char **srcp;		/* *srcp is updated */
const char *stop;		/* first untouchable char */
int *retp;			/* return-value pointer */
{
	char c;
	const char *p;
	int no;

	if (*srcp >= stop)
		return "?empty number in dotted-decimal address";

	if (stop - *srcp >= 3 && **srcp == '0' && CIEQ(*(*srcp+1), 'x'))
		return "hex numbers not supported in dotted-decimal addresses";
#ifdef NOLEADINGZEROS
	if (stop - *srcp >= 2 && **srcp == '0' && isdigit(*(*srcp+1)))
		return "octal numbers not supported in dotted-decimal addresses";
#endif /* NOLEADINGZEROS */

	/* must be decimal, if it's numeric at all */
	no = 0;
	p = *srcp;
	while (p < stop && no <= 255 && (c = *p) >= '0' && c <= '9') {
		no = no*10 + (c - '0');
		p++;
	}
	if (p == *srcp)
		return "?non-numeric component in dotted-decimal address";
	*srcp = p;
	if (no > 255)
		return "byte overflow in dotted-decimal address";
	*retp = no;
	return NULL;
}
