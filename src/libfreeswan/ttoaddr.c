/*
 * conversion from text forms of addresses to internal ones
 * Copyright (C) 2000  Henry Spencer.
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
#include <sys/socket.h>

#include "internal.h"
#include "freeswan.h"

/*
 * Legal ASCII characters in a domain name.  Underscore technically is not,
 * but is a common misunderstanding.  Non-ASCII characters are simply
 * exempted from checking at the moment, to allow for UTF-8 encoded stuff;
 * the purpose of this check is merely to catch blatant errors.
 */
static const char namechars[] = "abcdefghijklmnopqrstuvwxyz0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.";
#define	ISASCII(c)	(((c) & 0x80) == 0)

static err_t tryname(const char *, size_t, int, int, ip_address *);
static err_t tryhex(const char *, size_t, int, ip_address *);
static err_t trydotted(const char *, size_t, ip_address *);
static err_t getbyte(const char **, const char *, int *);
static err_t colon(const char *, size_t, ip_address *);
static err_t getpiece(const char **, const char *, unsigned *);

/*
 - ttoaddr - convert text name or dotted-decimal address to binary address
 */
err_t				/* NULL for success, else string literal */
ttoaddr(src, srclen, af, dst)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
int af;				/* address family */
ip_address *dst;
{
	err_t oops;
#	define	HEXLEN	10	/* strlen("0x11223344") */
	int nultermd;

	if (srclen == 0) {
		srclen = strlen(src);
		if (srclen == 0)
			return "empty string";
		nultermd = 1;
	} else
		nultermd = 0;	/* at least, not *known* to be terminated */

	switch (af) {
	case AF_INET:
	case AF_INET6:
	case 0:                  /* guess */
		break;
	    
	default:
		return "invalid address family";
	}

	if (af == AF_INET && srclen == HEXLEN && *src == '0') {
		if (*(src+1) == 'x' || *(src+1) == 'X')
			return tryhex(src+2, srclen-2, 'x', dst);
		if (*(src+1) == 'h' || *(src+1) == 'H')
			return tryhex(src+2, srclen-2, 'h', dst);
	}

	if (memchr(src, ':', srclen) != NULL) {
	    if(af == 0)
	    {
		af = AF_INET6;
	    }
	    
		if (af != AF_INET6)
			return "non-ipv6 address may not contain `:'";
		return colon(src, srclen, dst);
	}

	if (af == 0 || af == AF_INET) {
		oops = trydotted(src, srclen, dst);
		if (oops == NULL)
			return NULL;		/* it worked */
		if (*oops != '?')
			return oops;		/* probably meant as d-d */
	}

	return tryname(src, srclen, nultermd, af, dst);
}

/*
 - tnatoaddr - convert text numeric address (only) to binary address
 */
err_t				/* NULL for success, else string literal */
tnatoaddr(src, srclen, af, dst)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
int af;				/* address family */
ip_address *dst;
{
	err_t oops;

	if (srclen == 0) {
		srclen = strlen(src);
		if (srclen == 0)
			return "empty string";
	}

	switch (af) {
	case 0:  /* guess */
	        oops = colon(src, srclen, dst);
		if(oops == NULL)
		{
		    return NULL;
		}
		oops = trydotted(src, srclen, dst);
		if(oops == NULL)
		{
		    return NULL;
		}
		return "does not appear to be either IPv4 or IPv6 numeric address";
		break;
	    
	case AF_INET6:
		return colon(src, srclen, dst);
		break;
	case AF_INET:
		oops = trydotted(src, srclen, dst);
		if (oops == NULL)
			return NULL;		/* it worked */
		if (*oops != '?')
			return oops;		/* probably meant as d-d */
		return "does not appear to be numeric address";
		break;
	default:
		return "unknown address family in tnatoaddr";
		break;
	}
}

/*
 - tryname - try it as a name
 * Slightly complicated by lack of reliable NUL termination in source.
 */
static err_t
tryname(src, srclen, nultermd, af, dst)
const char *src;
size_t srclen;
int nultermd;			/* is it known to be NUL-terminated? */
int af;
ip_address *dst;
{
	struct hostent *h;
	struct netent *ne = NULL;
	char namebuf[100];	/* enough for most DNS names */
	const char *cp;
	char *p = namebuf;
	size_t n;

	for (cp = src, n = srclen; n > 0; cp++, n--)
		if (ISASCII(*cp) && strchr(namechars, *cp) == NULL)
			return "illegal (non-DNS-name) character in name";

	if (nultermd)
		cp = src;
	else {
		if (srclen+1 > sizeof(namebuf)) {
			p = (char *) MALLOC(srclen+1);
			if (p == NULL)
				return "unable to get temporary space for name";
		}
		p[0] = '\0';	/* strncpy semantics are wrong */
		strncat(p, src, srclen);
		cp = (const char *)p;
	}

	h = gethostbyname2(cp, af);
	if (h == NULL && af == AF_INET)
		ne = getnetbyname(cp);
	if (p != namebuf)
		FREE(p);
	if (h == NULL && ne == NULL)
		return "does not look numeric and name lookup failed";

	if (h != NULL) {
		if (h->h_addrtype != af)
			return "address-type mismatch from gethostbyname2!!!";
		return initaddr((unsigned char *)h->h_addr, h->h_length, af, dst);
	} else {
		if (ne->n_addrtype != af)
			return "address-type mismatch from getnetbyname!!!";
		ne->n_net = htonl(ne->n_net);
		return initaddr((unsigned char *)&ne->n_net, sizeof(ne->n_net),
								af, dst);
	}
}

/*
 - tryhex - try conversion as an eight-digit hex number (AF_INET only)
 */
static err_t
tryhex(src, srclen, flavor, dst)
const char *src;
size_t srclen;			/* should be 8 */
int flavor;			/* 'x' for network order, 'h' for host order */
ip_address *dst;
{
	err_t oops;
	unsigned long ul;
	union {
		uint32_t addr;
		unsigned char buf[4];
	} u;

	if (srclen != 8)
		return "internal error, tryhex called with bad length";

	oops = ttoul(src, srclen, 16, &ul);
	if (oops != NULL)
		return oops;

	u.addr = (flavor == 'h') ? ul : htonl(ul);
	return initaddr(u.buf, sizeof(u.buf), AF_INET, dst);
}

/*
 - trydotted - try conversion as dotted decimal (AF_INET only)
 *
 * If the first char of a complaint is '?', that means "didn't look like
 * dotted decimal at all".
 */
static err_t
trydotted(src, srclen, dst)
const char *src;
size_t srclen;
ip_address *dst;
{
	const char *stop = src + srclen;	/* just past end */
	int byte;
	err_t oops;
#	define	NBYTES	4
	unsigned char buf[NBYTES];
	int i;

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < NBYTES && src < stop; i++) {
		oops = getbyte(&src, stop, &byte);
		if (oops != NULL) {
			if (*oops != '?')
				return oops;	/* bad number */
			if (i > 1)
				return oops+1;	/* failed number */
			return oops;		/* with leading '?' */
		}
		buf[i] = byte;
		if (i < 3 && src < stop && *src++ != '.') {
			if (i == 0)
				return "?syntax error in dotted-decimal address";
			else
				return "syntax error in dotted-decimal address";
		}
	}
	if (src != stop)
		return "extra garbage on end of dotted-decimal address";

	return initaddr(buf, sizeof(buf), AF_INET, dst);
}

/*
 - getbyte - try to scan a byte in dotted decimal
 * A subtlety here is that all this arithmetic on ASCII digits really is
 * highly portable -- ANSI C guarantees that digits 0-9 are contiguous.
 * It's easier to just do it ourselves than set up for a call to ttoul().
 *
 * If the first char of a complaint is '?', that means "didn't look like a
 * number at all".
 */
err_t
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

/*
 - colon - convert IPv6 "numeric" address
 */
static err_t
colon(src, srclen, dst)
const char *src;
size_t srclen;			/* known to be >0 */
ip_address *dst;
{
	const char *stop = src + srclen;	/* just past end */
	unsigned piece = 0;
	int gapat;		/* where was empty piece seen */
	err_t oops;
#	define	NPIECES	8
	unsigned char buf[NPIECES*2];	/* short may have wrong byte order */
	int i;
	int j;
#	define	IT	"IPv6 numeric address"
	int naftergap;

	/* leading or trailing :: becomes single empty field */
	if (*src == ':') {		/* legal only if leading :: */
		if (srclen == 1 || *(src+1) != ':')
			return "illegal leading `:' in " IT;
		if (srclen == 2) {
			unspecaddr(AF_INET6, dst);
			return NULL;
		}
		src++;		/* past first but not second */
		srclen--;
	}
	if (*(stop-1) == ':') {		/* legal only if trailing :: */
		if (srclen == 1 || *(stop-2) != ':')
			return "illegal trailing `:' in " IT;
		srclen--;		/* leave one */
	}

	gapat = -1;
	for (i = 0; i < NPIECES && src < stop; i++) {
		oops = getpiece(&src, stop, &piece);
		if (oops != NULL && *oops == ':') {	/* empty field */
			if (gapat >= 0)
				return "more than one :: in " IT;
			gapat = i;
		} else if (oops != NULL)
			return oops;
		buf[2*i] = piece >> 8;
		buf[2*i + 1] = piece & 0xff;
		if (i < NPIECES-1) {	/* there should be more input */
			if (src == stop && gapat < 0)
				return IT " ends prematurely";
			if (src != stop && *src++ != ':')
				return "syntax error in " IT;
		}
	}
	if (src != stop)
		return "extra garbage on end of " IT;

	if (gapat < 0 && i < NPIECES)	/* should have been caught earlier */
		return "incomplete " IT " (internal error)";
	if (gapat >= 0 && i == NPIECES)
		return "non-abbreviating empty field in " IT;
	if (gapat >= 0) {
		naftergap = i - (gapat + 1);
		for (i--, j = NPIECES-1; naftergap > 0; i--, j--, naftergap--) {
			buf[2*j] = buf[2*i];
			buf[2*j + 1] = buf[2*i + 1];
		}
		for (; j >= gapat; j--)
			buf[2*j] = buf[2*j + 1] = 0;
	}

	return initaddr(buf, sizeof(buf), AF_INET6, dst);
}

/*
 - getpiece - try to scan one 16-bit piece of an IPv6 address
 */
err_t				/* ":" means "empty field seen" */
getpiece(srcp, stop, retp)
const char **srcp;		/* *srcp is updated */
const char *stop;		/* first untouchable char */
unsigned *retp;			/* return-value pointer */
{
	const char *p;
#	define	NDIG	4
	int d;
	unsigned long ret;
	err_t oops;

	if (*srcp >= stop || **srcp == ':') {	/* empty field */
		*retp = 0;
		return ":";
	}

	p = *srcp;
	d = 0;
	while (p < stop && d < NDIG && isxdigit(*p)) {
		p++;
		d++;
	}
	if (d == 0)
		return "non-hex field in IPv6 numeric address";
	if (p < stop && d == NDIG && isxdigit(*p))
		return "field in IPv6 numeric address longer than 4 hex digits";

	oops = ttoul(*srcp, d, 16, &ret);
	if (oops != NULL)	/* shouldn't happen, really... */
		return oops;

	*srcp = p;
	*retp = ret;
	return NULL;
}
