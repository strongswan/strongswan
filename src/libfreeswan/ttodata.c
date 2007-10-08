/*
 * convert from text form of arbitrary data (e.g., keys) to binary
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
 *
 * RCSID $Id$
 */
#include "internal.h"
#include "freeswan.h"

/* converters and misc */
static int unhex(const char *, char *, size_t);
static int unb64(const char *, char *, size_t);
static int untext(const char *, char *, size_t);
static const char *badch(const char *, int, char *, size_t);

/* internal error codes for converters */
#define	SHORT	(-2)		/* internal buffer too short */
#define	BADPAD	(-3)		/* bad base64 padding */
#define	BADCH0	(-4)		/* invalid character 0 */
#define	BADCH1	(-5)		/* invalid character 1 */
#define	BADCH2	(-6)		/* invalid character 2 */
#define	BADCH3	(-7)		/* invalid character 3 */
#define	BADOFF(code) (BADCH0-(code))

/*
 - ttodatav - convert text to data, with verbose error reports
 * If some of this looks slightly odd, it's because it has changed
 * repeatedly (from the original atodata()) without a major rewrite.
 */
const char *			/* NULL on success, else literal or errp */
ttodatav(src, srclen, base, dst, dstlen, lenp, errp, errlen, flags)
const char *src;
size_t srclen;			/* 0 means apply strlen() */
int base;			/* 0 means figure it out */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
size_t *lenp;			/* where to record length (NULL is nowhere) */
char *errp;			/* error buffer */
size_t errlen;
unsigned int flags;
{
	size_t ingroup;	/* number of input bytes converted at once */
	char buf[4];		/* output from conversion */
	int nbytes;		/* size of output */
	int (*decode)(const char *, char *, size_t);
	char *stop;
	int ndone;
	int i;
	int underscoreok;
	int skipSpace = 0;

	if (srclen == 0)
		srclen = strlen(src);
	if (dstlen == 0)
		dst = buf;	/* point it somewhere valid */
	stop = dst + dstlen;

	if (base == 0) {
		if (srclen < 2)
			return "input too short to be valid";
		if (*src++ != '0')
			return "input does not begin with format prefix";
		switch (*src++) {
		case 'x':
		case 'X':
			base = 16;
			break;
		case 's':
		case 'S':
			base = 64;
			break;
		case 't':
		case 'T':
			base = 256;
			break;
		default:
			return "unknown format prefix";
		}
		srclen -= 2;
	}
	switch (base) {
	case 16:
		decode = unhex;
		underscoreok = 1;
		ingroup = 2;
		break;
	case 64:
		decode = unb64;
		underscoreok = 0;
		ingroup = 4;
		if(flags & TTODATAV_IGNORESPACE) {
			skipSpace = 1;
		}
		break;

	case 256:
		decode = untext;
		ingroup = 1;
		underscoreok = 0;
		break;
	default:
		return "unknown base";
	}

	/* proceed */
	ndone = 0;
	while (srclen > 0) {
		char stage[4];	/* staging area for group */
		size_t sl = 0;

		/* Grab ingroup characters into stage,
		 * squeezing out blanks if we are supposed to ignore them.
		 */
		for (sl = 0; sl < ingroup; src++, srclen--) {
			if (srclen == 0)
				return "input ends in mid-byte, perhaps truncated";
			else if (!(skipSpace && (*src == ' ' || *src == '\t')))
				stage[sl++] = *src;
		}
		
		nbytes = (*decode)(stage, buf, sizeof(buf));
		switch (nbytes) {
		case BADCH0:
		case BADCH1:
		case BADCH2:
		case BADCH3:
			return badch(stage, nbytes, errp, errlen);
		case SHORT:
			return "internal buffer too short (\"can't happen\")";
		case BADPAD:
			return "bad (non-zero) padding at end of base64 input";
		}
		if (nbytes <= 0)
			return "unknown internal error";
		for (i = 0; i < nbytes; i++) {
			if (dst < stop)
				*dst++ = buf[i];
			ndone++;
		}
		while (srclen >= 1 && skipSpace && (*src == ' ' || *src == '\t')){
			src++;
			srclen--;
		}
		if (underscoreok && srclen > 1 && *src == '_') {
			/* srclen > 1 means not last character */
			src++;
			srclen--;
		}
	}

	if (ndone == 0)
		return "no data bytes specified by input";
	if (lenp != NULL)
		*lenp = ndone;
	return NULL;
}

/*
 - ttodata - convert text to data
 */
const char *			/* NULL on success, else literal */
ttodata(src, srclen, base, dst, dstlen, lenp)
const char *src;
size_t srclen;			/* 0 means apply strlen() */
int base;			/* 0 means figure it out */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
size_t *lenp;			/* where to record length (NULL is nowhere) */
{
	return ttodatav(src, srclen, base, dst, dstlen, lenp, (char *)NULL,
			(size_t)0, TTODATAV_SPACECOUNTS);
}

/*
 - atodata - convert ASCII to data
 * backward-compatibility interface
 */
size_t				/* 0 for failure, true length for success */
atodata(src, srclen, dst, dstlen)
const char *src;
size_t srclen;
char *dst;
size_t dstlen;
{
	size_t len;
	const char *err;

	err = ttodata(src, srclen, 0, dst, dstlen, &len);
	if (err != NULL)
		return 0;
	return len;
}

/*
 - atobytes - convert ASCII to data bytes
 * another backward-compatibility interface
 */
const char *
atobytes(src, srclen, dst, dstlen, lenp)
const char *src;
size_t srclen;
char *dst;
size_t dstlen;
size_t *lenp;
{
	return ttodata(src, srclen, 0, dst, dstlen, lenp);
}

/*
 - unhex - convert two ASCII hex digits to byte
 */
static int		/* number of result bytes, or error code */
unhex(src, dst, dstlen)
const char *src;	/* known to be full length */
char *dst;
size_t dstlen;		/* not large enough is a failure */
{
	char *p;
	unsigned byte;
	static char hex[] = "0123456789abcdef";

	if (dstlen < 1)
		return SHORT;
	
	p = strchr(hex, *src);
	if (p == NULL)
		p = strchr(hex, tolower(*src));
	if (p == NULL)
		return BADCH0;
	byte = (p - hex) << 4;
	src++;

	p = strchr(hex, *src);
	if (p == NULL)
		p = strchr(hex, tolower(*src));
	if (p == NULL)
		return BADCH1;
	byte |= (p - hex);

	*dst = byte;
	return 1;
}

/*
 - unb64 - convert four ASCII base64 digits to three bytes
 * Note that a base64 digit group is padded out with '=' if it represents
 * less than three bytes:  one byte is dd==, two is ddd=, three is dddd.
 */
static int		/* number of result bytes, or error code */
unb64(src, dst, dstlen)
const char *src;	/* known to be full length */
char *dst;
size_t dstlen;
{
	char *p;
	unsigned byte1;
	unsigned byte2;
	static char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (dstlen < 3)
		return SHORT;

	p = strchr(base64, *src++);

	if (p == NULL)
		return BADCH0;
	byte1 = (p - base64) << 2;	/* first six bits */

	p = strchr(base64, *src++);
	if (p == NULL) {
		return BADCH1;
	}

	byte2 = p - base64;		/* next six:  two plus four */
	*dst++ = byte1 | (byte2 >> 4);
	byte1 = (byte2 & 0xf) << 4;

	p = strchr(base64, *src++);
	if (p == NULL) {
		if (*(src-1) == '=' && *src == '=') {
			if (byte1 != 0)		/* bad padding */
				return BADPAD;
			return 1;
		}
		return BADCH2;
	}

	byte2 = p - base64;		/* next six:  four plus two */
	*dst++ = byte1 | (byte2 >> 2);
	byte1 = (byte2 & 0x3) << 6;

	p = strchr(base64, *src++);
	if (p == NULL) {
		if (*(src-1) == '=') {
			if (byte1 != 0)		/* bad padding */
				return BADPAD;
			return 2;
		}
		return BADCH3;
	}
	byte2 = p - base64;		/* last six */
	*dst++ = byte1 | byte2;

	return 3;
}

/*
 - untext - convert one ASCII character to byte
 */
static int		/* number of result bytes, or error code */
untext(src, dst, dstlen)
const char *src;	/* known to be full length */
char *dst;
size_t dstlen;		/* not large enough is a failure */
{
	if (dstlen < 1)
		return SHORT;

	*dst = *src;
	return 1;
}

/*
 - badch - produce a nice complaint about an unknown character
 *
 * If the compiler complains that the array bigenough[] has a negative
 * size, that means the TTODATAV_BUF constant has been set too small.
 */
static const char *		/* literal or errp */
badch(src, errcode, errp, errlen)
const char *src;
int errcode;
char *errp;			/* might be NULL */
size_t errlen;
{
	static const char pre[] = "unknown character (`";
	static const char suf[] = "') in input";
	char buf[5];
#	define	REQD	(sizeof(pre) - 1 + sizeof(buf) - 1 + sizeof(suf))
	struct sizecheck {
		char bigenough[TTODATAV_BUF - REQD];	/* see above */
	};
	char ch;

	if (errp == NULL || errlen < REQD)
		return "unknown character in input";
	strcpy(errp, pre);
	ch = *(src + BADOFF(errcode));
	if (isprint(ch)) {
		buf[0] = ch;
		buf[1] = '\0';
	} else {
		buf[0] = '\\';
		buf[1] = ((ch & 0700) >> 6) + '0';
		buf[2] = ((ch & 0070) >> 3) + '0';
		buf[3] = ((ch & 0007) >> 0) + '0';
		buf[4] = '\0';
	}
	strcat(errp, buf);
	strcat(errp, suf);
	return (const char *)errp;
}



#ifdef TTODATA_MAIN

#include <stdio.h>

struct artab;
static void check(struct artab *r, char *buf, size_t n, err_t oops, int *status);
static void regress(char *pgm);
static void hexout(const char *s, size_t len, FILE *f);

/*
 - main - convert first argument to hex, or run regression
 */
int
main(int argc, char *argv[])
{
	char buf[1024];
	char buf2[1024];
	char err[512];
	size_t n;
	size_t i;
	char *p = buf;
	char *p2 = buf2;
	char *pgm = argv[0];
	const char *oops;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {0x<hex>|0s<base64>|-r}\n", pgm);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress(pgm);	/* should not return */
		fprintf(stderr, "%s: regress() returned?!?\n", pgm);
		exit(1);
	}

	oops = ttodatav(argv[1], 0, 0, buf, sizeof(buf), &n,
			err, sizeof(err), TTODATAV_IGNORESPACE);
	if (oops != NULL) {
		fprintf(stderr, "%s: ttodata error `%s' in `%s'\n", pgm,
								oops, argv[1]);
		exit(1);
	}

	if (n > sizeof(buf)) {
		p = (char *)malloc((size_t)n);
		if (p == NULL) {
			fprintf(stderr,
				"%s: unable to malloc %d bytes for result\n",
				pgm, n);
			exit(1);
		}
		oops = ttodata(argv[1], 0, 0, p, n, &n);
		if (oops != NULL) {
			fprintf(stderr, "%s: error `%s' in ttodata retry?!?\n",
								pgm, oops);
			exit(1);
		}
	}

	hexout(p, n, stdout);
	printf("\n");

	i = datatot(buf, n, 'h', buf2, sizeof(buf2));
	if (i == 0) {
		fprintf(stderr, "%s: datatot reports error in `%s'\n", pgm,
								argv[1]);
		exit(1);
	}

	if (i > sizeof(buf2)) {
		p2 = (char *)malloc((size_t)i);
		if (p == NULL) {
			fprintf(stderr,
				"%s: unable to malloc %d bytes for result\n",
				pgm, i);
			exit(1);
		}
		i = datatot(buf, n, 'h', p2, i);
		if (i == 0) {
			fprintf(stderr, "%s: error in datatoa retry?!?\n", pgm);
			exit(1);
		}
	}

	printf("%s\n", p2);

	exit(0);
}

/*
 - hexout - output an arbitrary-length string in hex
 */
static void
hexout(s, len, f)
const char *s;
size_t len;
FILE *f;
{
	size_t i;

	fprintf(f, "0x");
	for (i = 0; i < len; i++)
		fprintf(f, "%02x", (unsigned char)s[i]);
}

struct artab {
	int base;
#	    define IGNORESPACE_BIAS 1000
	char *ascii;		/* NULL for end */
	char *data;		/* NULL for error expected */
} atodatatab[] = {
	{ 0, "",			NULL, },
	{ 0, "0",			NULL, },
	{ 0, "0x",		NULL, },
	{ 0, "0xa",		NULL, },
	{ 0, "0xab",		"\xab", },
	{ 0, "0xabc",		NULL, },
	{ 0, "0xabcd",		"\xab\xcd", },
	{ 0, "0x0123456789",	"\x01\x23\x45\x67\x89", },
	{ 0, "0x01x",		NULL, },
	{ 0, "0xabcdef",		"\xab\xcd\xef", },
	{ 0, "0xABCDEF",		"\xab\xcd\xef", },
	{ 0, "0XaBc0eEd81f",	"\xab\xc0\xee\xd8\x1f", },
	{ 0, "0XaBc0_eEd8",	"\xab\xc0\xee\xd8", },
	{ 0, "0XaBc0_",		NULL, },
	{ 0, "0X_aBc0",		NULL, },
	{ 0, "0Xa_Bc0",		NULL, },
	{ 16, "aBc0eEd8",	"\xab\xc0\xee\xd8", },
	{ 0, "0s",		NULL, },
	{ 0, "0sA",		NULL, },
	{ 0, "0sBA",		NULL, },
	{ 0, "0sCBA",		NULL, },
	{ 0, "0sDCBA",		"\x0c\x20\x40", },
	{ 0, "0SDCBA",		"\x0c\x20\x40", },
	{ 0, "0sDA==",		"\x0c", },
	{ 0, "0sDC==",		NULL, },
	{ 0, "0sDCA=",		"\x0c\x20", },
	{ 0, "0sDCB=",		NULL, },
	{ 0, "0sDCAZ",		"\x0c\x20\x19", },
	{ 0, "0sDCAa",		"\x0c\x20\x1a", },
	{ 0, "0sDCAz",		"\x0c\x20\x33", },
	{ 0, "0sDCA0",		"\x0c\x20\x34", },
	{ 0, "0sDCA9",		"\x0c\x20\x3d", },
	{ 0, "0sDCA+",		"\x0c\x20\x3e", },
	{ 0, "0sDCA/",		"\x0c\x20\x3f", },
	{ 0, "0sAbraCadabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0s AbraCadabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sA braCadabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAb raCadabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbr aCadabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbra Cadabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraC adabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCa dabra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCad abra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCada bra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCadab ra+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCadabr a+",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCadabra +",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ IGNORESPACE_BIAS + 0, "0sAbraCadabra+ ",	"\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ 0, "0t",		NULL, },
	{ 0, "0tabc_xyz",		"abc_xyz", },
	{ 256, "abc_xyz",		"abc_xyz", },
	{ 0, NULL,		NULL, },
};

struct drtab {
	char *data;	/* input; NULL for end */
	char format;
	int buflen;	/* -1 means big buffer */
	int outlen;	/* -1 means strlen(ascii)+1 */
	char *ascii;	/* NULL for error expected */
} datatoatab[] = {
	{ "",			'x',	-1,	-1,	NULL, },
	{ "",			'X',	-1,	-1,	NULL, },
	{ "",			'n',	-1,	-1,	NULL, },
	{ "0",			'x',	-1,	-1,	"0x30", },
	{ "0",			'x',	0,	5,	"---", },
	{ "0",			'x',	1,	5,	"", },
	{ "0",			'x',	2,	5,	"0", },
	{ "0",			'x',	3,	5,	"0x", },
	{ "0",			'x',	4,	5,	"0x3", },
	{ "0",			'x',	5,	5,	"0x30", },
	{ "0",			'x',	6,	5,	"0x30", },
	{ "\xab\xcd",		'x',	-1,	-1,	"0xabcd", },
	{ "\x01\x23\x45\x67\x89",	'x',	-1,	-1,	"0x0123456789", },
	{ "\xab\xcd\xef",		'x',	-1,	-1,	"0xabcdef", },
	{ "\xab\xc0\xee\xd8\x1f",	'x',	-1,	-1,	"0xabc0eed81f", },
	{ "\x01\x02",		'h',	-1,	-1,	"0x0102", },
	{ "\x01\x02\x03\x04\x05\x06",	'h',	-1, -1,	"0x01020304_0506", },
	{ "\xab\xc0\xee\xd8\x1f",	16,	-1,	-1,	"abc0eed81f", },
	{ "\x0c\x20\x40",		's',	-1,	-1,	"0sDCBA", },
	{ "\x0c\x20\x40",		's',	0,	7,	"---", },
	{ "\x0c\x20\x40",		's',	1,	7,	"", },
	{ "\x0c\x20\x40",		's',	2,	7,	"0", },
	{ "\x0c\x20\x40",		's',	3,	7,	"0s", },
	{ "\x0c\x20\x40",		's',	4,	7,	"0sD", },
	{ "\x0c\x20\x40",		's',	5,	7,	"0sDC", },
	{ "\x0c\x20\x40",		's',	6,	7,	"0sDCB", },
	{ "\x0c\x20\x40",		's',	7,	7,	"0sDCBA", },
	{ "\x0c\x20\x40",		's',	8,	7,	"0sDCBA", },
	{ "\x0c",			's',	-1,	-1,	"0sDA==", },
	{ "\x0c\x20",		's',	-1,	-1,	"0sDCA=", },
	{ "\x0c\x20\x19",		's',	-1,	-1,	"0sDCAZ", },
	{ "\x0c\x20\x1a",		's',	-1,	-1,	"0sDCAa", },
	{ "\x0c\x20\x33",		's',	-1,	-1,	"0sDCAz", },
	{ "\x0c\x20\x34",		's',	-1,	-1,	"0sDCA0", },
	{ "\x0c\x20\x3d",		's',	-1,	-1,	"0sDCA9", },
	{ "\x0c\x20\x3e",		's',	-1,	-1,	"0sDCA+", },
	{ "\x0c\x20\x3f",		's',	-1,	-1,	"0sDCA/", },
	{ "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", 's', -1, -1, "0sAbraCadabra+", },
	{ "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", 64, -1, -1, "AbraCadabra+", },
	{ NULL,			'x',	-1,	-1,	NULL, },
};

/*
 - regress - regression-test ttodata() and datatot()
 */
static void
check(r, buf, n, oops, status)
struct artab *r;
char *buf;
size_t n;
err_t oops;
int *status;
{
	if (oops != NULL && r->data == NULL)
		{}			/* error expected */
	else if (oops != NULL) {
		printf("`%s' gave error `%s', expecting %d `", r->ascii,
						oops, strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	} else if (r->data == NULL) {
		printf("`%s' gave %d `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting error\n");
		*status = 1;
	} else if (n != strlen(r->data)) {
		printf("length wrong in `%s': got %d `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting %d `", strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	} else if (memcmp(buf, r->data, n) != 0) {
		printf("`%s' gave %d `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting %d `", strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	}
	fflush(stdout);
}

static void			/* should not return at all, in fact */
regress(pgm)
char *pgm;
{
	struct artab *r;
	struct drtab *dr;
	char buf[100];
	size_t n;
	int status = 0;

	for (r = atodatatab; r->ascii != NULL; r++) {
		int base = r->base;
		int xbase = 0;

		if ((base == 0 || base == IGNORESPACE_BIAS + 0) && r->ascii[0] == '0') {
			switch (r->ascii[1]) {
			case 'x':
			case 'X':
				xbase = 16;
				break;
			case 's':
			case 'S':
				xbase = 64;
				break;
			case 't':
			case 'T':
				xbase = 256;
				break;
			}
		}
		
		if (base >= IGNORESPACE_BIAS) {
			base = base - IGNORESPACE_BIAS;
			check(r, buf, n, ttodatav(r->ascii, 0, base, buf, sizeof(buf), &n, NULL, 0, TTODATAV_IGNORESPACE), &status);
			if (xbase != 0)
				check(r, buf, n, ttodatav(r->ascii+2, 0, xbase, buf, sizeof(buf), &n, NULL, 0, TTODATAV_IGNORESPACE), &status);
		} else {
			check(r, buf, n, ttodata(r->ascii, 0, base, buf, sizeof(buf), &n), &status);
			if (base == 64 || xbase == 64)
				check(r, buf, n, ttodatav(r->ascii, 0, base, buf, sizeof(buf), &n, NULL, 0, TTODATAV_IGNORESPACE), &status);
			if (xbase != 0) {
				check(r, buf, n, ttodata(r->ascii+2, 0, xbase, buf, sizeof(buf), &n), &status);
				if (base == 64 || xbase == 64)
					check(r, buf, n, ttodatav(r->ascii+2, 0, xbase, buf, sizeof(buf), &n, NULL, 0, TTODATAV_IGNORESPACE), &status);
			}
		}
	}
	for (dr = datatoatab; dr->data != NULL; dr++) {
		size_t should;

		strcpy(buf, "---");
		n = datatot(dr->data, strlen(dr->data), dr->format, buf,
				(dr->buflen == -1) ? sizeof(buf) : dr->buflen);
		should = (dr->ascii == NULL) ? 0 : strlen(dr->ascii) + 1;
		if (dr->outlen != -1)
			should = dr->outlen;
		if (n == 0 && dr->ascii == NULL)
			{}			/* error expected */
		else if (n == 0) {
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' %c gave error, expecting %d `%s'\n",
				dr->format, should, dr->ascii);
			status = 1;
		} else if (dr->ascii == NULL) {
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' %c gave %d `%.*s', expecting error\n",
				dr->format, n, (int)n, buf);
			status = 1;
		} else if (n != should) {
			printf("length wrong in `");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("': got %d `%s'", n, buf);
			printf(", expecting %d `%s'\n", should, dr->ascii);
			status = 1;
		} else if (strcmp(buf, dr->ascii) != 0) {
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' gave %d `%s'", n, buf);
			printf(", expecting %d `%s'\n", should, dr->ascii);
			status = 1;
		}
		fflush(stdout);
	}
	exit(status);
}

#endif /* TTODATA_MAIN */
