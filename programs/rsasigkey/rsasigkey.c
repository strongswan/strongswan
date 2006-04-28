/*
 * RSA signature key generation
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
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
 *
 * RCSID $Id: rsasigkey.c,v 1.2 2005/08/11 10:35:58 as Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <freeswan.h>
#include "gmp.h"

#ifndef DEVICE
#define	DEVICE	"/dev/random"
#endif
#ifndef MAXBITS
#define	MAXBITS	20000
#endif

/* the code in getoldkey() knows about this */
#define	E	3		/* standard public exponent */

char usage[] = "rsasigkey [--verbose] [--random device] nbits";
char usage2[] = "rsasigkey [--verbose] --oldkey filename";
struct option opts[] = {
  {"verbose",	0,	NULL,	'v',},
  {"random",	1,	NULL,	'r',},
  {"rounds",	1,	NULL,	'p',},
  {"oldkey",	1,	NULL,	'o',},
  {"hostname",	1,	NULL,	'H',},
  {"noopt",	0,	NULL,	'n',},
  {"help",	0,	NULL,	'h',},
  {"version",	0,	NULL,	'V',},
  {0,		0,	NULL,	0,}
};
int verbose = 0;		/* narrate the action? */
char *device = DEVICE;		/* where to get randomness */
int nrounds = 30;		/* rounds of prime checking; 25 is good */
mpz_t prime1;			/* old key's prime1 */
mpz_t prime2;			/* old key's prime2 */
char outputhostname[1024];	/* hostname for output */
int do_lcm = 1;			/* use lcm(p-1, q-1), not (p-1)*(q-1) */

char me[] = "ipsec rsasigkey";	/* for messages */

/* forwards */
int getoldkey(char *filename);
void rsasigkey(int nbits, int useoldkey);
void initprime(mpz_t var, int nbits, int eval);
void initrandom(mpz_t var, int nbits);
void getrandom(size_t nbytes, char *buf);
char *bundle(int e, mpz_t n, size_t *sizep);
char *conv(char *bits, size_t nbytes, int format);
char *hexout(mpz_t var);
void report(char *msg);

/*
 - main - mostly argument parsing
 */
int main(int argc, char *argv[])
{
	int opt;
	extern int optind;
	extern char *optarg;
	int errflg = 0;
	int i;
	int nbits;
	char *oldkeyfile = NULL;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'v':	/* verbose description */
			verbose = 1;
			break;
		case 'r':	/* nonstandard /dev/random */
			device = optarg;
			break;
		case 'p':	/* number of prime-check rounds */
			nrounds = atoi(optarg);
			if (nrounds <= 0) {
				fprintf(stderr, "%s: rounds must be > 0\n", me);
				exit(2);
			}
			break;
		case 'o':	/* reformat old key */
			oldkeyfile = optarg;
			break;
		case 'H':	/* set hostname for output */
			strcpy(outputhostname, optarg);
			break;
		case 'n':	/* don't optimize the private key */
			do_lcm = 0;
			break;
		case 'h':	/* help */
			printf("Usage:\t%s\n", usage);
			printf("\tor\n");
			printf("\t%s\n", usage2);
			exit(0);
			break;
		case 'V':	/* version */
			printf("%s %s\n", me, ipsec_version_code());
			exit(0);
			break;
		case '?':
		default:
			errflg = 1;
			break;
		}
	if (errflg || optind != ((oldkeyfile != NULL) ? argc : argc-1)) {
		printf("Usage:\t%s\n", usage);
		printf("\tor\n");
		printf("\t%s\n", usage2);
		exit(2);
	}

	if (outputhostname[0] == '\0') {
		i = gethostname(outputhostname, sizeof(outputhostname));
		if (i < 0) {
			fprintf(stderr, "%s: gethostname failed (%s)\n",
				me,
				strerror(errno));
			exit(1);
		}
	}

	if (oldkeyfile == NULL) {
		assert(argv[optind] != NULL);
		nbits = atoi(argv[optind]);
	} else
		nbits = getoldkey(oldkeyfile);

	if (nbits <= 0) {
		fprintf(stderr, "%s: invalid bit count (%d)\n", me, nbits);
		exit(1);
	} else if (nbits > MAXBITS) {
		fprintf(stderr, "%s: overlarge bit count (max %d)\n", me,
								MAXBITS);
		exit(1);
	} else if (nbits % (CHAR_BIT*2) != 0) {	/* *2 for nbits/2-bit primes */
		fprintf(stderr, "%s: bit count (%d) not multiple of %d\n", me,
						nbits, (int)CHAR_BIT*2);
		exit(1);
	}

	rsasigkey(nbits, (oldkeyfile == NULL) ? 0 : 1);
	exit(0);
}

/*
 - getoldkey - fetch an old key's primes
 */
int				/* nbits */
getoldkey(filename)
char *filename;
{
	FILE *f;
	char line[MAXBITS/2];
	char *p;
	char *value;
	static char pube[] = "PublicExponent:";
	static char pubevalue[] = "0x03";
	static char pr1[] = "Prime1:";
	static char pr2[] = "Prime2:";
#	define	STREQ(a, b)	(strcmp(a, b) == 0)
	int sawpube = 0;
	int sawpr1 = 0;
	int sawpr2 = 0;
	int nbits;

	nbits = 0;
 
	if (STREQ(filename, "-"))
		f = stdin;
	else
		f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "%s: unable to open file `%s' (%s)\n", me,
						filename, strerror(errno));
		exit(1);
	}
	if (verbose)
		fprintf(stderr, "getting old key from %s...\n", filename);

	while (fgets(line, sizeof(line), f) != NULL) {
		p = line + strlen(line) - 1;
		if (*p != '\n') {
			fprintf(stderr, "%s: over-long line in file `%s'\n",
							me, filename);
			exit(1);
		}
		*p = '\0';

		p = line + strspn(line, " \t");		/* p -> first word */
		value = strpbrk(p, " \t");		/* value -> after it */
		if (value != NULL) {
			*value++ = '\0';
			value += strspn(value, " \t");
			/* value -> second word if any */
		}

		if (value == NULL || *value == '\0') {
			/* wrong format */
		} else if (STREQ(p, pube)) {
			sawpube = 1;
			if (!STREQ(value, pubevalue)) {
				fprintf(stderr, "%s: wrong public exponent (`%s') in old key\n",
					me, value);
				exit(1);
			}
		} else if (STREQ(p, pr1)) {
			if (sawpr1) {
				fprintf(stderr, "%s: duplicate `%s' lines in `%s'\n",
					me, pr1, filename);
				exit(1);
			}
			sawpr1 = 1;
			nbits = (strlen(value) - 2) * 4 * 2;
			if (mpz_init_set_str(prime1, value, 0) < 0) {
				fprintf(stderr, "%s: conversion error in reading old prime1\n",
					me);
				exit(1);
			}
		} else if (STREQ(p, pr2)) {
			if (sawpr2) {
				fprintf(stderr, "%s: duplicate `%s' lines in `%s'\n",
					me, pr2, filename);
				exit(1);
			}
			sawpr2 = 1;
			if (mpz_init_set_str(prime2, value, 0) < 0) {
				fprintf(stderr, "%s: conversion error in reading old prime2\n",
					me);
				exit(1);
			}
		}
	}
	
	if (f != stdin)
		fclose(f);

	if (!sawpube || !sawpr1 || !sawpr2) {
		fprintf(stderr, "%s: old key missing or incomplete\n", me);
		exit(1);
	}

	assert(sawpr1);		/* and thus nbits is known */
	return(nbits);
}

/*
 - rsasigkey - generate an RSA signature key
 * e is fixed at 3, without discussion.  That would not be wise if these
 * keys were to be used for encryption, but for signatures there are some
 * real speed advantages.
 */
void
rsasigkey(nbits, useoldkey)
int nbits;
int useoldkey;			/* take primes from old key? */
{
	mpz_t p;
	mpz_t q;
	mpz_t n;
	mpz_t e;
	mpz_t d;
	mpz_t q1;			/* temporary */
	mpz_t m;			/* internal modulus, (p-1)*(q-1) */
	mpz_t t;			/* temporary */
	mpz_t exp1;
	mpz_t exp2;
	mpz_t coeff;
	char *bundp;
	size_t bs;
	int success;
	time_t now = time((time_t *)NULL);

	/* the easy stuff */
	if (useoldkey) {
		mpz_init_set(p, prime1);
		mpz_init_set(q, prime2);
	} else {
		initprime(p, nbits/2, E);
		initprime(q, nbits/2, E);
	}
	mpz_init(t);
	if (mpz_cmp(p, q) < 0) {
		report("swapping primes so p is the larger...");
		mpz_set(t, p);
		mpz_set(p, q);
		mpz_set(q, t);
	}
	report("computing modulus...");
	mpz_init(n);
	mpz_mul(n, p, q);		/* n = p*q */
	mpz_init_set_ui(e, E);

	/* internal modulus */
	report("computing lcm(p-1, q-1)...");
	mpz_init_set(m, p);
	mpz_sub_ui(m, m, 1);
	mpz_init_set(q1, q);
	mpz_sub_ui(q1, q1, 1);
	mpz_gcd(t, m, q1);		/* t = gcd(p-1, q-1) */
	mpz_mul(m, m, q1);		/* m = (p-1)*(q-1) */
	if (do_lcm)
		mpz_divexact(m, m, t);		/* m = lcm(p-1, q-1) */
	mpz_gcd(t, m, e);
	assert(mpz_cmp_ui(t, 1) == 0);	/* m and e relatively prime */

	/* decryption key */
	report("computing d...");
	mpz_init(d);
	success = mpz_invert(d, e, m);
	assert(success);		/* e has an inverse mod m */
	if (mpz_cmp_ui(d, 0) < 0)
		mpz_add(d, d, m);
	assert(mpz_cmp(d, m) < 0);

	/* the speedup hacks */
	report("computing exp1, exp1, coeff...");
	mpz_init(exp1);
	mpz_sub_ui(t, p, 1);
	mpz_mod(exp1, d, t);		/* exp1 = d mod p-1 */
	mpz_init(exp2);
	mpz_sub_ui(t, q, 1);
	mpz_mod(exp2, d, t);		/* exp2 = d mod q-1 */
	mpz_init(coeff);
	mpz_invert(coeff, q, p);	/* coeff = q^-1 mod p */
	if (mpz_cmp_ui(coeff, 0) < 0)
		mpz_add(coeff, coeff, p);
	assert(mpz_cmp(coeff, p) < 0);

	/* and the output */
	/* note, getoldkey() knows about some of this */
	report("output...\n");		/* deliberate extra newline */
	printf("\t# RSA %d bits   %s   %s", nbits, outputhostname, ctime(&now));
							/* ctime provides \n */
	printf("\t# for signatures only, UNSAFE FOR ENCRYPTION\n");
	bundp = bundle(E, n, &bs);
	printf("\t#pubkey=%s\n", conv(bundp, bs, 's'));	/* RFC2537ish format */
	printf("\tModulus: %s\n", hexout(n));
	printf("\tPublicExponent: %s\n", hexout(e));
	printf("\t# everything after this point is secret\n");
	printf("\tPrivateExponent: %s\n", hexout(d));
	printf("\tPrime1: %s\n", hexout(p));
	printf("\tPrime2: %s\n", hexout(q));
	printf("\tExponent1: %s\n", hexout(exp1));
	printf("\tExponent2: %s\n", hexout(exp2));
	printf("\tCoefficient: %s\n", hexout(coeff));
}

/*
 - initprime - initialize an mpz_t to a random prime of specified size
 * Efficiency tweak:  we reject candidates that are 1 higher than a multiple
 * of e, since they will make the internal modulus not relatively prime to e.
 */
void
initprime(var, nbits, eval)
mpz_t var;
int nbits;			/* known to be a multiple of CHAR_BIT */
int eval;			/* value of e; 0 means don't bother w. tweak */
{
	unsigned long tries;
	size_t len;
#	define	OKAY(p)	(eval == 0 || mpz_fdiv_ui(p, eval) != 1)

	initrandom(var, nbits);
	assert(mpz_fdiv_ui(var, 2) == 1);	/* odd number */

	report("looking for a prime starting there (can take a while)...");
	tries = 1;
	while (!( OKAY(var) && mpz_probab_prime_p(var, nrounds) )) {
		mpz_add_ui(var, var, 2);
		tries++;
	}

	len = mpz_sizeinbase(var, 2);
	assert(len == (size_t)nbits || len == (size_t)(nbits+1));
	if (len == (size_t)(nbits+1)) {
		report("carry out occurred (!), retrying...");
		mpz_clear(var);
		initprime(var, nbits, eval);
		return;
	}
	if (verbose)
		fprintf(stderr, "found it after %lu tries.\n", tries);
}

/*
 - initrandom - initialize an mpz_t to a random number, specified bit count
 * Converting via hex is a bit weird, but it's the best route GMP gives us.
 * Note that highmost and lowmost bits are forced on -- highmost to give a
 * number of exactly the specified length, lowmost so it is an odd number.
 */
void
initrandom(var, nbits)
mpz_t var;
int nbits;			/* known to be a multiple of CHAR_BIT */
{
	size_t nbytes = (size_t)(nbits / CHAR_BIT);
	static char bitbuf[MAXBITS/CHAR_BIT];
	static char hexbuf[2 + MAXBITS/4 + 1];
	size_t hsize = sizeof(hexbuf);

	assert(nbytes <= sizeof(bitbuf));
	getrandom(nbytes, bitbuf);
	bitbuf[0] |= 01 << (CHAR_BIT-1);	/* force high bit on */
	bitbuf[nbytes-1] |= 01;			/* force low bit on */
	if (datatot(bitbuf, nbytes, 'x', hexbuf, hsize) > hsize) {
		fprintf(stderr, "%s: can't-happen buffer overflow\n", me);
		exit(1);
	}
	if (mpz_init_set_str(var, hexbuf, 0) < 0) {
		fprintf(stderr, "%s: can't-happen hex conversion error\n", me);
		exit(1);
	}
}

/*
 - getrandom - get some random bytes from /dev/random (or wherever)
 */
void
getrandom(nbytes, buf)
size_t nbytes;
char *buf;			/* known to be big enough */
{
	size_t ndone;
	int dev;
	size_t got;

	dev = open(device, 0);
	if (dev < 0) {
		fprintf(stderr, "%s: could not open %s (%s)\n", me,
						device, strerror(errno));
		exit(1);
	}

	ndone = 0;
	if (verbose)
		fprintf(stderr, "getting %d random bytes from %s...\n", (int) nbytes,
							device);
	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			fprintf(stderr, "%s: read error on %s (%s)\n", me,
						device, strerror(errno));
			exit(1);
		}
		if (got == 0) {
			fprintf(stderr, "%s: eof on %s!?!\n", me, device);
			exit(1);
		}
		ndone += got;
	}

	close(dev);
}

/*
 - hexout - prepare hex output, guaranteeing even number of digits
 * (The current FreeS/WAN conversion routines want an even digit count,
 * but mpz_get_str doesn't promise one.)
 */
char *				/* pointer to static buffer (ick) */
hexout(var)
mpz_t var;
{
	static char hexbuf[3 + MAXBITS/4 + 1];
	char *hexp;

	mpz_get_str(hexbuf+3, 16, var);
	if (strlen(hexbuf+3)%2 == 0)	/* even number of hex digits */
		hexp = hexbuf+1;
	else {				/* odd, must pad */
		hexp = hexbuf;
		hexp[2] = '0';
	}
	hexp[0] = '0';
	hexp[1] = 'x';

	return hexp;
}

/*
 - bundle - bundle e and n into an RFC2537-format lump
 * Note, calls hexout.
 */
char *				/* pointer to static buffer (ick) */
bundle(e, n, sizep)
int e;
mpz_t n;
size_t *sizep;
{
	char *hexp = hexout(n);
	static char bundbuf[2 + MAXBITS/8];
	const char *er;
	size_t size;

	assert(e <= 255);
	bundbuf[0] = 1;
	bundbuf[1] = e;
	er = ttodata(hexp, 0, 0, bundbuf+2, sizeof(bundbuf)-2, &size);
	if (er != NULL) {
		fprintf(stderr, "%s: can't-happen bundle convert error `%s'\n",
								me, er);
		exit(1);
	}
	if (size > sizeof(bundbuf)-2) {
		fprintf(stderr, "%s: can't-happen bundle overflow (need %d)\n",
								me, (int) size);
		exit(1);
	}
	if (sizep != NULL)
		*sizep = size + 2;
	return bundbuf;
}

/*
 - conv - convert bits to output in specified format
 */
char *				/* pointer to static buffer (ick) */
conv(bits, nbytes, format)
char *bits;
size_t nbytes;
int format;			/* datatot() code */
{
	static char convbuf[MAXBITS/4 + 50];	/* enough for hex */
	size_t n;

	n = datatot(bits, nbytes, format, convbuf, sizeof(convbuf));
	if (n == 0) {
		fprintf(stderr, "%s: can't-happen convert error\n", me);
		exit(1);
	}
	if (n > sizeof(convbuf)) {
		fprintf(stderr, "%s: can't-happen convert overflow (need %d)\n",
								me, (int) n);
		exit(1);
	}
	return convbuf;
}

/*
 - report - report progress, if indicated
 */
void
report(msg)
char *msg;
{
	if (!verbose)
		return;
	fprintf(stderr, "%s\n", msg);
}
