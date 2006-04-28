/**
 * @file rsakey.c
 * @brief Functions for RSA key generation 
 */

/* 
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 *
 * $Id: rsakey.c,v 1.5 2006/01/04 21:16:30 as Exp $
 */
 

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <gmp.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/mp_defs.h"
#include "../pluto/log.h"
#include "../pluto/asn1.h"
#include "../pluto/pkcs1.h"

#include "rsakey.h"

/* Number of times the probabilistic primality test is applied */
#define PRIMECHECK_ROUNDS	30

/* Public exponent used for signature key generation */
#define PUBLIC_EXPONENT		0x10001

#ifndef RANDOM_DEVICE
#define	RANDOM_DEVICE	"/dev/random"
#endif


/**
 * @brief Reads a specific number of bytes from a given device/file
 * 
 * @param[in]		nbytes		number of bytes to read from random device
 * @param[out]		buf		pointer to buffer where to write the data in.
 * 					size of buffer has to be at least nbytes.
 * @return				TRUE, if succeeded, FALSE otherwise
 */

static bool
get_true_random_bytes(size_t nbytes, char *buf)
{
    size_t ndone;
    size_t got;
    char *device = RANDOM_DEVICE;

    int dev = open(RANDOM_DEVICE, 0);

    if (dev < 0)
    {
	fprintf(stderr, "could not open random device %s", device);
	return FALSE;
    }

    DBG(DBG_CONTROL,
	DBG_log("getting %d bytes from %s...", (int) nbytes, device)
    )
	
    ndone = 0;
    while (ndone < nbytes)
    {
	got = read(dev, buf + ndone, nbytes - ndone);
	if (got < 0)
	{
	    fprintf(stderr, "read error on %s", device);
	    return FALSE;
	}
	if (got == 0)
	{
	    fprintf(stderr, "eof on %s", device);
	    return FALSE;
	}
	 ndone += got;
    }
    close(dev);
    return TRUE;
}

/**
 * @brief initialize an mpz_t to a random number, specified bit count
 *
 * Converting the random value in a value of type mpz_t is done 
 * by creating a hexbuffer.
 * Converting via hex is a bit weird, but it's the best route GMP gives us.
 * Note that highmost and lowmost bits are forced on -- highmost to give a
 * number of exactly the specified length, lowmost so it is an odd number.
 *
 * @param[out] 	var uninitialized mpz_t to store th random number in
 * @param[in] 	nbits length of var in bits (known to be a multiple of BITS_PER_BYTE)
 * @return 	TRUE on success, FALSE otherwise
 */
static bool
init_random(mpz_t var, int nbits)
{
    size_t nbytes = (size_t)(nbits/BITS_PER_BYTE);
    char random_buf[RSA_MAX_OCTETS/2];

    assert(nbytes <= sizeof(random_buf));

    if (!get_true_random_bytes(nbytes, random_buf))
	return FALSE;
	
    random_buf[0] |= 01 << (BITS_PER_BYTE-1);	/* force high bit on */
    random_buf[nbytes-1] |= 01;			/* force low bit on */
    n_to_mpz(var, random_buf, nbytes);
    return TRUE;
}

/**
 * @brief initialize an mpz_t to a random prime of specified size
 *
 * Efficiency tweak: we reject candidates that are 1 higher than a multiple
 * of e, since they will make the internal modulus not relatively prime to e.
 *
 * @param[out] 	var mpz_t variable to initialize
 * @param[in] 	nbits length of given prime in bits (known to be a multiple of BITS_PER_BYTE)
 * @param[in] 	eval E-Value, 0 means don't bother w. tweak
 * @return 		1 on success, 0 otherwise
 */
static bool
init_prime(mpz_t var, int nbits, int eval)
{
    unsigned long tries;
    size_t len;

    /* get a random value of nbits length */
    if (!init_random(var, nbits))
	return FALSE;

    /* check if odd number */
    assert(mpz_fdiv_ui(var, 2) == 1);
    DBG(DBG_CONTROLMORE,
	DBG_log("looking for a prime starting there (can take a while)...")
    )

    tries = 1;
    while (mpz_fdiv_ui(var, eval) == 1
       || !mpz_probab_prime_p(var, PRIMECHECK_ROUNDS))
    {
	/* not a prime, increase by 2 */
	mpz_add_ui(var, var, 2);
	tries++;
    }

    len = mpz_sizeinbase(var, 2);

    /* check bit length of primee */
    assert(len == (size_t)nbits || len == (size_t)(nbits+1));

    if (len == (size_t)(nbits+1))
    {
	DBG(DBG_CONTROLMORE,
	    DBG_log("carry out occurred (!), retrying...")
	)
	mpz_clear(var);
	/* recursive call */
	return init_prime(var, nbits, eval);
    }
    DBG(DBG_CONTROLMORE,
	DBG_log("found it after %lu tries.",tries)
    )
    return TRUE;
}

/** 
 * @brief Generate a RSA key usable for encryption
 * 
 * Generate an RSA key usable for encryption. All the 
 * values of the RSA key are filled into mpz_t parameters.
 * These mpz_t parameters must not be initialized and have
 * to be cleared with mpz_clear after using.
 *
 * @param[in] 	nbits size of rsa key in bits
 * @return 	RSA_public_key_t containing the generated RSA key 
 */
err_t
generate_rsa_private_key(int nbits, RSA_private_key_t *key)
{
    mpz_t p, q, n, e, d, exp1, exp2, coeff;
    mpz_t m, q1, t;	/* temporary variables*/

     DBG(DBG_CONTROL,
	DBG_log("generating %d bit RSA key:", nbits)
    )

    if (nbits <= 0) 
	return "negative rsa key length!";

    /* Get values of primes p and q */
    DBG(DBG_CONTROLMORE,
	DBG_log("initialize prime p")
    )
    if (!init_prime(p, nbits/2, PUBLIC_EXPONENT)) 
	return "could not generate prime p";

    DBG(DBG_CONTROLMORE,
	DBG_log("initialize prime q")
    )
    if (!init_prime(q, nbits/2, PUBLIC_EXPONENT)) 
	return "could not generate prime q";
	
    mpz_init(t);

    /* Swapping primes so p is larger then q */
    if (mpz_cmp(p, q) < 0) 
    {
	DBG(DBG_CONTROLMORE,
	    DBG_log("swapping primes so p is the larger...")
	);
	mpz_set(t, p);
	mpz_set(p, q);
	mpz_set(q, t);
    }
	
    DBG(DBG_CONTROLMORE,
	DBG_log("computing modulus...")
    )
    mpz_init(n);
    /* n = p*q */
    mpz_mul(n, p, q);

    /* Assign e the value of defined PUBLIC_EXPONENT */
    mpz_init_set_ui(e, PUBLIC_EXPONENT);

    DBG(DBG_CONTROLMORE,
	DBG_log("computing lcm(p-1, q-1)...")
    )
    /* m = p */
    mpz_init_set(m, p);
    /* m = m-1 */
    mpz_sub_ui(m, m, 1);
    /* q1 = q */
    mpz_init_set(q1, q);
    /* q1 = q1-1 */
    mpz_sub_ui(q1, q1, 1);
    /* t = gcd(p-1, q-1) */
    mpz_gcd(t, m, q1);
    /* m = (p-1)*(q-1) */
    mpz_mul(m, m, q1);
    /* m = m / t */
    mpz_divexact(m, m, t);
    /* t = gcd(m, e) (greatest common divisor) */
    mpz_gcd(t, m, e);
    /* m and e relatively prime */
    assert(mpz_cmp_ui(t, 1) == 0);

    /* decryption key */
    DBG(DBG_CONTROLMORE,
	DBG_log("computing d...")
    )
    mpz_init(d);
    /* e has an inverse mod m */
    assert(mpz_invert(d, e, m));

    /* make sure d is positive */
    if (mpz_cmp_ui(d, 0) < 0)
	mpz_add(d, d, m);

    /* d has to be positive */	
    assert(mpz_cmp(d, m) < 0);

    /* the speedup hacks */
    DBG(DBG_CONTROLMORE,
	DBG_log("computing exp1, exp1, coeff...")
    )
    mpz_init(exp1);
    /* t = p-1 */
    mpz_sub_ui(t, p, 1);
    /* exp1 = d mod p-1 */
    mpz_mod(exp1, d, t);

    mpz_init(exp2);
    /* t = q-1 */
    mpz_sub_ui(t, q, 1);
    /* exp2 = d mod q-1 */
    mpz_mod(exp2, d, t);

    mpz_init(coeff);
    /* coeff = q^-1 mod p */
    mpz_invert(coeff, q, p);

    /* make sure coeff is positive */
    if (mpz_cmp_ui(coeff, 0) < 0)
	mpz_add(coeff, coeff, p);

    /* coeff has to be positive */
    assert(mpz_cmp(coeff, p) < 0);

    /* Clear temporary variables */
	mpz_clear(q1);
	mpz_clear(m);
	mpz_clear(t);

    /* form FreeS/WAN keyid */
    {
	size_t e_len = (mpz_sizeinbase(e,2)+BITS_PER_BYTE-1)/BITS_PER_BYTE;
	size_t n_len = (mpz_sizeinbase(n,2)+BITS_PER_BYTE-1)/BITS_PER_BYTE;
	chunk_t e_ch = mpz_to_n(e, e_len);
	chunk_t n_ch = mpz_to_n(n, n_len);
	form_keyid(e_ch, n_ch, key->pub.keyid, &key->pub.k);
	freeanychunk(e_ch);
	freeanychunk(n_ch);
    }
    /* fill in the elements of the RSA private key */
    key->p = *p;
    key->q = *q;
    key->pub.n = *n;
    key->pub.e = *e;
    key->d = *d;
    key->dP = *exp1;
    key->dQ = *exp2;
    key->qInv = *coeff;

    DBG(DBG_CONTROL,
	DBG_log("RSA key *%s generated with %d bits", key->pub.keyid
	    , (int)mpz_sizeinbase(n,2))
    )

#ifdef DEBUG
    DBG(DBG_PRIVATE,
	RSA_show_private_key(key)
    )
#endif
    return NULL;
}
