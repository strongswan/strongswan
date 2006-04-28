/* elgamal.c  -  ElGamal Public Key encryption
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * For a description of the algorithm, see:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. Pages 476 ff.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef PLUTO
#include <gmp.h>
#include <freeswan.h>
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "rnd.h"
#include "gcryptfix.h"
#else /*! PLUTO */
/* #include <config.h> */
#endif /* !PLUTO */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PLUTO
/* #include "util.h" */
/* #include "mpi.h" */
/* #include "cipher.h" */
#endif

#include "elgamal.h"

typedef struct {
    MPI p;	    /* prime */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
} ELG_public_key;


typedef struct {
    MPI p;	    /* prime */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
    MPI x;	    /* secret exponent */
} ELG_secret_key;


static void test_keys( ELG_secret_key *sk, unsigned nbits );
static MPI gen_k( MPI p );
static void generate( ELG_secret_key *sk, unsigned nbits, MPI **factors );
static int  check_secret_key( ELG_secret_key *sk );
static void encrypt(MPI a, MPI b, MPI input, ELG_public_key *pkey );
static void decrypt(MPI output, MPI a, MPI b, ELG_secret_key *skey );
static void sign(MPI a, MPI b, MPI input, ELG_secret_key *skey);
static int  verify(MPI a, MPI b, MPI input, ELG_public_key *pkey);


static void
progress( int c )
{
    fputc( c, stderr );
}


static void
test_keys( ELG_secret_key *sk, unsigned nbits )
{
    ELG_public_key pk;
    MPI test = mpi_alloc( 0 );
    MPI out1_a = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out1_b = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out2 = mpi_alloc( nbits / BITS_PER_MPI_LIMB );

    pk.p = sk->p;
    pk.g = sk->g;
    pk.y = sk->y;

    /*mpi_set_bytes( test, nbits, get_random_byte, 0 );*/
    {	char *p = get_random_bits( nbits, 0, 0 );
	mpi_set_buffer( test, p, (nbits+7)/8, 0 );
	m_free(p);
    }

    encrypt( out1_a, out1_b, test, &pk );
    decrypt( out2, out1_a, out1_b, sk );
    if( mpi_cmp( test, out2 ) )
	log_fatal("ElGamal operation: encrypt, decrypt failed\n");

    sign( out1_a, out1_b, test, sk );
    if( !verify( out1_a, out1_b, test, &pk ) )
	log_fatal("ElGamal operation: sign, verify failed\n");

    mpi_free( test );
    mpi_free( out1_a );
    mpi_free( out1_b );
    mpi_free( out2 );
}


/****************
 * generate a random secret exponent k from prime p, so
 * that k is relatively prime to p-1
 */
static MPI
gen_k( MPI p )
{
    MPI k = mpi_alloc_secure( 0 );
    MPI temp = mpi_alloc( mpi_get_nlimbs(p) );
    MPI p_1 = mpi_copy(p);
    unsigned int nbits = mpi_get_nbits(p);
    unsigned int nbytes = (nbits+7)/8;
    char *rndbuf = NULL;

    if( DBG_CIPHER )
	log_debug("choosing a random k ");
    mpi_sub_ui( p_1, p, 1);
    for(;;) {
	if( DBG_CIPHER )
	    progress('.');
	if( !rndbuf || nbits < 32 ) {
	    m_free(rndbuf);
	    rndbuf = get_random_bits( nbits, 1, 1 );
	}
	else { /* change only some of the higher bits */
	    /* we could imporove this by directly requesting more memory
	     * at the first call to get_random_bits() and use this the here
	     * maybe it is easier to do this directly in random.c */
	    char *pp = get_random_bits( 32, 1, 1 );
	    memcpy( rndbuf,pp, 4 );
	    m_free(pp);
	}
	mpi_set_buffer( k, rndbuf, nbytes, 0 );

	for(;;) {
	    /* make sure that the number is of the exact lenght */
	    if( mpi_test_bit( k, nbits-1 ) )
		mpi_set_highbit( k, nbits-1 );
	    else {
		mpi_set_highbit( k, nbits-1 );
		mpi_clear_bit( k, nbits-1 );
	    }
	    if( !(mpi_cmp( k, p_1 ) < 0) ) {  /* check: k < (p-1) */
		if( DBG_CIPHER )
		    progress('+');
		break; /* no  */
	    }
	    if( !(mpi_cmp_ui( k, 0 ) > 0) ) { /* check: k > 0 */
		if( DBG_CIPHER )
		    progress('-');
		break; /* no */
	    }
	    if( mpi_gcd( temp, k, p_1 ) )
		goto found;  /* okay, k is relatively prime to (p-1) */
	    mpi_add_ui( k, k, 1 );
	}
    }
  found:
    m_free(rndbuf);
    if( DBG_CIPHER )
	progress('\n');
    mpi_free(p_1);
    mpi_free(temp);

    return k;
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 *	    and an array with n-1 factors of (p-1)
 */
static void
generate(  ELG_secret_key *sk, unsigned nbits, MPI **ret_factors )
{
    MPI p;    /* the prime */
    MPI p_min1;
    MPI g;
    MPI x;    /* the secret exponent */
    MPI y;
    MPI temp;
    unsigned qbits;
    byte *rndbuf;

    p_min1 = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    temp   = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    if( nbits < 512 )
	qbits = 120;
    else if( nbits <= 1024 )
	qbits = 160;
    else if( nbits <= 2048 )
	qbits = 200;
    else
	qbits = 240;
    g = mpi_alloc(1);
    p = generate_elg_prime( 0, nbits, qbits, g, ret_factors );
    mpi_sub_ui(p_min1, p, 1);


    /* select a random number which has these properties:
     *	 0 < x < p-1
     * This must be a very good random number because this is the
     * secret part.  The prime is public and may be shared anyway,
     * so a random generator level of 1 is used for the prime.
     */
    x = mpi_alloc_secure( nbits/BITS_PER_MPI_LIMB );
    if( DBG_CIPHER )
	log_debug("choosing a random x ");
    rndbuf = NULL;
    do {
	if( DBG_CIPHER )
	    progress('.');
	if( rndbuf ) { /* change only some of the higher bits */
	    if( nbits < 16 ) {/* should never happen ... */
		m_free(rndbuf);
		rndbuf = get_random_bits( nbits, 2, 1 );
	    }
	    else {
		char *r = get_random_bits( 16, 2, 1 );
		memcpy(rndbuf, r, 16/8 );
		m_free(r);
	    }
	}
	else
	    rndbuf = get_random_bits( nbits, 2, 1 );
	mpi_set_buffer( x, rndbuf, (nbits+7)/8, 0 );
	mpi_clear_highbit( x, nbits+1 );
    } while( !( mpi_cmp_ui( x, 0 )>0 && mpi_cmp( x, p_min1 )<0 ) );
    m_free(rndbuf);

    y = mpi_alloc(nbits/BITS_PER_MPI_LIMB);
    mpi_powm( y, g, x, p );

    if( DBG_CIPHER ) {
	progress('\n');
	log_mpidump("elg  p= ", p );
	log_mpidump("elg  g= ", g );
	log_mpidump("elg  y= ", y );
	log_mpidump("elg  x= ", x );
    }

    /* copy the stuff to the key structures */
    sk->p = p;
    sk->g = g;
    sk->y = y;
    sk->x = x;

    /* now we can test our keys (this should never fail!) */
    test_keys( sk, nbits - 64 );

    mpi_free( p_min1 );
    mpi_free( temp   );
}


/****************
 * Test whether the secret key is valid.
 * Returns: if this is a valid key.
 */
static int
check_secret_key( ELG_secret_key *sk )
{
    int rc;
    MPI y = mpi_alloc( mpi_get_nlimbs(sk->y) );

    mpi_powm( y, sk->g, sk->x, sk->p );
    rc = !mpi_cmp( y, sk->y );
    mpi_free( y );
    return rc;
}


static void
encrypt(MPI a, MPI b, MPI input, ELG_public_key *pkey )
{
    MPI k;

    /* Note: maybe we should change the interface, so that it
     * is possible to check that input is < p and return an
     * error code.
     */

    k = gen_k( pkey->p );
    mpi_powm( a, pkey->g, k, pkey->p );
    /* b = (y^k * input) mod p
     *	 = ((y^k mod p) * (input mod p)) mod p
     * and because input is < p
     *	 = ((y^k mod p) * input) mod p
     */
    mpi_powm( b, pkey->y, k, pkey->p );
    mpi_mulm( b, b, input, pkey->p );
  #if 0
    if( DBG_CIPHER ) {
	log_mpidump("elg encrypted y= ", pkey->y);
	log_mpidump("elg encrypted p= ", pkey->p);
	log_mpidump("elg encrypted k= ", k);
	log_mpidump("elg encrypted M= ", input);
	log_mpidump("elg encrypted a= ", a);
	log_mpidump("elg encrypted b= ", b);
    }
  #endif
    mpi_free(k);
}




static void
decrypt(MPI output, MPI a, MPI b, ELG_secret_key *skey )
{
    MPI t1 = mpi_alloc_secure( mpi_get_nlimbs( skey->p ) );

    /* output = b/(a^x) mod p */

    mpi_powm( t1, a, skey->x, skey->p );
    mpi_invm( t1, t1, skey->p );
    mpi_mulm( output, b, t1, skey->p );
  #if 0
    if( DBG_CIPHER ) {
	log_mpidump("elg decrypted x= ", skey->x);
	log_mpidump("elg decrypted p= ", skey->p);
	log_mpidump("elg decrypted a= ", a);
	log_mpidump("elg decrypted b= ", b);
	log_mpidump("elg decrypted M= ", output);
    }
  #endif
    mpi_free(t1);
}


/****************
 * Make an Elgamal signature out of INPUT
 */

static void
sign(MPI a, MPI b, MPI input, ELG_secret_key *skey )
{
    MPI k;
    MPI t   = mpi_alloc( mpi_get_nlimbs(a) );
    MPI inv = mpi_alloc( mpi_get_nlimbs(a) );
    MPI p_1 = mpi_copy(skey->p);

   /*
    * b = (t * inv) mod (p-1)
    * b = (t * inv(k,(p-1),(p-1)) mod (p-1)
    * b = (((M-x*a) mod (p-1)) * inv(k,(p-1),(p-1))) mod (p-1)
    *
    */
    mpi_sub_ui(p_1, p_1, 1);
    k = gen_k( skey->p );
    mpi_powm( a, skey->g, k, skey->p );
    mpi_mul(t, skey->x, a );
    mpi_subm(t, input, t, p_1 );
    while( mpi_is_neg(t) )
	mpi_add(t, t, p_1);
    mpi_invm(inv, k, p_1 );
    mpi_mulm(b, t, inv, p_1 );

  #if 0
    if( DBG_CIPHER ) {
	log_mpidump("elg sign p= ", skey->p);
	log_mpidump("elg sign g= ", skey->g);
	log_mpidump("elg sign y= ", skey->y);
	log_mpidump("elg sign x= ", skey->x);
	log_mpidump("elg sign k= ", k);
	log_mpidump("elg sign M= ", input);
	log_mpidump("elg sign a= ", a);
	log_mpidump("elg sign b= ", b);
    }
  #endif
    mpi_free(k);
    mpi_free(t);
    mpi_free(inv);
    mpi_free(p_1);
}


/****************
 * Returns true if the signature composed of A and B is valid.
 */
static int
verify(MPI a, MPI b, MPI input, ELG_public_key *pkey )
{
    int rc;
    MPI t1;
    MPI t2;
    MPI base[4];
    MPI exp[4];

    if( !(mpi_cmp_ui( a, 0 ) > 0 && mpi_cmp( a, pkey->p ) < 0) )
	return 0; /* assertion	0 < a < p  failed */

    t1 = mpi_alloc( mpi_get_nlimbs(a) );
    t2 = mpi_alloc( mpi_get_nlimbs(a) );

  #if 0
    /* t1 = (y^a mod p) * (a^b mod p) mod p */
    mpi_powm( t1, pkey->y, a, pkey->p );
    mpi_powm( t2, a, b, pkey->p );
    mpi_mulm( t1, t1, t2, pkey->p );

    /* t2 = g ^ input mod p */
    mpi_powm( t2, pkey->g, input, pkey->p );

    rc = !mpi_cmp( t1, t2 );
  #elif 0
    /* t1 = (y^a mod p) * (a^b mod p) mod p */
    base[0] = pkey->y; exp[0] = a;
    base[1] = a;       exp[1] = b;
    base[2] = NULL;    exp[2] = NULL;
    mpi_mulpowm( t1, base, exp, pkey->p );

    /* t2 = g ^ input mod p */
    mpi_powm( t2, pkey->g, input, pkey->p );

    rc = !mpi_cmp( t1, t2 );
  #else
    /* t1 = g ^ - input * y ^ a * a ^ b  mod p */
    mpi_invm(t2, pkey->g, pkey->p );
    base[0] = t2     ; exp[0] = input;
    base[1] = pkey->y; exp[1] = a;
    base[2] = a;       exp[2] = b;
    base[3] = NULL;    exp[3] = NULL;
    mpi_mulpowm( t1, base, exp, pkey->p );
    rc = !mpi_cmp_ui( t1, 1 );

  #endif

    mpi_free(t1);
    mpi_free(t2);
    return rc;
}

/*********************************************
 **************  interface  ******************
 *********************************************/

int
elg_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;

    generate( &sk, nbits, retfactors );
    skey[0] = sk.p;
    skey[1] = sk.g;
    skey[2] = sk.y;
    skey[3] = sk.x;
    return 0;
}


int
elg_check_secret_key( int algo, MPI *skey )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;
    if( !skey[0] || !skey[1] || !skey[2] || !skey[3] )
	return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.g = skey[1];
    sk.y = skey[2];
    sk.x = skey[3];
    if( !check_secret_key( &sk ) )
	return G10ERR_BAD_SECKEY;

    return 0;
}



int
elg_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
    ELG_public_key pk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;
    if( !data || !pkey[0] || !pkey[1] || !pkey[2] )
	return G10ERR_BAD_MPI;

    pk.p = pkey[0];
    pk.g = pkey[1];
    pk.y = pkey[2];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
    resarr[1] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
    encrypt( resarr[0], resarr[1], data, &pk );
    return 0;
}

int
elg_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;
    if( !data[0] || !data[1]
	|| !skey[0] || !skey[1] || !skey[2] || !skey[3] )
	return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.g = skey[1];
    sk.y = skey[2];
    sk.x = skey[3];
    *result = mpi_alloc_secure( mpi_get_nlimbs( sk.p ) );
    decrypt( *result, data[0], data[1], &sk );
    return 0;
}

int
elg_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;
    if( !data || !skey[0] || !skey[1] || !skey[2] || !skey[3] )
	return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.g = skey[1];
    sk.y = skey[2];
    sk.x = skey[3];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
    resarr[1] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
    sign( resarr[0], resarr[1], data, &sk );
    return 0;
}

int
elg_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI) UNUSED, void *opaquev UNUSED)
{
    ELG_public_key pk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;
    if( !data[0] || !data[1] || !hash
	|| !pkey[0] || !pkey[1] || !pkey[2] )
	return G10ERR_BAD_MPI;

    pk.p = pkey[0];
    pk.g = pkey[1];
    pk.y = pkey[2];
    if( !verify( data[0], data[1], hash, &pk ) )
	return G10ERR_BAD_SIGN;
    return 0;
}



unsigned
elg_get_nbits( int algo, MPI *pkey )
{
    if( !is_ELGAMAL(algo) )
	return 0;
    return mpi_get_nbits( pkey[0] );
}


/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 * Usage: Bit 0 set : allows signing
 *	      1 set : allows encryption
 * NOTE: This function allows signing also for ELG-E, which is not
 * okay but a bad hack to allow to work with old gpg keys. The real check
 * is done in the gnupg ocde depending on the packet version.
 */
const char *
elg_get_info( int algo, int *npkey, int *nskey, int *nenc, int *nsig,
							 int *use )
{
    *npkey = 3;
    *nskey = 4;
    *nenc = 2;
    *nsig = 2;

    switch( algo ) {
      case PUBKEY_ALGO_ELGAMAL:
	*use = PUBKEY_USAGE_SIG|PUBKEY_USAGE_ENC;
	return "ELG";
      case PUBKEY_ALGO_ELGAMAL_E:
	*use = PUBKEY_USAGE_SIG|PUBKEY_USAGE_ENC;
	return "ELG-E";
      default: *use = 0; return NULL;
    }
}


