/* dsa.c  -  DSA signature scheme
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
/* #include <assert.h> */
/* #include "util.h" */
/* #include "mpi.h" */
/* #include "cipher.h" */
#endif

#include "dsa.h"

typedef struct {
    MPI p;	    /* prime */
    MPI q;	    /* group order */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
} DSA_public_key;


typedef struct {
    MPI p;	    /* prime */
    MPI q;	    /* group order */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
    MPI x;	    /* secret exponent */
} DSA_secret_key;


static MPI gen_k( MPI q );
static void test_keys( DSA_secret_key *sk, unsigned qbits );
static int  check_secret_key( DSA_secret_key *sk );
static void generate( DSA_secret_key *sk, unsigned nbits, MPI **ret_factors );
static void sign(MPI r, MPI s, MPI input, DSA_secret_key *skey);
static int  verify(MPI r, MPI s, MPI input, DSA_public_key *pkey);

static void
progress( int c )
{
    fputc( c, stderr );
}


/****************
 * Generate a random secret exponent k less than q
 */
static MPI
gen_k( MPI q )
{
    MPI k = mpi_alloc_secure( mpi_get_nlimbs(q) );
    unsigned int nbits = mpi_get_nbits(q);
    unsigned int nbytes = (nbits+7)/8;
    char *rndbuf = NULL;

    if( DBG_CIPHER )
	log_debug("choosing a random k ");
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
	if( mpi_test_bit( k, nbits-1 ) )
	    mpi_set_highbit( k, nbits-1 );
	else {
	    mpi_set_highbit( k, nbits-1 );
	    mpi_clear_bit( k, nbits-1 );
	}

	if( !(mpi_cmp( k, q ) < 0) ) {	/* check: k < q */
	    if( DBG_CIPHER )
		progress('+');
	    continue; /* no  */
	}
	if( !(mpi_cmp_ui( k, 0 ) > 0) ) { /* check: k > 0 */
	    if( DBG_CIPHER )
		progress('-');
	    continue; /* no */
	}
	break;	/* okay */
    }
    m_free(rndbuf);
    if( DBG_CIPHER )
	progress('\n');

    return k;
}


static void
test_keys( DSA_secret_key *sk, unsigned qbits )
{
    DSA_public_key pk;
    MPI test = mpi_alloc( qbits / BITS_PER_MPI_LIMB );
    MPI out1_a = mpi_alloc( qbits / BITS_PER_MPI_LIMB );
    MPI out1_b = mpi_alloc( qbits / BITS_PER_MPI_LIMB );

    pk.p = sk->p;
    pk.q = sk->q;
    pk.g = sk->g;
    pk.y = sk->y;
    /*mpi_set_bytes( test, qbits, get_random_byte, 0 );*/
    {	char *p = get_random_bits( qbits, 0, 0 );
	mpi_set_buffer( test, p, (qbits+7)/8, 0 );
	m_free(p);
    }

    sign( out1_a, out1_b, test, sk );
    if( !verify( out1_a, out1_b, test, &pk ) )
	log_fatal("DSA:: sign, verify failed\n");

    mpi_free( test );
    mpi_free( out1_a );
    mpi_free( out1_b );
}



/****************
 * Generate a DSA key pair with a key of size NBITS
 * Returns: 2 structures filled with all needed values
 *	    and an array with the n-1 factors of (p-1)
 */
static void
generate( DSA_secret_key *sk, unsigned nbits, MPI **ret_factors )
{
    MPI p;    /* the prime */
    MPI q;    /* the 160 bit prime factor */
    MPI g;    /* the generator */
    MPI y;    /* g^x mod p */
    MPI x;    /* the secret exponent */
    MPI h, e;  /* helper */
    unsigned qbits;
    byte *rndbuf;

    assert( nbits >= 512 && nbits <= 1024 );

    qbits = 160;
    p = generate_elg_prime( 1, nbits, qbits, NULL, ret_factors );
    /* get q out of factors */
    q = mpi_copy((*ret_factors)[0]);
    if( mpi_get_nbits(q) != qbits )
	BUG();

    /* find a generator g (h and e are helpers)*/
    /* e = (p-1)/q */
    e = mpi_alloc( mpi_get_nlimbs(p) );
    mpi_sub_ui( e, p, 1 );
    mpi_fdiv_q( e, e, q );
    g = mpi_alloc( mpi_get_nlimbs(p) );
    h = mpi_alloc_set_ui( 1 ); /* we start with 2 */
    do {
	mpi_add_ui( h, h, 1 );
	/* g = h^e mod p */
	mpi_powm( g, h, e, p );
    } while( !mpi_cmp_ui( g, 1 ) );  /* continue until g != 1 */

    /* select a random number which has these properties:
     *	 0 < x < q-1
     * This must be a very good random number because this
     * is the secret part. */
    if( DBG_CIPHER )
	log_debug("choosing a random x ");
    assert( qbits >= 160 );
    x = mpi_alloc_secure( mpi_get_nlimbs(q) );
    mpi_sub_ui( h, q, 1 );  /* put q-1 into h */
    rndbuf = NULL;
    do {
	if( DBG_CIPHER )
	    progress('.');
	if( !rndbuf )
	    rndbuf = get_random_bits( qbits, 2, 1 );
	else { /* change only some of the higher bits (= 2 bytes)*/
	    char *r = get_random_bits( 16, 2, 1 );
	    memcpy(rndbuf, r, 16/8 );
	    m_free(r);
	}
	mpi_set_buffer( x, rndbuf, (qbits+7)/8, 0 );
	mpi_clear_highbit( x, qbits+1 );
    } while( !( mpi_cmp_ui( x, 0 )>0 && mpi_cmp( x, h )<0 ) );
    m_free(rndbuf);
    mpi_free( e );
    mpi_free( h );

    /* y = g^x mod p */
    y = mpi_alloc( mpi_get_nlimbs(p) );
    mpi_powm( y, g, x, p );

    if( DBG_CIPHER ) {
	progress('\n');
	log_mpidump("dsa  p= ", p );
	log_mpidump("dsa  q= ", q );
	log_mpidump("dsa  g= ", g );
	log_mpidump("dsa  y= ", y );
	log_mpidump("dsa  x= ", x );
    }

    /* copy the stuff to the key structures */
    sk->p = p;
    sk->q = q;
    sk->g = g;
    sk->y = y;
    sk->x = x;

    /* now we can test our keys (this should never fail!) */
    test_keys( sk, qbits );
}



/****************
 * Test whether the secret key is valid.
 * Returns: if this is a valid key.
 */
static int
check_secret_key( DSA_secret_key *sk )
{
    int rc;
    MPI y = mpi_alloc( mpi_get_nlimbs(sk->y) );

    mpi_powm( y, sk->g, sk->x, sk->p );
    rc = !mpi_cmp( y, sk->y );
    mpi_free( y );
    return rc;
}



/****************
 * Make a DSA signature from HASH and put it into r and s.
 */

static void
sign(MPI r, MPI s, MPI hash, DSA_secret_key *skey )
{
    MPI k;
    MPI kinv;
    MPI tmp;

    /* select a random k with 0 < k < q */
    k = gen_k( skey->q );

    /* r = (a^k mod p) mod q */
    mpi_powm( r, skey->g, k, skey->p );
    mpi_fdiv_r( r, r, skey->q );

    /* kinv = k^(-1) mod q */
    kinv = mpi_alloc( mpi_get_nlimbs(k) );
    mpi_invm(kinv, k, skey->q );

    /* s = (kinv * ( hash + x * r)) mod q */
    tmp = mpi_alloc( mpi_get_nlimbs(skey->p) );
    mpi_mul( tmp, skey->x, r );
    mpi_add( tmp, tmp, hash );
    mpi_mulm( s , kinv, tmp, skey->q );

    mpi_free(k);
    mpi_free(kinv);
    mpi_free(tmp);
}


/****************
 * Returns true if the signature composed from R and S is valid.
 */
static int
verify(MPI r, MPI s, MPI hash, DSA_public_key *pkey )
{
    int rc;
    MPI w, u1, u2, v;
    MPI base[3];
    MPI exp[3];


    if( !(mpi_cmp_ui( r, 0 ) > 0 && mpi_cmp( r, pkey->q ) < 0) )
	return 0; /* assertion	0 < r < q  failed */
    if( !(mpi_cmp_ui( s, 0 ) > 0 && mpi_cmp( s, pkey->q ) < 0) )
	return 0; /* assertion	0 < s < q  failed */

    w  = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    u1 = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    u2 = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    v  = mpi_alloc( mpi_get_nlimbs(pkey->p) );

    /* w = s^(-1) mod q */
    mpi_invm( w, s, pkey->q );

    /* u1 = (hash * w) mod q */
    mpi_mulm( u1, hash, w, pkey->q );

    /* u2 = r * w mod q  */
    mpi_mulm( u2, r, w, pkey->q );

    /* v =  g^u1 * y^u2 mod p mod q */
    base[0] = pkey->g; exp[0] = u1;
    base[1] = pkey->y; exp[1] = u2;
    base[2] = NULL;    exp[2] = NULL;
    mpi_mulpowm( v, base, exp, pkey->p );
    mpi_fdiv_r( v, v, pkey->q );

    rc = !mpi_cmp( v, r );

    mpi_free(w);
    mpi_free(u1);
    mpi_free(u2);
    mpi_free(v);
    return rc;
}


/*********************************************
 **************  interface  ******************
 *********************************************/

int
dsa_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{
    DSA_secret_key sk;

    if( algo != PUBKEY_ALGO_DSA )
	return G10ERR_PUBKEY_ALGO;

    generate( &sk, nbits, retfactors );
    skey[0] = sk.p;
    skey[1] = sk.q;
    skey[2] = sk.g;
    skey[3] = sk.y;
    skey[4] = sk.x;
    return 0;
}


int
dsa_check_secret_key( int algo, MPI *skey )
{
    DSA_secret_key sk;

    if( algo != PUBKEY_ALGO_DSA )
	return G10ERR_PUBKEY_ALGO;
    if( !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] )
	return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.q = skey[1];
    sk.g = skey[2];
    sk.y = skey[3];
    sk.x = skey[4];
    if( !check_secret_key( &sk ) )
	return G10ERR_BAD_SECKEY;

    return 0;
}



int
dsa_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
    DSA_secret_key sk;

    if( algo != PUBKEY_ALGO_DSA )
	return G10ERR_PUBKEY_ALGO;
    if( !data || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] )
	return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.q = skey[1];
    sk.g = skey[2];
    sk.y = skey[3];
    sk.x = skey[4];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
    resarr[1] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
    sign( resarr[0], resarr[1], data, &sk );
    return 0;
}

int
dsa_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI) UNUSED, void *opaquev UNUSED)
{
    DSA_public_key pk;

    if( algo != PUBKEY_ALGO_DSA )
	return G10ERR_PUBKEY_ALGO;
    if( !data[0] || !data[1] || !hash
	|| !pkey[0] || !pkey[1] || !pkey[2] || !pkey[3] )
	return G10ERR_BAD_MPI;

    pk.p = pkey[0];
    pk.q = pkey[1];
    pk.g = pkey[2];
    pk.y = pkey[3];
    if( !verify( data[0], data[1], hash, &pk ) )
	return G10ERR_BAD_SIGN;
    return 0;
}



unsigned
dsa_get_nbits( int algo, MPI *pkey )
{
    if( algo != PUBKEY_ALGO_DSA )
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
 */
const char *
dsa_get_info( int algo, int *npkey, int *nskey, int *nenc, int *nsig,
							 int *use )
{
    *npkey = 4;
    *nskey = 5;
    *nenc = 0;
    *nsig = 2;

    switch( algo ) {
      case PUBKEY_ALGO_DSA:   *use = PUBKEY_USAGE_SIG; return "DSA";
      default: *use = 0; return NULL;
    }
}


