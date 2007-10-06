/* Routines to make gcrypt routines feel at home in Pluto.
 * Copyright (C) 1999  D. Hugh Redelmeier.
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
 * RCSID $Id$
 */

#include <stdlib.h>

#include <gmp.h>
#include <freeswan.h>
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "rnd.h"
#include "gcryptfix.h"	/* includes <gmp.h> "defs.h" "rnd.h" */

MPI
mpi_alloc( unsigned nlimbs UNUSED )
{
    MPI n = alloc_bytes(sizeof *n, "mpi_alloc");

    mpz_init(n);
    return n;
}

MPI
mpi_alloc_secure( unsigned nlimbs )
{
    return mpi_alloc(nlimbs);
}

MPI
mpi_alloc_set_ui( unsigned long u)
{
    MPI n = alloc_bytes(sizeof *n, "mpi_copy");

    mpz_init_set_ui(n, u);
    return n;
}

MPI
mpi_copy( MPI a )
{
    MPI n = alloc_bytes(sizeof *n, "mpi_copy");

    mpz_init_set(n, a);
    return n;
}

void
mpi_free( MPI a )
{
    mpz_clear(a);
    pfree(a);
}

int
mpi_divisible_ui(MPI dividend, ulong divisor )
{
    ulong rem;
    mpz_t remtoo;

    mpz_init(remtoo);
    rem = mpz_mod_ui(remtoo, dividend, divisor);
    mpz_clear(remtoo);
    return rem == 0;
}

unsigned
mpi_trailing_zeros( MPI a )
{
    return mpz_scan1(a, 0);
}

unsigned
mpi_get_nbits( MPI a )
{
    return mpz_sizeinbase(a, 2);
}

int
mpi_test_bit( MPI a, unsigned n )
{
    /* inspired by gmp/mpz/clrbit.c */
    mp_size_t li = n / mp_bits_per_limb;

    if (li >= a->_mp_size)
	return 0;
    return (a->_mp_d[li] & ((mp_limb_t) 1 << (n % mp_bits_per_limb))) != 0;
}

void
mpi_set_bit( MPI a, unsigned n )
{
    mpz_setbit(a, n);
}

void
mpi_clear_bit( MPI a, unsigned n )
{
    mpz_clrbit(a, n);
}

void
mpi_clear_highbit( MPI a, unsigned n )
{
    /* This seems whacky, but what do I know. */
    mpz_fdiv_r_2exp(a, a, n);
}

void
mpi_set_highbit( MPI a, unsigned n )
{
    /* This seems whacky, but what do I know. */
    mpz_fdiv_r_2exp(a, a, n+1);
    mpz_setbit(a, n);
}

void
mpi_set_buffer( MPI a, const u_char *buffer, unsigned nbytes, int sign )
{
    /* this is a lot like n_to_mpz */
    size_t i;

    passert(sign == 0);	/* we won't hit any negative numbers */
    mpz_init_set_ui(a, 0);

    for (i = 0; i != nbytes; i++)
    {
	mpz_mul_ui(a, a, 1 << BITS_PER_BYTE);
	mpz_add_ui(a, a, buffer[i]);
    }
}

u_char *
get_random_bits(size_t nbits, int level UNUSED, int secure UNUSED)
{
    size_t nbytes = (nbits+7)/8;
    u_char *b = alloc_bytes(nbytes, "random bytes");

    get_rnd_bytes(b, nbytes);
    return b;
}
/**************** from gnupg-1.0.0/mpi/mpi-mpow.c
 * RES = (BASE[0] ^ EXP[0]) *  (BASE[1] ^ EXP[1]) * ... * mod M
 */
#define barrett_mulm( w, u, v, m, y, k, r1, r2 ) mpi_mulm( (w), (u), (v), (m) )

static int
build_index( MPI *exparray, int k, int i, int t )
{
    int j, bitno;
    int index = 0;

    bitno = t-i;
    for(j=k-1; j >= 0; j-- ) {
	index <<= 1;
	if( mpi_test_bit( exparray[j], bitno ) )
	    index |= 1;
    }
    /*log_debug("t=%d i=%d index=%d\n", t, i, index );*/
    return index;
}

void
mpi_mulpowm( MPI res, MPI *basearray, MPI *exparray, MPI m)
{
    int k;	/* number of elements */
    int t;	/* bit size of largest exponent */
    int i, j, idx;
    MPI *G;	/* table with precomputed values of size 2^k */
    MPI tmp;
  #ifdef USE_BARRETT
    MPI barrett_y, barrett_r1, barrett_r2;
    int barrett_k;
  #endif

    for(k=0; basearray[k]; k++ )
	;
    passert(k);
    for(t=0, i=0; (tmp=exparray[i]); i++ ) {
	/*log_mpidump("exp: ", tmp );*/
	j = mpi_get_nbits(tmp);
	if( j > t )
	    t = j;
    }
    /*log_mpidump("mod: ", m );*/
    passert(i==k);
    passert(t);
    passert( k < 10 );

#ifdef PLUTO
    m_alloc_ptrs_clear(G, 1<<k);
#else
    G = m_alloc_clear( (1<<k) * sizeof *G );
#endif

  #ifdef USE_BARRETT
    barrett_y = init_barrett( m, &barrett_k, &barrett_r1, &barrett_r2 );
  #endif
    /* and calculate */
    tmp =  mpi_alloc( mpi_get_nlimbs(m)+1 );
    mpi_set_ui( res, 1 );
    for(i = 1; i <= t; i++ ) {
	barrett_mulm(tmp, res, res, m, barrett_y, barrett_k,
				       barrett_r1, barrett_r2 );
	idx = build_index( exparray, k, i, t );
	passert( idx >= 0 && idx < (1<<k) );
	if( !G[idx] ) {
	    if( !idx )
		 G[0] = mpi_alloc_set_ui( 1 );
	    else {
		for(j=0; j < k; j++ ) {
		    if( (idx & (1<<j) ) ) {
			if( !G[idx] )
			    G[idx] = mpi_copy( basearray[j] );
			else
			    barrett_mulm( G[idx], G[idx], basearray[j],
					       m, barrett_y, barrett_k, barrett_r1, barrett_r2	);
		    }
		}
		if( !G[idx] )
		    G[idx] = mpi_alloc(0);
	    }
	}
	barrett_mulm(res, tmp, G[idx], m, barrett_y, barrett_k, barrett_r1, barrett_r2	);
    }

    /* cleanup */
    mpi_free(tmp);
  #ifdef USE_BARRETT
    mpi_free(barrett_y);
    mpi_free(barrett_r1);
    mpi_free(barrett_r2);
  #endif
    for(i=0; i < (1<<k); i++ )
	mpi_free(G[i]);
    m_free(G);
}

void
log_mpidump( const char *text UNUSED, MPI a )
{
    /* Print number in hex -- helpful to see if they match bytes.
     * Humans are not going to do arithmetic with the large numbers!
     * Much code adapted from mpz_to_n.
     */
    u_char buf[8048];	/* this ought to be big enough */
    size_t len = (mpz_sizeinbase(a, 16) + 1) / 2;   /* bytes */
    MP_INT temp1, temp2;
    int i;

    passert(len <= sizeof(buf));

    mpz_init(&temp1);
    mpz_init(&temp2);

    mpz_set(&temp1, a);

    for (i = len-1; i >= 0; i--)
    {
	buf[i] = mpz_mdivmod_ui(&temp2, NULL, &temp1, 1 << BITS_PER_BYTE);
	mpz_set(&temp1, &temp2);
    }

    passert(mpz_sgn(&temp1) == 0);	/* we must have done all the bits */
    mpz_clear(&temp1);
    mpz_clear(&temp2);

#ifdef DEBUG
    DBG_dump(text, buf, len);
#endif /* DEBUG */
}
