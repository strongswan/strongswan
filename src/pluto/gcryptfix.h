/* Definitions to make gcrypt routines feel at home in Pluto.
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

#define DBG_CIPHER  1   /* some day we'll do this right */

/* Simulate MPI routines with gmp routines.
 * gmp's MP_INT is a stuct; MPI's MPI is a pointer to an analogous struct.
 * gmp's mpz_t is an array of one of these structs to enable magic pointer
 * conversions to make the notation convenient (but confusing).
 */
typedef u_char byte;
typedef MP_INT *MPI;

#define BITS_PER_MPI_LIMB mp_bits_per_limb

extern MPI mpi_alloc( unsigned nlimbs );
extern MPI mpi_alloc_secure( unsigned nlimbs );
#define mpi_alloc_like(n) mpi_alloc(mpi_get_nlimbs(n))
extern MPI mpi_alloc_set_ui( unsigned long u);
#define mpi_set_ui(w, u) mpz_set_ui(w, u)
#define mpi_set(w, u) mpz_set(w, u)
extern void mpi_free( MPI a );
extern MPI  mpi_copy( MPI a );
extern unsigned mpi_get_nbits( MPI a );
#define mpi_get_nlimbs(a)     ((a)->_mp_alloc)  /* dirty, but useless */
extern void  mpi_set_buffer( MPI a, const u_char *buffer, unsigned nbytes, int sign );
extern unsigned mpi_trailing_zeros( MPI a );
extern int  mpi_test_bit( MPI a, unsigned n );
extern void mpi_set_bit( MPI a, unsigned n );
extern void mpi_clear_bit( MPI a, unsigned n );
extern void mpi_clear_highbit( MPI a, unsigned n );
extern void mpi_set_highbit( MPI a, unsigned n );
#define mpi_cmp_ui(u, v) mpz_cmp_ui((u), (v))
#define mpi_cmp(u, v) mpz_cmp((u), (v))
#define mpi_is_neg(n) (mpz_sgn(n) < 0)
#define mpi_add(w, u, v) mpz_add((w), (u), (v))
#define mpi_add_ui(w, u, v) mpz_add_ui((w), (u), (v))
#define mpi_sub_ui(w, u, v) mpz_sub_ui((w), (u), (v))
#define mpi_subm( w, u, v, m) { mpz_sub( (w), (u), (v)) ; mpz_fdiv_r((w), (w), (m)); }
#define mpi_mul( w, u, v) mpz_mul( (w), (u), (v))
#define mpi_mul_ui( w, u, v) mpz_mul_ui( (w), (u), (v))
#define mpi_mulm( w, u, v, m) { mpz_mul( (w), (u), (v)) ; mpz_fdiv_r((w), (w), (m)); }
#define mpi_fdiv_q(quot, dividend, divisor) mpz_fdiv_q((quot), (dividend), (divisor))
#define mpi_fdiv_r( rem, dividend, divisor ) mpz_fdiv_r( (rem), (dividend), (divisor) )
#define mpi_fdiv_r_ui( rem, dividend, divisor )  mpz_fdiv_r_ui( (rem), (dividend), (divisor) )
#define mpi_tdiv_q_2exp( w, u, count ) mpz_tdiv_q_2exp( (w), (u), (count) )
extern int   mpi_divisible_ui(MPI dividend, ulong divisor );
#define mpi_powm( res, base, exp, mod) mpz_powm( res, base, exp, mod)
extern void mpi_mulpowm( MPI res, MPI *basearray, MPI *exparray, MPI mod);
#define mpi_gcd( g, a, b ) ( mpz_gcd( (g), (a), (b) ), !mpi_cmp_ui( (g), 1))
#define mpi_invm( x, a, n ) mpz_invert( (x), (a), (n) )

#ifdef DEBUG
# define log_debug(f...)  DBG_log(f)
#else
# define log_debug(f...)  do ; while (0)        /* do nothing, carefully */
#endif
#define log_fatal(f...)  exit_log(f)    /* overreaction? */
extern void log_mpidump( const char *text, MPI a );

#define assert(p) passert(p)
#define BUG() passert(FALSE)

#define m_alloc_ptrs_clear(pp, n) { \
		int c = (n); \
		(pp) = malloc((n) * sizeof(*(pp))); \
		while (c > 0) (pp)[--c] = NULL; \
	}

extern u_char *get_random_bits(size_t nbits, int level, int secure);
#define m_alloc(sz) malloc((sz))        /* not initialized */
#define m_free(n) free(n)  /* always freeing something from get_random_bits */

/* declarations from gnupg-1.0.0/include/cipher.h */
/*-- primegen.c --*/
MPI generate_secret_prime( unsigned nbits );
MPI generate_public_prime( unsigned nbits );
MPI generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
										   MPI g, MPI **factors );

#define PUBKEY_ALGO_ELGAMAL_E 16     /* encrypt only ElGamal (but not for v3)*/
#define PUBKEY_ALGO_DSA       17
#define PUBKEY_ALGO_ELGAMAL   20     /* sign and encrypt elgamal */

#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)

#define PUBKEY_USAGE_SIG     1      /* key is good for signatures */
#define PUBKEY_USAGE_ENC     2      /* key is good for encryption */

/* from gnupg-1.0.0/include/errors.h */

#define G10ERR_PUBKEY_ALGO     4 /* Unknown pubkey algorithm */
#define G10ERR_BAD_SECKEY      7 /* Bad secret key */
#define G10ERR_BAD_SIGN        8 /* Bad signature */
#define G10ERR_BAD_MPI        30

/*-- smallprime.c --*/
extern ushort small_prime_numbers[];
