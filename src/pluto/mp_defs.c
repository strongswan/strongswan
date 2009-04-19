/* some multiprecision utilities
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "mp_defs.h"
#include "log.h"

/* Convert MP_INT to network form (binary octets, big-endian).
 * We do the malloc; caller must eventually do free.
 */
chunk_t
mpz_to_n(const MP_INT *mp, size_t bytes)
{
	chunk_t r;
	MP_INT temp1, temp2;
	int i;

	r.len = bytes;
	r.ptr = malloc(r.len);

	mpz_init(&temp1);
	mpz_init(&temp2);

	mpz_set(&temp1, mp);

	for (i = r.len-1; i >= 0; i--)
	{
		r.ptr[i] = mpz_mdivmod_ui(&temp2, NULL, &temp1, 1 << BITS_PER_BYTE);
		mpz_set(&temp1, &temp2);
	}

	passert(mpz_sgn(&temp1) == 0);      /* we must have done all the bits */
	mpz_clear(&temp1);
	mpz_clear(&temp2);

	return r;
}

/* Convert network form (binary bytes, big-endian) to MP_INT.
 * The *mp must not be previously mpz_inited.
 */
void
n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen)
{
	size_t i;

	mpz_init_set_ui(mp, 0);

	for (i = 0; i != nlen; i++)
	{
		mpz_mul_ui(mp, mp, 1 << BITS_PER_BYTE);
		mpz_add_ui(mp, mp, nbytes[i]);
	}
}
