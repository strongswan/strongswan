/* some multiprecision utilities
 * Copyright (C) 1997 Angelos D. Keromytis.
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
 */

#ifndef _MP_DEFS_H
#define _MP_DEFS_H

#include <gmp.h>

#include <utils.h>

extern void n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen);
extern chunk_t mpz_to_n(const MP_INT *mp, size_t bytes);
extern chunk_t asn1_integer_from_mpz(const mpz_t value);

/* var := mod(base ** exp, mod), ensuring var is mpz_inited */
#define mpz_init_powm(flag, var, base, exp, mod) { \
	if (!(flag)) \
		mpz_init(&(var)); \
	(flag) = TRUE; \
	mpz_powm(&(var), &(base), &(exp), (mod)); \
	}

#endif /* _MP_DEFS_H */
