/* crypto interfaces
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

#include <crypto/hashers/hasher.h>
#include <crypto/hashers/hasher.h>
#include <crypto/prfs/prf.h>

#include "ike_alg.h"

extern void init_crypto(void);
extern void free_crypto(void);

/* Oakley group descriptions */

extern MP_INT groupgenerator;   /* MODP group generator (2) */

struct oakley_group_desc {
	u_int16_t group;
	MP_INT *modulus;
	size_t bytes;
};

extern const struct oakley_group_desc unset_group;      /* magic signifier */
extern const struct oakley_group_desc *lookup_group(u_int16_t group);
#define OAKLEY_GROUP_SIZE 7
extern const struct oakley_group_desc oakley_group[OAKLEY_GROUP_SIZE];

/* unification of cryptographic encoding/decoding algorithms
 * The IV is taken from and returned to st->st_new_iv.
 * This allows the old IV to be retained.
 * Use update_iv to commit to the new IV (for example, once a packet has
 * been validated).
 */

#define MAX_OAKLEY_KEY_LEN0  (3 * DES_CBC_BLOCK_SIZE)
#define MAX_OAKLEY_KEY_LEN  (256/BITS_PER_BYTE)

struct state;   /* forward declaration, dammit */

void crypto_cbc_encrypt(const struct encrypt_desc *e, bool enc, u_int8_t *buf, size_t size, struct state *st);

#define update_iv(st)   memcpy((st)->st_iv, (st)->st_new_iv \
	, (st)->st_iv_len = (st)->st_new_iv_len)

#define set_ph1_iv(st, iv) \
	passert((st)->st_ph1_iv_len <= sizeof((st)->st_ph1_iv)); \
	memcpy((st)->st_ph1_iv, (iv), (st)->st_ph1_iv_len);

/* unification of cryptographic hashing mechanisms */

extern encryption_algorithm_t oakley_to_encryption_algorithm(int alg);
extern hash_algorithm_t oakley_to_hash_algorithm(int alg);
extern pseudo_random_function_t oakley_to_prf(int alg);

