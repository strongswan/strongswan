/* cookie generation/verification routines.
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <freeswan.h>

#include <library.h>
#include <crypto/rngs/rng.h>

#include "constants.h"
#include "defs.h"
#include "cookie.h"

const u_char zero_cookie[COOKIE_SIZE];  /* guaranteed 0 */

/* Generate a cookie.
 * First argument is true if we're to create an Initiator cookie.
 * Length SHOULD be a multiple of sizeof(u_int32_t).
 */
void get_cookie(bool initiator, u_int8_t *cookie, int length, ip_address *addr)
{
	hasher_t *hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	u_char buffer[HASH_SIZE_SHA1];

	do {
		if (initiator)
		{
			rng_t *rng;

			rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
			rng->get_bytes(rng, length, cookie);
			rng->destroy(rng);
		}
		else  /* Responder cookie */
		{
			chunk_t addr_chunk, secret_chunk, counter_chunk;
			size_t addr_len;
			static u_int32_t counter = 0;
			unsigned char addr_buf[
				sizeof(union {struct in_addr A; struct in6_addr B;})];

			addr_len = addrbytesof(addr, addr_buf, sizeof(addr_buf));
			addr_chunk = chunk_create(addr_buf, addr_len);
			secret_chunk = chunk_create(secret_of_the_day, HASH_SIZE_SHA1);
			counter++;
			counter_chunk = chunk_create((void *) &counter, sizeof(counter));
			hasher->get_hash(hasher, addr_chunk, NULL);
			hasher->get_hash(hasher, secret_chunk, NULL);
			hasher->get_hash(hasher, counter_chunk, buffer);
			memcpy(cookie, buffer, length);
		}
	} while (is_zero_cookie(cookie));   /* probably never loops */

	hasher->destroy(hasher);
}
