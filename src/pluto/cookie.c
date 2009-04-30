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

#include "constants.h"
#include "defs.h"
#include "sha1.h"
#include "rnd.h"
#include "cookie.h"

const u_char zero_cookie[COOKIE_SIZE];  /* guaranteed 0 */

/* Generate a cookie.
 * First argument is true if we're to create an Initiator cookie.
 * Length SHOULD be a multiple of sizeof(u_int32_t).
 */
void
get_cookie(bool initiator, u_int8_t *cookie, int length, const ip_address *addr)
{
	u_char buffer[SHA1_DIGEST_SIZE];
	SHA1_CTX ctx;

	do {
		if (initiator)
		{
			get_rnd_bytes(cookie, length);
		}
		else  /* Responder cookie */
		{
			/* This looks as good as any way */
			size_t addr_length;
			static u_int32_t counter = 0;
			unsigned char addr_buff[
				sizeof(union {struct in_addr A; struct in6_addr B;})];

			addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));
			SHA1Init(&ctx);
			SHA1Update(&ctx, addr_buff, addr_length);
			SHA1Update(&ctx, secret_of_the_day, sizeof(secret_of_the_day));
			counter++;
			SHA1Update(&ctx, (const void *) &counter, sizeof(counter));
			SHA1Final(buffer, &ctx);
			memcpy(cookie, buffer, length);
		}
	} while (is_zero_cookie(cookie));   /* probably never loops */
}
