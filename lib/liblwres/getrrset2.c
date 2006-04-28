/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: getrrset2.c,v 1.1 2004/03/15 20:35:25 as Exp $ */

#include <config.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <lwres/lwres.h>
#include <lwres/net.h>
#include <lwres/netdb.h>	/* XXX #include <netdb.h> */

#include <lwres/async.h>

#include "assert_p.h"

int
lwres_getrrsetbyname_async(const char *hostname, unsigned int rdclass,
			   unsigned int rdtype, unsigned int flags,
			   struct rrsetinfo **res)
{
	int ret, ret2;
	lwres_context_t *ctx = NULL;
	struct lwres_async_state las;
	struct lwres_async_state *plas;
	struct timeval timeout;
	fd_set readfds;
	int    sock;

	ret = lwres_async_init(&ctx);
	if(ret != ERRSET_SUCCESS) {
		return(ret);
	}
	
	ret = lwres_getrrsetbyname_init(hostname, rdclass,
					rdtype, flags,
					ctx, &las);

	if(ret != ERRSET_SUCCESS) {
		return ret;
	}

	again:

	lwres_getrrsetbyname_xmit(ctx, &las);
	timeout.tv_sec = lwres_async_timeout(ctx);
	sock = lwres_async_fd(ctx);

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	ret2 = select(sock + 1, &readfds, NULL, NULL, &timeout);
	
	/*
	 * What happened with select?
	 */
	if (ret2 < 0) {
		ret = LWRES_R_IOERROR;
		goto out3;
	}
	if (ret2 == 0) {
		ret = LWRES_R_TIMEOUT;
		goto out3;
	}

	ret = lwres_getrrsetbyname_read(&plas, ctx, res);
	if(ret == LWRES_R_RETRY) {
		/* XXX retransmit */
		goto again;
	}

 out3:
	/* clean stuff up */

 out:
	if (ctx != NULL)
		lwres_context_destroy(&ctx);
	
	return ret;
}

