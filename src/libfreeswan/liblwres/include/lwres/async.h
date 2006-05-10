/*
 * Copyright (C) 2003  Michael Richardson
 * Contributed by Michael Richardson <mcr@freeswan.org> while working
 * on the Linux FreeS/WAN project in 2003.
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

/* $Id: async.h,v 1.1 2004/03/15 20:35:25 as Exp $ */

#ifndef LWRES_ASYNC_H
#define LWRES_ASYNC_H 1

#include <lwres/lwres.h>

/*
 * support for asynchronous requests to lwres port
 */
struct lwres_async_state {
	struct lwres_async_state *next;

	lwres_buffer_t            b_in, b_out;
	lwres_uint32_t            serial;
	int                       opcode;

	int (*callback)(void *uctx, struct rrsetinfo *res);
	void *uctx;
};



/*
 * The calls for asynchronous requests.
 */

int lwres_async_init(lwres_context_t **pctx);

int lwres_getrrsetbyname_init(const char *hostname, unsigned int rdclass,
			      unsigned int rdtype, unsigned int flags,
			      lwres_context_t *ctx,
			      struct lwres_async_state *las);

int lwres_getrrsetbyname_xmit(lwres_context_t *ctx,
			      struct lwres_async_state *las);

unsigned long lwres_async_timeout(lwres_context_t *ctx);

int lwres_async_fd(lwres_context_t *ctx);

int lwres_getrrsetbyname_read(struct lwres_async_state **plas,
			      lwres_context_t *ctx,
			      struct rrsetinfo **res);

int lwres_getrrsetbyname_async(const char *hostname, unsigned int rdclass,
			       unsigned int rdtype, unsigned int flags,
			       struct rrsetinfo **res);

#endif /* LWRES_ASYNC_H */









