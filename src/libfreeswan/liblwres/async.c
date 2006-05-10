/*
 * Copyright (C) 2003, Michael Richardson <mcr@freeswawn.org>
 * Derived from code:  Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: async.c,v 1.1 2004/03/15 20:35:25 as Exp $ */

#include <config.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <lwres/lwres.h>
#include <lwres/net.h>
#include <lwres/netdb.h>	/* XXX #include <netdb.h> */
#include <lwres/async.h>

#include "assert_p.h"
#include "context_p.h"

/*
 * malloc / calloc functions that guarantee to only
 * return NULL if there is an error, like they used
 * to before the ANSI C committee broke them.
 */

static void *
sane_malloc(size_t size) {
	if (size == 0)
		size = 1;
	return (malloc(size));
}

static void *
sane_calloc(size_t number, size_t size) {
	size_t len = number * size;
	void *mem  = sane_malloc(len);
	if (mem != NULL)
		memset(mem, 0, len);
	return (mem);
}

int 
lwres_async_init(lwres_context_t **pctx)
{
	lwres_result_t lwresult;
	lwres_context_t *ctx = NULL;
	int result;

	lwresult = lwres_context_create(&ctx, NULL, NULL, NULL, 0);
	if (lwresult != LWRES_R_SUCCESS) {
		result = lwresult_to_result(lwresult);
		return(result);
	}
	(void) lwres_conf_parse(ctx, lwres_resolv_conf);

	*pctx = ctx;
	return (ERRSET_SUCCESS);
}

int
lwres_getrrsetbyname_init(const char *hostname, unsigned int rdclass,
			  unsigned int rdtype, unsigned int flags,
			  lwres_context_t *ctx,
			  struct lwres_async_state *las)
{
	lwres_result_t lwresult;
	unsigned int i;
	unsigned int lwflags;
	unsigned int result;

	int ret;
	lwres_lwpacket_t pkt;
	lwres_grbnrequest_t request;
	char target_name[1024];
	unsigned int target_length;

	int ret2;

	if (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		return result;
	}

	/*
	 * Don't allow queries of class or type ANY
	 */
	if (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		return result;
	}

	/*
	 * If any input flags were defined, lwflags would be set here
	 * based on them
	 */
	UNUSED(flags);
	lwflags = 0;

	las->b_in.base = NULL;
	las->b_out.base = NULL;
	las->serial = lwres_context_nextserial(ctx);
	las->opcode = LWRES_OPCODE_GETRDATABYNAME;

	target_length = strlen(hostname);
	if (target_length >= sizeof(target_name))
		return (LWRES_R_FAILURE);
	strcpy(target_name, hostname); /* strcpy is safe */

	/*
	 * Set up our request and render it to a buffer.
	 */
	request.rdclass = rdclass;
	request.rdtype = rdtype;
	request.flags = lwflags;
	request.name = target_name;
	request.namelen = target_length;
	pkt.pktflags = 0;
	pkt.serial = las->serial;
	pkt.result = 0;
	pkt.recvlength = LWRES_RECVLENGTH;

	/* set up async system */
	las->next = ctx->pending;
	ctx->pending = las;

	ret = lwres_grbnrequest_render(ctx, &request, &pkt, &las->b_out);

	return ret;
}

int
lwres_getrrsetbyname_xmit(lwres_context_t *ctx,
			  struct lwres_async_state *las)
{
	lwres_result_t lwresult;
	int ret;

	lwresult = lwres_context_send(ctx, las->b_out.base, las->b_out.length);

	return(lwresult_to_result(lwresult));
}



unsigned long
lwres_async_timeout(lwres_context_t *ctx) 
{
	unsigned long tv_sec;

	/*
	 * Type of tv_sec is long, so make sure the unsigned long timeout
	 * does not overflow it.
	 */
	if (ctx->timeout <= LONG_MAX)
		tv_sec = (long)ctx->timeout;
	else
		tv_sec = LONG_MAX;

	return tv_sec;
}

int
lwres_async_fd(lwres_context_t *ctx) 
{
	return (ctx->sock);
}


/*
const char *hostname, unsigned int rdclass,
			  unsigned int rdtype, unsigned int flags,
*/
			  
int
lwres_getrrsetbyname_read(struct lwres_async_state **plas,
			  lwres_context_t *ctx,
			  struct rrsetinfo **res)
{
	lwres_result_t lwresult;
	lwres_grbnresponse_t *response = NULL;
	char *buffer;
	struct rrsetinfo *rrset = NULL;
	int recvlen;
	int ret, result, i;
	lwres_buffer_t            b_in;
	struct lwres_async_state *las;
	struct lwres_async_state **las_prev;
	lwres_lwpacket_t pkt;

	buffer = NULL;
	buffer = CTXMALLOC(LWRES_RECVLENGTH);
	if (buffer == NULL) {
		return ERRSET_NOMEMORY;
	}

	ret = LWRES_R_SUCCESS;
	lwresult = lwres_context_recv(ctx, buffer, LWRES_RECVLENGTH, &recvlen);
	if (lwresult == LWRES_R_RETRY) {
		ret = LWRES_R_RETRY;
		goto out;
	}
	
	if (ret != LWRES_R_SUCCESS) 
		goto out;

	lwres_buffer_init(&b_in, buffer, recvlen);
	b_in.used = recvlen;

	/*
	 * Parse the packet header.
	 */
	ret = lwres_lwpacket_parseheader(&b_in, &pkt);
	if (ret != LWRES_R_SUCCESS)
		goto out;

	/*
	 * find an appropriate waiting las entry. This is a linear search.
	 * we can do MUCH better, since we control the serial number!
	 * do that later.
	 */
	las_prev = &ctx->pending;
	las = ctx->pending;
	while(las && las->serial != pkt.serial) {
		las_prev=&las->next;
		las=las->next;
	}

	if(las == NULL) {
		/* no matching serial number! */
		return(LWRES_R_RETRY);
	}

	/* okay, remove it from the receive queue */
	*las_prev = las->next;
	las->next = NULL;

	*plas = las;

	/*
	 * Free what we've transmitted, long ago.
	 */
	CTXFREE(las->b_out.base, las->b_out.length);
	las->b_out.base = NULL;
	las->b_out.length = 0;

	if (pkt.result != LWRES_R_SUCCESS) {
		ret = pkt.result;
		goto out;
	}

	/*
	 * Parse the response.
	 */
	ret = lwres_grbnresponse_parse(ctx, &b_in, &pkt, &response);
	if (ret != LWRES_R_SUCCESS) {
	out:
		if (buffer != NULL)
			CTXFREE(buffer, LWRES_RECVLENGTH);
		if (response != NULL)
			lwres_grbnresponse_free(ctx, &response);
		result = lwresult_to_result(ret);
		goto fail;
	}

	response->base = buffer;
	response->baselen = LWRES_RECVLENGTH;
	buffer = NULL; /* don't free this below */

	lwresult = LWRES_R_SUCCESS;

	rrset = sane_malloc(sizeof(struct rrsetinfo));
	if (rrset == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}
	rrset->rri_name = NULL;
	rrset->rri_rdclass = response->rdclass;
	rrset->rri_rdtype = response->rdtype;
	rrset->rri_ttl = response->ttl;
	rrset->rri_flags = 0;
	rrset->rri_nrdatas = 0;
	rrset->rri_rdatas = NULL;
	rrset->rri_nsigs = 0;
	rrset->rri_sigs = NULL;

	rrset->rri_name = sane_malloc(response->realnamelen + 1);
	if (rrset->rri_name == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}
	strncpy(rrset->rri_name, response->realname, response->realnamelen);
	rrset->rri_name[response->realnamelen] = 0;

	if ((response->flags & LWRDATA_VALIDATED) != 0)
		rrset->rri_flags |= RRSET_VALIDATED;

	rrset->rri_nrdatas = response->nrdatas;
	rrset->rri_rdatas = sane_calloc(rrset->rri_nrdatas,
				   sizeof(struct rdatainfo));
	if (rrset->rri_rdatas == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}
	for (i = 0; i < rrset->rri_nrdatas; i++) {
		rrset->rri_rdatas[i].rdi_length = response->rdatalen[i];
		rrset->rri_rdatas[i].rdi_data =
				sane_malloc(rrset->rri_rdatas[i].rdi_length);
		if (rrset->rri_rdatas[i].rdi_data == NULL) {
			result = ERRSET_NOMEMORY;
			goto fail;
		}
		memcpy(rrset->rri_rdatas[i].rdi_data, response->rdatas[i],
		       rrset->rri_rdatas[i].rdi_length);
	}
	rrset->rri_nsigs = response->nsigs;
	rrset->rri_sigs = sane_calloc(rrset->rri_nsigs,
				      sizeof(struct rdatainfo));
	if (rrset->rri_sigs == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}
	for (i = 0; i < rrset->rri_nsigs; i++) {
		rrset->rri_sigs[i].rdi_length = response->siglen[i];
		rrset->rri_sigs[i].rdi_data =
				sane_malloc(rrset->rri_sigs[i].rdi_length);
		if (rrset->rri_sigs[i].rdi_data == NULL) {
			result = ERRSET_NOMEMORY;
			goto fail;
		}
		memcpy(rrset->rri_sigs[i].rdi_data, response->sigs[i],
		       rrset->rri_sigs[i].rdi_length);
	}

	lwres_grbnresponse_free(ctx, &response);

	*res = rrset;
	return (ERRSET_SUCCESS);
 fail:
	if (rrset != NULL)
		lwres_freerrset(rrset);
	if (response != NULL)
		lwres_grbnresponse_free(ctx, &response);
	return (result);

}

