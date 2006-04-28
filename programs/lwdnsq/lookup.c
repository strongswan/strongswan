/*
 * DNS KEY lookup helper
 * Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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

char lookup_c_version[] = "@(#) RCSID $Id: lookup.c,v 1.1 2004/03/15 20:35:28 as Exp $";


#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h> 

#include <freeswan.h>

#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
#include <ctype.h>
#include <signal.h>

#include <isc/mem.h>
#include <isc/buffer.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <dns/name.h>
#include <lwres/netdb.h>
#include <lwres/async.h>
#include "lwdnsq.h"

static int lwresd_has_spoken = 0;

char *xstrdup(const char *s)
{
	char *n;

	n = strdup(s);
	if(n == NULL) {
		abort();
	}
	return n;
}

void free_dl(dnskey_glob *gs, dnskey_lookup *dl)
{
	dnskey_lookup **walk;

	walk = &gs->dns_outstanding;
	while(*walk!=NULL && *walk != dl)
	{
		walk = &((*walk)->next);
	}
	if(*walk != NULL)
	{
		/* if we exit with it non-null, then we
		 * found a matching location, remove
		 * it.
		 */
		*walk = dl->next;
		dl->next = NULL;
	}
	gs->dns_inflight--;

	if(dl->tracking_id) {
		free(dl->tracking_id);
		dl->tracking_id = NULL;
	}
	if(dl->wantedtype_name) {
		free(dl->wantedtype_name);
		dl->wantedtype_name = NULL;
	}
	if(dl->fqdn) {
		free(dl->fqdn);
		dl->fqdn = NULL;
	}
#if 0
	if(dl->last_cname_used) {
		dns_name_free(&dl->last_cname, gs->iscmem);
	}
#endif
	
	free(dl);
}

void lookup_thing(dnskey_glob *gs,
		  dns_rdatatype_t wantedtype,
		  char *wantedtype_name,
		  char *id,
		  char *fqdn)
{
	isc_mem_t    *iscmem;
	isc_buffer_t *iscbuf;
	int success;
	dnskey_lookup *dl;

	iscmem=NULL;
	iscbuf=NULL;
	dl = malloc(sizeof(*dl));
	memset(dl, 0, sizeof(*dl));

	dl->tracking_id = strdup(id);
	dl->step = dkl_start;

	output_transaction_line(gs, id, 0, "START", NULL);

	success = lwres_getrrsetbyname_init(fqdn, dns_rdataclass_in,
					    wantedtype, 0 /*flags*/,
					    gs->lwctx, &dl->las);

	if(success != ERRSET_SUCCESS) {
		/* screwed: */
		output_transaction_line(gs, id, 0, "FATAL", "isc buffer error");
		return;
	}

	lwres_getrrsetbyname_xmit(gs->lwctx, &dl->las);

	dl->step = dkl_first;
	dl->wantedtype = wantedtype;
	dl->wantedtype_name = xstrdup(wantedtype_name);
	dl->fqdn = xstrdup(fqdn);
	dl->tracking_id = xstrdup(id);

	/* link it in */
	dl->next = gs->dns_outstanding;
	gs->dns_outstanding = dl;
	
	gs->dns_inflight++;

	return;
}


int setup_follow_possible_cname(dnskey_glob   *gs,
				dnskey_lookup *dl)
{
	int ret;

	dl->cname_count++;

	/*
	 * If we are on an odd cycle (starting with 1),
	 * then convert to dns_name_t so that we can compare later.
	 *
	 * This detects loops in the CNAME processing, while still
	 * allowing an arbitrary number of CNAMEs to be followed. 
	 */
	if(dl->cname_count & 1) 
	{
		isc_buffer_t fqdn_src;
		isc_buffer_t *fqdn_dst;

		if(dl->cname_count == 1)
		{
			memset(&dl->last_cname, 0, sizeof(dl->last_cname));
			dns_name_init(&dl->last_cname, NULL);
		}
		else
		{
			dns_name_reset(&dl->last_cname);
		}

		fqdn_dst=NULL;

		isc_buffer_init(&fqdn_src, dl->fqdn, strlen(dl->fqdn));
		isc_buffer_add(&fqdn_src, strlen(dl->fqdn));

		isc_buffer_allocate(gs->iscmem, &fqdn_dst, strlen(dl->fqdn)+1);

#if 0
		if(dl->last_cname_used) {
			dns_name_free(&dl->last_cname, gs->iscmem);
		}
#endif
		dl->last_cname_used = 1;
		if(dns_name_fromtext(&dl->last_cname,
				     &fqdn_src,
				     NULL,
				     1,
				     fqdn_dst) != ISC_R_SUCCESS) {
			return 0;
		}

		/* something else here ? */
	}
				 
	ret = lwres_getrrsetbyname_init(dl->fqdn, dns_rdataclass_in,
					dns_rdatatype_cname, 0 /*flags*/,
					gs->lwctx,
					&dl->las);

	if(ret != ERRSET_SUCCESS) {
		return 0;
	}

	lwres_getrrsetbyname_xmit(gs->lwctx, &dl->las);

	return 1;
}


/*
 * we asked for, and got a CNAME of some kind.
 */
void process_step_cname(dnskey_glob *gs,
			dnskey_lookup *dl,
			struct rrsetinfo *ans,
			int success)
{
	struct rdatainfo *ri;
	isc_region_t  region;
	dns_rdata_t   rd;
	dns_rdata_cname_t cn;
	char simplebuf[80];
	isc_buffer_t *cname_text;
	char cname_buf[DNS_NAME_MAXTEXT];
	/* char cname_buf2[DNS_NAME_MAXTEXT]; */

	switch(success) {
	case ERRSET_NONAME:
	case ERRSET_NODATA:
		/* no, no CNAME found, thing isn't there */
		snprintf(simplebuf, sizeof(simplebuf),
			 "RR of type %s for %s was not found (tried CNAMEs)",
			 dl->wantedtype_name,
			 dl->fqdn);
		output_transaction_line(gs, dl->tracking_id, 0, "RETRY", 
					simplebuf);
		dl->step = dkl_done;
		return;
		
	case 0:
		/* aha! found a CNAME */
		break;

	default:
	fatal:
		/* some other error */
		snprintf(simplebuf, sizeof(simplebuf), "err=%d", success);
		output_transaction_line(gs, dl->tracking_id, 0, "FATAL", simplebuf);
		dl->step = dkl_done;
		return;
	}

	/*
	 * now process out the CNAMEs, and look them up, one by one...
	 * there should be only one... We just use the first one that works.
	 */

	if(ans->rri_flags & RRSET_VALIDATED) {
		output_transaction_line(gs, dl->tracking_id, 0, "DNSSEC", "OKAY");
	} else {
		output_transaction_line(gs, dl->tracking_id, 0, "DNSSEC", "not present");
	}

	if(ans->rri_nrdatas != 1) {
		/* we got a number of CNAMEs different from 1! */
		success=0;
		snprintf(simplebuf, sizeof(simplebuf), "illegal number of CNAMES: %d", ans->rri_nrdatas);
		output_transaction_line(gs, dl->tracking_id, 0, "FATAL", simplebuf);
		dl->step = dkl_done;
		return;
	}

	/* process first CNAME record */
	ri= &ans->rri_rdatas[0];

	memset(&region, 0, sizeof(region));
	memset(&rd,     0, sizeof(rd));
	
	region.base   =  ri->rdi_data;
	region.length =  ri->rdi_length;

	dns_rdata_fromregion(&rd, dns_rdataclass_in,
			     dns_rdatatype_cname, &region);
	
	/* we set mctx to NULL, which means that the tenure for
	 * the stuff pointed to by cn will persist only as long
	 * as rd persists.
	 */
	if(dns_rdata_tostruct(&rd, &cn, NULL) != ISC_R_SUCCESS) {
		/* failed, try next return error */
		success=0;
		goto fatal;
	}

	cname_text=NULL;
	if(isc_buffer_allocate(gs->iscmem, &cname_text, DNS_NAME_MAXTEXT)) {
		success=0;
		goto fatal;
	}

	if(dns_name_totext(&cn.cname, ISC_TRUE, cname_text) !=
	   ISC_R_SUCCESS) {
		success=0;
		goto fatal;
	}
	
	cname_buf[0]='\0';
	strncat(cname_buf,
		isc_buffer_base(cname_text),
		isc_buffer_usedlength(cname_text));

	/* free up buffer */
	isc_buffer_free(&cname_text);
	
	{
		/* add a trailing . */
		char *end;
		end = &cname_buf[strlen(cname_buf)];
		if(*end != '.') {
			strncat(cname_buf, ".", sizeof(cname_buf));
		}
	}
	
	/* format out a text version */
	output_transaction_line(gs, dl->tracking_id, 0, "CNAME", cname_buf);
	output_transaction_line(gs, dl->tracking_id, 0, "CNAMEFROM", dl->fqdn);
	
	/* check for loops in the CNAMEs! */
	if(dns_name_equal(&dl->last_cname, &cn.cname) == ISC_TRUE) {
		/* damn, we found a loop! */
		dl->step = dkl_done;
		return;
	}

	/* send new request. */
	/* okay, so look this new thing up */		
	success = lwres_getrrsetbyname_init(cname_buf, dns_rdataclass_in,
					    dl->wantedtype, 0 /*flags*/,
					    gs->lwctx, &dl->las);

	if(success != ERRSET_SUCCESS) {
		return;
	}

	lwres_getrrsetbyname_xmit(gs->lwctx, &dl->las);

	dl->step = dkl_second;
}

void process_step_first(dnskey_glob *gs,
			dnskey_lookup *dl,
			struct rrsetinfo *ans,
			int success,
			int attempt)  /* attempt = 0 first time, 1 after cname */
{
	char simplebuf[132], typebuf[16];
	char txtbuf[1024];
	int i;

	switch(success) {
	case ERRSET_NODATA:
		if(attempt == 0) {
			lwresd_has_spoken = 1;
			setup_follow_possible_cname(gs, dl);
			dl->step = dkl_cname;
			return;
		} 
		/* FALLTHROUGH */
	case ERRSET_NONAME:
		lwresd_has_spoken = 1;
		snprintf(simplebuf, sizeof(simplebuf),
			 "RR of type %s for %s was not found",
			 dl->wantedtype_name,
			 dl->fqdn);
		output_transaction_line(gs, dl->tracking_id, 0, "RETRY", 
					simplebuf);
		dl->step = dkl_done;
		goto done;
		
	case ERRSET_NOMEMORY:
		snprintf(simplebuf, sizeof(simplebuf),
			 "ran out of memory while looking up RR of type %s for %s",
			 dl->wantedtype_name, dl->fqdn);
		output_transaction_line(gs, dl->tracking_id, 0, "FATAL", simplebuf);
		dl->step = dkl_done;
		goto done;

	case ERRSET_FAIL:
		snprintf(simplebuf, sizeof(simplebuf),
			 "unspecified failure while looking up RR of type %s for %s%s",
			 dl->wantedtype_name, dl->fqdn,
			 lwresd_has_spoken ? "" : " (is lwresd running?)");
		output_transaction_line(gs, dl->tracking_id, 0, "FATAL", simplebuf);
		dl->step = dkl_done;
		goto done;
		
	case ERRSET_INVAL:
		snprintf(simplebuf, sizeof(simplebuf),
			 "invalid input while looking up RR of type %s for %s",
			 dl->wantedtype_name, dl->fqdn);
		output_transaction_line(gs, dl->tracking_id, 0, "RETRY", simplebuf);
		dl->step = dkl_done;
		goto done;

	default:
		snprintf(simplebuf, sizeof(simplebuf), " unknown error %d", success);
		output_transaction_line(gs, dl->tracking_id, 0, "RETRY", simplebuf);
		dl->step = dkl_done;
	done:
		return;
		
	case 0:
		/* everything okay */
		lwresd_has_spoken = 1;
		dl->step = dkl_done;
		break;
	}

	/* output the rest of the data */

	if(ans->rri_flags & RRSET_VALIDATED) {
		output_transaction_line(gs, dl->tracking_id, 0, "DNSSEC", "OKAY");
		snprintf(typebuf, sizeof(typebuf), "AD-%s", dl->wantedtype_name);
		if(dl->wantedtype_name) free(dl->wantedtype_name);
		dl->wantedtype_name=xstrdup(typebuf);
	} else {
		output_transaction_line(gs, dl->tracking_id, 0, "DNSSEC", "not present");
	}

	output_transaction_line(gs, dl->tracking_id, 0, "NAME", ans->rri_name);

	for(i=0; i<ans->rri_nrdatas; i++) {
		struct rdatainfo *ri = &ans->rri_rdatas[i];
		isc_region_t  region;
		dns_rdata_t    rd;

		isc_buffer_clear(gs->iscbuf);
		memset(&region, 0, sizeof(region));
		memset(&rd,     0, sizeof(rd));
		
		region.base   =  ri->rdi_data;
		region.length =  ri->rdi_length;

		if(dl->wantedtype == dns_rdatatype_txt) {
			/* special treatment for TXT records */
			unsigned int len, rdatalen, totlen;
			unsigned char *txtp, *rdata;

			txtp     = txtbuf;
			totlen   = 0;
			rdatalen = ri->rdi_length;
			rdata    = ri->rdi_data;

			while(rdatalen > 0) {
				len= (unsigned)rdata[0];
				memcpy(txtp, rdata+1, len);
				totlen   += len;
				txtp     += len;
				rdata    += len+1;
				rdatalen -= len+1;
			}
			*txtp = '\0';

			output_transaction_line_limited(gs, dl->tracking_id, 0,
							dl->wantedtype_name,
							totlen, txtbuf);

		} else {
			dns_rdata_fromregion(&rd, dns_rdataclass_in,
					     dl->wantedtype, &region);
			
			if(dns_rdata_totext(&rd, NULL, gs->iscbuf) != ISC_R_SUCCESS) {

			}
			
			output_transaction_line_limited(gs, dl->tracking_id, 0,
							dl->wantedtype_name,
					(int)isc_buffer_usedlength(gs->iscbuf),
					(char *)isc_buffer_base(gs->iscbuf));
		}
	}
		
	for(i=0; i<ans->rri_nsigs; i++) {
		struct rdatainfo *ri = &ans->rri_sigs[i];
		isc_region_t  region;
		dns_rdata_t    rd;

		isc_buffer_clear(gs->iscbuf);
		memset(&region, 0, sizeof(region));
		memset(&rd,     0, sizeof(rd));
		
		region.base   =  ri->rdi_data;
		region.length =  ri->rdi_length;

		dns_rdata_fromregion(&rd, dns_rdataclass_in,
				     dns_rdatatype_sig, &region);
		if(dns_rdata_totext(&rd, NULL, gs->iscbuf) != ISC_R_SUCCESS) {
			output_transaction_line(gs, dl->tracking_id, 0, "FATAL", "isc totext error");
			return;
		}
		
		output_transaction_line_limited(gs, dl->tracking_id, 0, "SIG",
					(int)isc_buffer_usedlength(gs->iscbuf),
					(char *)isc_buffer_base(gs->iscbuf));
	}
}	



void lookup_step(dnskey_glob *gs,
		 dnskey_lookup *dl,
		 struct rrsetinfo *ans,
		 int success)
{
	/* char simplebuf[80]; */
	int  nextstate;

	nextstate = dkl_done;

	if(dl == NULL)
	{
		return;
	}

	switch(dl->step)
	{
	case dkl_start:
		/* first request done, why are still in this state? */
		break;

	case dkl_first:
		/* okay, got the reply from the first step! */
		process_step_first(gs, dl, ans, success, 0);
		nextstate = dl->step;
		break;
		
	case dkl_cname:
		/*
		 * we asked for a cname, and we have some result to deal
		 * with here.
		 */
		process_step_cname(gs, dl, ans, success);
		nextstate = dl->step;
		break;

	case dkl_second:
		/*
		 * we had asked for something, for a cname, and we followed
		 * it, and we'll see what we got back.
		 */
		process_step_first(gs, dl, ans, success, 1);
		nextstate = dl->step;
		break;

	case dkl_done:
		/* this should not happen, really, just book keeping, so,
		 * just free up the structure, and return.
		 */
		nextstate = dl->step;
		return;
	}


	/* we have been through, made a state transition, if we are
	 * done, then do that.
	 */
	if(nextstate == dkl_done)
	{
		output_transaction_line(gs, dl->tracking_id, 0, "DONE", NULL);
		free_dl(gs, dl);
		dl=NULL;
	}
	return;
}

void process_dns_reply(dnskey_glob *gs)
{
  dnskey_lookup *dl;
  struct lwres_async_state *plas;
  struct rrsetinfo *res;
  int success;

  plas = NULL;

  success = lwres_getrrsetbyname_read(&plas, gs->lwctx, &res);

  /* cast answer back to dnskey_lookup structure */
  dl = (dnskey_lookup *)plas;

  if(success == LWRES_R_RETRY) {
	  /* XXX we got something from some other weird place!
	   * transmit again, in the hope of getting the right answer
	   */
	  dl->retry_count--;
	  if(dl->retry_count > 0) {
		  lwres_getrrsetbyname_xmit(gs->lwctx, plas);
	  } else {
		  output_transaction_line(gs, dl->tracking_id, 0, "FATAL", "too many retries");
		  free_dl(gs, dl);
	  }
	  return;
  }

  /* perform next step for this one */
  lookup_step(gs, dl, res, success);
}
	
/*
 * $Log: lookup.c,v $
 * Revision 1.1  2004/03/15 20:35:28  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.3  2003/09/18 02:17:39  mcr
 * 	if we have tried a CNAME lookup, then take a NODATA
 * 	reply as a no-name.
 *
 * Revision 1.2  2003/09/10 17:55:14  mcr
 * 	the CNAME message had the s removed, which changes test
 * 	results gratuitously.
 *
 * Revision 1.1  2003/09/03 01:13:24  mcr
 * 	first attempt at async capable lwdnsq.
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 2
 * End:
 *
 */
