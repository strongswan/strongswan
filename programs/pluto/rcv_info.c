/* info/policy communicating routines
 * Copyright (C) 2003       Michael Richardson <mcr@freeswan.org>
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
 * RCSID $Id: rcv_info.c,v 1.2 2004/04/01 18:44:38 as Exp $
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"
#include "foodgroups.h"
#include "whack.h"	/* needs connections.h */
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "kernel.h"
#include "rcv_whack.h"
#include "log.h"
#include "keys.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "server.h"

#include "freeswan/ipsec_policy.h"
#include "rcv_info.h"

/* global */
int info_fd = -1;

static void
info_lookuphostpair(struct ipsec_policy_cmd_query *ipcq)
{
    struct connection *c;
    struct state *p1st, *p2st;


    /* default result: no crypto */
    ipcq->strength  = IPSEC_PRIVACY_NONE;
    ipcq->bandwidth = IPSEC_QOS_WIRESPEED;
    ipcq->credential_count = 0;

#ifdef DEBUG
    {
	char sstr[ADDRTOT_BUF], dstr[ADDRTOT_BUF];

	addrtot(&ipcq->query_local,  0, sstr, sizeof(sstr));
	addrtot(&ipcq->query_remote, 0, dstr, sizeof(dstr));
	DBG_log("info request for %s -> %s", sstr, dstr);
    }
#endif

    /* okay, look up what connection handles this ip pair */

    c = find_connection_for_clients(NULL,
				    &ipcq->query_local,
				    &ipcq->query_remote);
    if (c == NULL)
    {
	/* try reversing it */
	c = find_connection_for_clients(NULL,
					&ipcq->query_remote,
					&ipcq->query_local);
	if (c != NULL)
	{
	    ip_address tmp;
	    tmp = ipcq->query_local;
	    ipcq->query_local = ipcq->query_remote;
	    ipcq->query_remote = tmp;
	}
    }
    
    if (c == NULL)
    {
#ifdef DEBUG
	DBG_log("no connection found");
#endif
	return;	/* no crypto */
    }

    if (c->newest_ipsec_sa == SOS_NOBODY)
    {
	ip_subnet us, them;

	DBG_log("connection %s found, no ipsec state, looking again", c->name);
	addrtosubnet(&ipcq->query_local, &us);
	addrtosubnet(&ipcq->query_remote, &them);
	c = find_client_connection(c, &us, &them);

	if (c == NULL)
	    return;	/* no crypto */
    }

    DBG_log("connection %s[%ld] with state %u"
	, c->name, c->instance_serial
	, (unsigned int)c->newest_ipsec_sa);

    if (c->newest_ipsec_sa == SOS_NOBODY)
	return;	/* no crypto */

    /* we found a connection, try to lookup the state */
    p2st = state_with_serialno(c->newest_ipsec_sa);

    p1st = find_phase1_state(c, ISAKMP_SA_ESTABLISHED_STATES);

    if (p1st == NULL || p2st == NULL)
    {
	DBG_log("connection %s[%ld] has missing states %s %s"
	    , c->name, c->instance_serial
	    , (p1st ? "phase1" : "")
	    , (p2st ? "phase1" : ""));
	return;	/* no crypto */
    }

    /* if we have AH present, then record minimal info */
    if (p2st->st_ah.present)
    {
	ipcq->strength = IPSEC_PRIVACY_INTEGRAL;
	ipcq->auth_detail = p2st->st_esp.attrs.auth;
    }

    if (p2st->st_esp.present)
    {
	/*
	 * XXX-mcr Please do not shout at me about relative strengths
	 *         here. I'm not a cryptographer. I just diddle bits.
	 */
	switch (p2st->st_esp.attrs.transid)
	{
	case ESP_NULL:
	    /* actually, do not change it if we set it from AH */
	    break;

	case ESP_DES:
	case ESP_DES_IV64:
	case ESP_DES_IV32:
	case ESP_RC4:
	    ipcq->strength = IPSEC_PRIVACY_ROT13;
	    break;
	    
	case ESP_RC5:
	case ESP_IDEA:
	case ESP_CAST:
	case ESP_BLOWFISH:
	case ESP_3DES:
	    ipcq->strength = IPSEC_PRIVACY_PRIVATE;
	    ipcq->bandwidth = IPSEC_QOS_VOIP;
	    break;

	case ESP_3IDEA:
	    ipcq->strength = IPSEC_PRIVACY_STRONG;
	    ipcq->bandwidth = IPSEC_QOS_INTERACTIVE;
	    break;

	case ESP_AES:
	    ipcq->strength = IPSEC_PRIVACY_STRONG;
	    ipcq->bandwidth = IPSEC_QOS_FTP;
	    break;
	}
	ipcq->esp_detail = p2st->st_esp.attrs.transid;
    }

    if (p2st->st_ipcomp.present)
	ipcq->comp_detail = p2st->st_esp.attrs.transid;

    /* now! the credentails that were used */
    /* for the moment we only have 1 credential, the DNS name,
     * because the DNS servers do not return the chain of SIGs yet
     */

    if(!c->spd.this.key_from_DNS_on_demand)
    {
	/* the key didn't come from the DNS in some way,
	 * so it must have been loaded locally.
	 */
	ipcq->credential_count = 1;
	ipcq->credentials[0].ii_type   = c->spd.this.id.kind;
	ipcq->credentials[0].ii_format = CERT_RAW_RSA;
    }
	
#if 0
    switch (c->spd.id.kind)
    {
    case ID_IPV4_ADDR:
    }
    if (c->gw_info == NULL)
    {
	plog("rcv_info: connection %s had NULL gw_info.", c->name);
	return
    }
#endif

    ipcq->credential_count = 1;

    /* pull credentials out of gw_info */
    
    switch (p1st->st_peer_pubkey->dns_auth_level)
    {
    case DAL_UNSIGNED:
    case DAL_NOTSEC:
	/* these seem to be the same for this purpose */
	ipcq->credentials[0].ii_type   = p1st->st_peer_pubkey->id.kind;
	ipcq->credentials[0].ii_type   = CERT_NONE;
	idtoa(&p1st->st_peer_pubkey->id
	    , ipcq->credentials[0].ii_credential.ipsec_dns_signed.fqdn
	    , sizeof(ipcq->credentials[0].ii_credential.ipsec_dns_signed.fqdn));
	break;
	
    case DAL_SIGNED:
	ipcq->credentials[0].ii_type   = p1st->st_peer_pubkey->id.kind;
	ipcq->credentials[0].ii_format = CERT_DNS_SIGNED_KEY;
	idtoa(&p1st->st_peer_pubkey->id
	    , ipcq->credentials[0].ii_credential.ipsec_dns_signed.fqdn
	    , sizeof(ipcq->credentials[0].ii_credential.ipsec_dns_signed.fqdn));

	if (p1st->st_peer_pubkey->dns_sig != NULL)
	{
	    strncat(ipcq->credentials[0].ii_credential.ipsec_dns_signed.dns_sig
		, p1st->st_peer_pubkey->dns_sig
		, sizeof(ipcq->credentials[0].ii_credential.ipsec_dns_signed.dns_sig));
	}
	break;

    case DAL_LOCAL:
	ipcq->credentials[0].ii_type   = p1st->st_peer_pubkey->id.kind;
	ipcq->credentials[0].ii_format = CERT_RAW_RSA;
	idtoa(&p1st->st_peer_pubkey->id
	    , ipcq->credentials[0].ii_credential.ipsec_raw_key.id_name
	    , sizeof(ipcq->credentials[0].ii_credential.ipsec_raw_key.id_name));
	break;
    }
}

/*
 * Handle an info/policy request. 
 *
 * For now, we close the socket after answering the request.
 *
 */
void
info_handle(int infoctlfd)
{
	struct sockaddr_un info_client_addr;
	int info_addr_len = sizeof(info_client_addr);
	/* Note: actual value in n should fit in int.  To print, cast to int. */
	int infofd;
	err_t err;
	struct ipsec_policy_cmd_query ipcq;

	infofd = accept(infoctlfd, (struct sockaddr *)&info_client_addr
	    , &info_addr_len);

	if (infofd < 0)
	{
	    log_errno((e, "accept() failed in info_handle()"));
	    return;
	}

	err = ipsec_policy_readmsg(infofd, (unsigned char *)&ipcq, sizeof(ipcq));

	if (err != NULL)
	{
	    log_errno((e, "readmsg said: %s", err));
	    close(infofd);
	    return;
	}

	switch (ipcq.head.ipm_msg_type)
	{
	case IPSEC_CMD_QUERY_HOSTPAIR:
	    info_lookuphostpair(&ipcq);
	    write(infofd, &ipcq, ipcq.head.ipm_msg_len);
	    break;
	    
	default:
	    plog("got unimplemented msg type: %d", ipcq.head.ipm_msg_type);
	    break;
	}

	/* for now, close the socket */
	close(infofd);
}
