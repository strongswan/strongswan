/* Mode config related functions
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
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
 * RCSID $Id: modecfg.c,v 1.6 2006/04/24 20:44:57 as Exp $
 *
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "demux.h"
#include "timer.h"
#include "ipsec_doi.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h"
#include "modecfg.h"
#include "whack.h"

/*
 * Addresses assigned (usually via MODE_CONFIG) to the Initiator
 */
struct internal_addr
{
    ip_address    ipaddr;
    ip_address    dns[2];
    ip_address    wins[2];  
};

/*
 * Get inside IP address for a connection
 */
static void
get_internal_addresses(struct connection *c, struct internal_addr *ia)
{
    zero(ia);

    if (isanyaddr(&c->spd.that.host_srcip))
    {
	/* not defined in connection - fetch it from LDAP */
    }
    else
    {
	ia->ipaddr = c->spd.that.host_srcip;
    }
}

/*
 * Compute HASH of Mode Config.
 */
static size_t
mode_cfg_hash(u_char *dest, const u_char *start, const u_char *roof
	     , const struct state *st)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const u_char *) &st->st_msgid, sizeof(st->st_msgid));
    hmac_update(&ctx, start, roof-start);
    hmac_final(dest, &ctx);

    DBG(DBG_CRYPT,
	DBG_log("MODE CFG: HASH computed:");
 	DBG_dump("", dest, ctx.hmac_digest_size)
    ) 
    return ctx.hmac_digest_size;
}


/* Mode Config Reply
 * Generates a reply stream containing Mode Config information (eg: IP, DNS, WINS)
 */
stf_status modecfg_resp(struct state *st
			, u_int resp
			, pb_stream *rbody
			, u_int16_t replytype
			, bool hackthat
			, u_int16_t ap_id)
{
    u_char *r_hash_start,*r_hashval;

    /* START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR); */

    {
	pb_stream hash_pbs;
	int np = ISAKMP_NEXT_ATTR;

	if (!out_generic(np, &isakmp_hash_desc, rbody, &hash_pbs))
	    return STF_INTERNAL_ERROR;
	r_hashval = hash_pbs.cur;	/* remember where to plant value */
	if (!out_zero(st->st_oakley.hasher->hash_digest_size, &hash_pbs, "HASH"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&hash_pbs);
	r_hash_start = (rbody)->cur;	/* hash from after HASH payload */
    }

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr,attrval;
	int attr_type;
	struct internal_addr ia;
	int dns_idx, wins_idx;
	bool dont_advance;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = replytype;

	attrh.isama_identifier = ap_id;
	if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
	    return STF_INTERNAL_ERROR;

	get_internal_addresses(st->st_connection, &ia);

	if (!isanyaddr(&ia.dns[0]))	/* We got DNS addresses, answer with those */
	    resp |= LELEM(INTERNAL_IP4_DNS);
	else
	    resp &= ~LELEM(INTERNAL_IP4_DNS);

	if (!isanyaddr(&ia.wins[0]))	/* We got WINS addresses, answer with those */
	    resp |= LELEM(INTERNAL_IP4_NBNS);
	else
	    resp &= ~LELEM(INTERNAL_IP4_NBNS);

	if (hackthat)
	{
	    if (memcmp(&st->st_connection->spd.that.client.addr
		      ,&ia.ipaddr
		      ,sizeof(ia.ipaddr)) != 0)
	    {
		/* Make the Internal IP address and Netmask 
		 * as that client address
		 */
		st->st_connection->spd.that.client.addr = ia.ipaddr;
		st->st_connection->spd.that.client.maskbits = 32;
		st->st_connection->spd.that.has_client = TRUE;
	    }
	}

	attr_type = 0;
	dns_idx = 0;
	wins_idx = 0;

	while (resp != 0)
	{
	    dont_advance = FALSE;
	    if (resp & 1)
	    {
		const u_char *byte_ptr;
		u_int len;

		/* ISAKMP attr out */
		attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV;
		out_struct(&attr, &isakmp_modecfg_attribute_desc, &strattr, &attrval);

		switch (attr_type)
		{
		case INTERNAL_IP4_ADDRESS:
		    {
			char srcip[ADDRTOT_BUF];

			addrtot(&ia.ipaddr, 0, srcip, sizeof(srcip));
			plog("assigning virtual IP source address %s", srcip);
			len = addrbytesptr(&ia.ipaddr, &byte_ptr);
 			out_raw(byte_ptr,len,&attrval,"IP4_addr");
		     }
 		    break;
		case INTERNAL_IP4_NETMASK:
		    {
 			u_int  mask;
#if 0
			char mask[4],bits[8]={0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe};
			int t,m=st->st_connection->that.host_addr.maskbit;
			for (t=0; t<4; t++)
			{
			    if (m < 8)
				mask[t] = bits[m];
			    else
				mask[t] = 0xff;
			    m -= 8;
			}
#endif				    
			if (st->st_connection->spd.this.client.maskbits == 0)
 			    mask = 0;
 			else
 			    mask = 0xffffffff * 1;
			    out_raw(&mask,4,&attrval,"IP4_mask");
		    }
		    break;
		case INTERNAL_IP4_SUBNET:
		    {
			char mask[4];
			char bits[8] = {0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe};
			int t;
			int m = st->st_connection->spd.this.client.maskbits;

			for (t = 0; t < 4; t++)
			{
			    if (m < 8)
				mask[t] = bits[m];
			    else
				mask[t] = 0xff;
			    m -= 8;
			    if (m < 0)
			        m = 0;
			}
			len = addrbytesptr(&st->st_connection->spd.this.client.addr, &byte_ptr);
			out_raw(byte_ptr,len,&attrval,"IP4_subnet");
			out_raw(mask,sizeof(mask),&attrval,"IP4_submsk");
		    }
		    break;
		case INTERNAL_IP4_DNS:
 		    len = addrbytesptr(&ia.dns[dns_idx++], &byte_ptr);
 		    out_raw(byte_ptr,len,&attrval,"IP4_dns");
		    if (dns_idx < 2 && !isanyaddr(&ia.dns[dns_idx]))
		    {
			dont_advance = TRUE;
		    }
 		    break;
		case INTERNAL_IP4_NBNS:
 		    len = addrbytesptr(&ia.wins[wins_idx++], &byte_ptr);
 		    out_raw(byte_ptr,len,&attrval,"IP4_wins");
		    if (wins_idx < 2 && !isanyaddr(&ia.wins[wins_idx]))
		    {
			dont_advance = TRUE;
		    }
 		    break;
		default:
		    plog("attempt to send unsupported mode cfg attribute %s."
			 , enum_show(&modecfg_attr_names, attr_type));
		    break;
		}
		close_output_pbs(&attrval);

	    }
	    if (!dont_advance)
	    {
		attr_type++;
		resp >>= 1;
	    }
	}
	close_message(&strattr);
    }

    mode_cfg_hash(r_hashval,r_hash_start,rbody->cur,st);
    close_message(rbody);
    encrypt_message(rbody, st);
    return STF_OK;
}

/* Set MODE_CONFIG data to client.
 * Pack IP Addresses, DNS, etc... and ship
 */
stf_status modecfg_send_set(struct state *st)
{
    pb_stream reply,rbody;
    char buf[256];

    /* set up reply */
    init_pbs(&reply, buf, sizeof(buf), "ModecfgR1");

    st->st_state = STATE_MODE_CFG_R1;
    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	hdr.isa_msgid = st->st_msgid;

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    return STF_INTERNAL_ERROR;
	}
    }

#define MODECFG_SET_ITEM ( LELEM(INTERNAL_IP4_ADDRESS) | LELEM(INTERNAL_IP4_SUBNET) | LELEM(INTERNAL_IP4_NBNS) | LELEM(INTERNAL_IP4_DNS) )

    modecfg_resp(st, MODECFG_SET_ITEM
		   , &rbody
		   , ISAKMP_CFG_SET
		   , TRUE
		   , 0/* XXX ID */);
#undef MODECFG_SET_ITEM

    clonetochunk(st->st_tpacket, reply.start
		, pbs_offset(&reply), "ModeCfg set");

    /* Transmit */
    send_packet(st, "ModeCfg set");

    /* RETRANSMIT if Main, SA_REPLACE if Aggressive */
    if (st->st_event->ev_type != EVENT_RETRANSMIT
    && st->st_event->ev_type != EVENT_NULL)
    {
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);
    }

    return STF_OK;
}

/* Set MODE_CONFIG data to client.
 * Pack IP Addresses, DNS, etc... and ship
 */
stf_status
modecfg_start_set(struct state *st)
{
    if (st->st_msgid == 0)
    {
	/* pick a new message id */
	st->st_msgid = generate_msgid(st);
    }
    st->st_modecfg.vars_set = TRUE;

    return modecfg_send_set(st);
}

/*
 * Send modecfg IP address request (IP4 address)
 */
stf_status
modecfg_send_request(struct state *st)
{
    pb_stream reply;
    pb_stream rbody;
    char buf[256];
    u_char *r_hash_start,*r_hashval;

    /* set up reply */
    init_pbs(&reply, buf, sizeof(buf), "modecfg_buf");

    plog("sending ModeCfg request");

    /* this is the beginning of a new exchange */
    st->st_msgid = generate_msgid(st);
    st->st_state = STATE_MODE_CFG_I1;

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	zero(&hdr);	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_HASH;
	hdr.isa_xchg = ISAKMP_XCHG_MODE_CFG;
	hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
	hdr.isa_msgid = st->st_msgid;

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    return STF_INTERNAL_ERROR;
	}
    }

    START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_ATTR);

    /* ATTR out */
    {
	struct  isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr;

	attrh.isama_np = ISAKMP_NEXT_NONE;
	attrh.isama_type = ISAKMP_CFG_REQUEST;
	attrh.isama_identifier = 0;
	if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
	    return STF_INTERNAL_ERROR;
	/* ISAKMP attr out (ipv4) */
	attr.isaat_af_type = INTERNAL_IP4_ADDRESS;
	attr.isaat_lv = 0;
	out_struct(&attr, &isakmp_modecfg_attribute_desc, &strattr, NULL);
	
	/* ISAKMP attr out (netmask) */
	attr.isaat_af_type = INTERNAL_IP4_NETMASK;
	attr.isaat_lv = 0;
	out_struct(&attr, &isakmp_modecfg_attribute_desc, &strattr, NULL);

	close_message(&strattr);
    }

    mode_cfg_hash(r_hashval,r_hash_start,rbody.cur,st);

    close_message(&rbody);
    close_output_pbs(&reply);

    init_phase2_iv(st, &st->st_msgid);
    encrypt_message(&rbody, st);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply)
	, "modecfg: req");

    /* Transmit */
    send_packet(st, "modecfg: req");

    /* RETRANSMIT if Main, SA_REPLACE if Aggressive */
    if (st->st_event->ev_type != EVENT_RETRANSMIT)
    {	
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0 * 3, st);
    }
    st->st_modecfg.started = TRUE;

    return STF_OK;
}

/*
 * parse a modecfg attribute payload
 */
static stf_status
modecfg_parse_attributes(pb_stream *attrs, u_int *set)
{
    struct isakmp_attribute attr;
    pb_stream strattr;

    while (pbs_left(attrs) > sizeof(struct isakmp_attribute))
    {
	if (!in_struct(&attr, &isakmp_modecfg_attribute_desc, attrs, &strattr))
	{
	    int len = (attr.isaat_af_type & 0x8000)? 4 : attr.isaat_lv;

	    if (len < 4)
	    {
		plog("Attribute was too short: %d", len);
		return STF_FAIL;
	    }

	    attrs->cur += len;
	}

	switch (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
	{
	case INTERNAL_IP4_ADDRESS:
	case INTERNAL_IP4_NETMASK:
	case INTERNAL_IP4_DNS:
	case INTERNAL_IP4_SUBNET:
	case INTERNAL_IP4_NBNS:
	    *set |= LELEM(attr.isaat_af_type);
	    break;
	default:
	    plog("unsupported mode cfg attribute %s received."
		, enum_show(&modecfg_attr_names
		    , attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK ));
	    break;
	}
    }
    return STF_OK;
}

/* STATE_MODE_CFG_R0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs both in the responder and in the initiator.
 *
 * In the responding server, it occurs when the client *asks* for an IP
 * address or other information.
 *
 * Otherwise, it occurs in the initiator when the server sends a challenge
 * a set, or has a reply to our request.
 */
stf_status
modecfg_inR0(struct msg_digest *md)
{
    struct state *const st = md->st;
    struct payload_digest *p;
    stf_status stat;

    plog("received ModeCfg request");

    st->st_msgid = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md, mode_cfg_hash(hash_val
				      ,hash_pbs->roof
				      , md->message_pbs.roof, st)
		     , "MODECFG-HASH", "MODE R0");

    /* process the MODECFG payloads therein */
    for (p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
	u_int set_modecfg_attrs = LEMPTY;

	switch (p->payload.attribute.isama_type)
	{
	default:
	    plog("Expecting ISAKMP_CFG_REQUEST, got %s instead (ignored)."
		, enum_name(&attr_msg_type_names
			, p->payload.attribute.isama_type));

	    stat = modecfg_parse_attributes(&p->pbs, &set_modecfg_attrs);
	    if (stat != STF_OK)
		return stat;
	    break;

	case ISAKMP_CFG_REQUEST:
	    stat = modecfg_parse_attributes(&p->pbs, &set_modecfg_attrs);
	    if (stat != STF_OK)
		return stat;

	    stat = modecfg_resp(st, set_modecfg_attrs
				,&md->rbody
				,ISAKMP_CFG_REPLY
				,TRUE
				,p->payload.attribute.isama_identifier);

	    if (stat != STF_OK)
	    {
		/* notification payload - not exactly the right choice, but okay */
		md->note = CERTIFICATE_UNAVAILABLE;
		return stat;
	    }

	    /* they asked us, we responded, msgid is done */
	    st->st_msgid = 0;
	}
    }
    return STF_OK;
}

/* STATE_MODE_CFG_R2:
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * used in server push mode, on the client (initiator).
 */
static stf_status
modecfg_inI2(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *attrs = &md->chain[ISAKMP_NEXT_ATTR]->pbs;
    int resp = LEMPTY;
    stf_status stat;
    struct payload_digest *p;
    u_int16_t isama_id = 0;

    st->st_msgid = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md
		     , mode_cfg_hash(hash_val
				    ,hash_pbs->roof
				    , md->message_pbs.roof
				    , st)
		     , "MODECFG-HASH", "MODE R1");

    for (p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;

	isama_id = p->payload.attribute.isama_identifier;

	if (p->payload.attribute.isama_type != ISAKMP_CFG_SET)
	{
	    plog("Expecting MODE_CFG_SET, got %x instead."
			 ,md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_type);
	    return STF_IGNORE;
	}

	/* CHECK that SET has been received. */

	while (pbs_left(attrs) > sizeof(struct isakmp_attribute))
	{
            if (!in_struct(&attr, &isakmp_modecfg_attribute_desc
			   , attrs, &strattr))
	    {
		int len;

		/* Skip unknown */
		if (attr.isaat_af_type & 0x8000)
		    len = 4;
		else
		    len = attr.isaat_lv;

		if (len < 4)
		{
		    plog("Attribute was too short: %d", len);
		    return STF_FAIL;
		}

		attrs->cur += len;
	    }

	    switch (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
	    {
	    case INTERNAL_IP4_ADDRESS:
		{
		    struct connection *c = st->st_connection;
		    ip_address a;
		    u_int32_t *ap = (u_int32_t *)(strattr.cur);
		    a.u.v4.sin_family = AF_INET;

		    memcpy(&a.u.v4.sin_addr.s_addr, ap
			       , sizeof(a.u.v4.sin_addr.s_addr));

		    if (addrbytesptr(&c->spd.this.host_srcip, NULL) == 0
		    || isanyaddr(&c->spd.this.host_srcip))
		    {
			char srcip[ADDRTOT_BUF];

			c->spd.this.host_srcip = a;
			addrtot(&a, 0, srcip, sizeof(srcip));
			plog("setting virtual IP source address to %s", srcip);
		    }

		    /* setting client subnet as srcip/32 */
		    addrtosubnet(&a, &c->spd.this.client);
		    c->spd.this.has_client = TRUE;
		}
		resp |= LELEM(attr.isaat_af_type);
		break;
	    case INTERNAL_IP4_NETMASK:
	    case INTERNAL_IP4_DNS:
	    case INTERNAL_IP4_SUBNET:
	    case INTERNAL_IP4_NBNS:
		resp |= LELEM(attr.isaat_af_type);
		break;
	    default:
		plog("unsupported mode cfg attribute %s received."
			, enum_show(&modecfg_attr_names, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
		break;
	    }
	}
    }

    /* ack things */
    stat = modecfg_resp(st, resp
			,&md->rbody
			,ISAKMP_CFG_ACK
			,FALSE
			,isama_id);

    if (stat != STF_OK)
    {
	/* notification payload - not exactly the right choice, but okay */
	md->note = CERTIFICATE_UNAVAILABLE;
	return stat;
    }

    /*
     * we are done with this exchange, clear things so
     * that we can start phase 2 properly
     */
    st->st_msgid = 0;

    if (resp)
    {
	st->st_modecfg.vars_set = TRUE;
    }
    return STF_OK;
}

/* STATE_MODE_CFG_R1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 */
stf_status
modecfg_inR1(struct msg_digest *md)
{
    struct state *const st = md->st;
    pb_stream *attrs = &md->chain[ISAKMP_NEXT_ATTR]->pbs;
    int set_modecfg_attrs = LEMPTY;
    stf_status stat;
    struct payload_digest *p;

    plog("parsing ModeCfg reply");

    st->st_msgid = md->hdr.isa_msgid;
    CHECK_QUICK_HASH(md, mode_cfg_hash(hash_val,hash_pbs->roof, md->message_pbs.roof, st)
	, "MODECFG-HASH", "MODE R1");


    /* process the MODECFG payloads therein */
    for (p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
        struct isakmp_attribute attr;
        pb_stream strattr;
	
	attrs = &p->pbs;
	
	switch (p->payload.attribute.isama_type)
	{
	default:
	{
	    plog("Expecting MODE_CFG_ACK, got %x instead."
		,md->chain[ISAKMP_NEXT_ATTR]->payload.attribute.isama_type);
	    return STF_IGNORE;
	}
	break;
	
	case ISAKMP_CFG_ACK:
	    /* CHECK that ACK has been received. */
	    stat = modecfg_parse_attributes(attrs, &set_modecfg_attrs);
	    if (stat != STF_OK)
		return stat;
	    break;

	case ISAKMP_CFG_REPLY:
	    while (pbs_left(attrs) > sizeof(struct isakmp_attribute))
	    {
		if (!in_struct(&attr, &isakmp_modecfg_attribute_desc
			       , attrs, &strattr))
		{
		    /* Skip unknown */
		    int len;
		    if (attr.isaat_af_type & 0x8000)
			len = 4;
		    else
			len = attr.isaat_lv;
		    
		    if (len < 4)
		    {
			plog("Attribute was too short: %d", len);
			return STF_FAIL;
		    }

		    attrs->cur += len;
		}

		switch (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )
		{
		case INTERNAL_IP4_ADDRESS:
		   {
			struct connection *c = st->st_connection;
			ip_address a;
			u_int32_t *ap = (u_int32_t *)(strattr.cur);
			a.u.v4.sin_family = AF_INET;

			memcpy(&a.u.v4.sin_addr.s_addr, ap
			   , sizeof(a.u.v4.sin_addr.s_addr));

			if (addrbytesptr(&c->spd.this.host_srcip, NULL) == 0
			|| isanyaddr(&c->spd.this.host_srcip))
			{
			    char srcip[ADDRTOT_BUF];

			    c->spd.this.host_srcip = a;
			    addrtot(&a, 0, srcip, sizeof(srcip));
			    plog("setting virtual IP source address to %s", srcip);
			}

			/* setting client subnet as srcip/32 */
			addrtosubnet(&a, &c->spd.this.client);
			setportof(0, &c->spd.this.client.addr);
			c->spd.this.has_client = TRUE;
		    }
		    /* fall through to set attribute flage */

		case INTERNAL_IP4_NETMASK:
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP4_SUBNET:
		case INTERNAL_IP4_NBNS:
		    set_modecfg_attrs |= LELEM(attr.isaat_af_type);
		    break;
		default:
		    plog("unsupported mode cfg attribute %s received."
			    , enum_show(&modecfg_attr_names
				, (attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK )));
		    break;
		}
	    }
	    break;
	}
    }

    /* we are done with this exchange, clear things so that we can start phase 2 properly */
    st->st_msgid = 0;

    if (set_modecfg_attrs)
    {
	st->st_modecfg.vars_set = TRUE;
    }
    return STF_OK;
}
