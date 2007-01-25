/* Mode config related functions
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2006-2007 Andreas Steffen - Hochschule fuer Technik Rapperswil
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
#include "xauth.h"

#define MAX_XAUTH_TRIES		3

#define SUPPORTED_ATTR_SET   ( LELEM(INTERNAL_IP4_ADDRESS)         \
                             | LELEM(INTERNAL_IP4_NETMASK)         \
                             | LELEM(INTERNAL_IP4_DNS)             \
                             | LELEM(INTERNAL_IP4_NBNS)            \
                             | LELEM(APPLICATION_VERSION)          \
                             )

#define SUPPORTED_UNITY_ATTR_SET ( LELEM(UNITY_BANNER - UNITY_BASE) )

#define UNITY_BANNER_STR    "Welcome to strongSwan - the Linux VPN Solution!\n"

/*
 * Addresses assigned (usually via ModeCfg) to the Initiator
 */
typedef struct internal_addr internal_addr_t;

struct internal_addr
{
    lset_t attr_set;
    lset_t xauth_attr_set;
    lset_t unity_attr_set;

    /* ModeCfg variables */
    ip_address ipaddr;
    ip_address dns[2];
    ip_address wins[2];

    char *unity_banner;

    /* XAUTH variables */
    u_int16_t  xauth_type;
    xauth_t    xauth_secret;
    bool       xauth_status;
};

/*
 * Initialize an internal_addr struct
 */
static void
init_internal_addr(internal_addr_t *ia)
{
    ia->attr_set = LEMPTY;
    ia->xauth_attr_set = LEMPTY;
    ia->xauth_secret.user_name = empty_chunk;
    ia->xauth_secret.user_password = empty_chunk;
    ia->xauth_status = FALSE;
    ia->unity_attr_set = LEMPTY;
    ia->unity_banner = NULL;

    anyaddr(AF_INET, &ia->ipaddr);
    anyaddr(AF_INET, &ia->dns[0]);
    anyaddr(AF_INET, &ia->dns[1]);
    anyaddr(AF_INET, &ia->wins[0]);
    anyaddr(AF_INET, &ia->wins[1]);
}

/*
 * get internal IP address for a connection
 */
static void
get_internal_addr(struct connection *c, internal_addr_t *ia)
{
    if (isanyaddr(&c->spd.that.host_srcip))
    {
	/* not defined in connection - fetch it from LDAP */
    }
    else
    {
	char srcip[ADDRTOT_BUF];

	ia->ipaddr = c->spd.that.host_srcip;

	addrtot(&ia->ipaddr, 0, srcip, sizeof(srcip));
	plog("assigning virtual IP source address %s", srcip);
    }

    if (!isanyaddr(&ia->ipaddr))	/* We got an IP address, send it */
    {
	c->spd.that.client.addr     = ia->ipaddr;
	c->spd.that.client.maskbits = 32;
	c->spd.that.has_client      = TRUE;
	
	ia->attr_set = LELEM(INTERNAL_IP4_ADDRESS)
		     | LELEM(INTERNAL_IP4_NETMASK);
    }

    if (!isanyaddr(&ia->dns[0]))	/* We got DNS addresses, send them */
	ia->attr_set |= LELEM(INTERNAL_IP4_DNS);

    if (!isanyaddr(&ia->wins[0]))	/* We got WINS addresses, send them */
	ia->attr_set |= LELEM(INTERNAL_IP4_NBNS);
}

/*
 * Set srcip and client subnet to internal IP address
 */
static bool
set_internal_addr(struct connection *c, internal_addr_t *ia)
{
    if (ia->attr_set & LELEM(INTERNAL_IP4_ADDRESS)
    && !isanyaddr(&ia->ipaddr))
    {
	if (addrbytesptr(&c->spd.this.host_srcip, NULL) == 0
	|| isanyaddr(&c->spd.this.host_srcip)
	|| sameaddr(&c->spd.this.host_srcip, &ia->ipaddr))
	{
	    char srcip[ADDRTOT_BUF];

	    addrtot(&ia->ipaddr, 0, srcip, sizeof(srcip));
	    plog("setting virtual IP source address to %s", srcip);
	}
	else
	{
	    char old_srcip[ADDRTOT_BUF];
	    char new_srcip[ADDRTOT_BUF];

	    addrtot(&c->spd.this.host_srcip, 0, old_srcip, sizeof(old_srcip));
	    addrtot(&ia->ipaddr, 0, new_srcip, sizeof(new_srcip));
	    plog("replacing virtual IP source address %s by %s"
		, old_srcip, new_srcip);
	}
	
	/* setting srcip */
	c->spd.this.host_srcip = ia->ipaddr;

	/* setting client subnet to srcip/32 */
	addrtosubnet(&ia->ipaddr, &c->spd.this.client);
	setportof(0, &c->spd.this.client.addr);
	c->spd.this.has_client = TRUE;
	return TRUE;
    }
    return FALSE;
}

/*
 * Compute HASH of Mode Config.
 */
static size_t
modecfg_hash(u_char *dest, const u_char *start, const u_char *roof
	    , const struct state *st)
{
    struct hmac_ctx ctx;

    hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
    hmac_update(&ctx, (const u_char *) &st->st_msgid, sizeof(st->st_msgid));
    hmac_update(&ctx, start, roof-start);
    hmac_final(dest, &ctx);

    DBG(DBG_CRYPT,
	DBG_log("ModeCfg HASH computed:");
 	DBG_dump("", dest, ctx.hmac_digest_size)
    ) 
    return ctx.hmac_digest_size;
}


/* 
 * Generate an IKE message containing ModeCfg information (eg: IP, DNS, WINS)
 */
static stf_status
modecfg_build_msg(struct state *st, pb_stream *rbody
				  , u_int16_t msg_type
				  , internal_addr_t *ia
				  , u_int16_t ap_id)
{
    u_char *r_hash_start, *r_hashval;

    START_HASH_PAYLOAD(*rbody, ISAKMP_NEXT_ATTR);

    /* ATTR out */
    {
	struct isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr,attrval;
	int attr_type;
	int dns_idx, wins_idx;
	bool dont_advance;
	bool is_xauth_attr_set = ia->xauth_attr_set != LEMPTY;
	bool is_unity_attr_set = ia->unity_attr_set != LEMPTY;
	lset_t attr_set = ia->attr_set;

	attrh.isama_np         = ISAKMP_NEXT_NONE;
	attrh.isama_type       = msg_type;
	attrh.isama_identifier = ap_id;

	if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
	    return STF_INTERNAL_ERROR;

	attr_type = 0;
	dns_idx = 0;
	wins_idx = 0;

	while (attr_set != LEMPTY || is_xauth_attr_set || is_unity_attr_set)
	{
	    if (attr_set == LEMPTY)
	    {
		if (is_xauth_attr_set)
	  	{
		    attr_set = ia->xauth_attr_set;
		    attr_type = XAUTH_BASE;
		    is_xauth_attr_set = FALSE;
		}
		else
		{
		    attr_set = ia->unity_attr_set;
		    attr_type = UNITY_BASE;
		    is_unity_attr_set = FALSE;
		}
	    }
	
	    dont_advance = FALSE;

	    if (attr_set & 1)
	    {
		const u_char *byte_ptr;
		u_int len;

		/* ISAKMP attr out */
		if (attr_type == XAUTH_TYPE)
		{
		    attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TV;
		    attr.isaat_lv = ia->xauth_type;
		}
		else if (attr_type == XAUTH_STATUS)
		{
		    attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TV;
		    attr.isaat_lv = ia->xauth_status;
		}
		else
		{
		    attr.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV;
		}
		out_struct(&attr, &isakmp_modecfg_attribute_desc, &strattr, &attrval);

		switch (attr_type)
		{
		case INTERNAL_IP4_ADDRESS:
		    if (!isanyaddr(&ia->ipaddr))
		    {
			len = addrbytesptr(&ia->ipaddr, &byte_ptr);
 			out_raw(byte_ptr, len, &attrval, "IP4_addr");
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
			    out_raw(&mask, 4, &attrval, "IP4_mask");
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
			out_raw(byte_ptr, len, &attrval, "IP4_subnet");
			out_raw(mask, sizeof(mask), &attrval, "IP4_submsk");
		    }
		    break;
		case INTERNAL_IP4_DNS:
		    if (!isanyaddr(&ia->dns[dns_idx]))
		    {
 		    	len = addrbytesptr(&ia->dns[dns_idx++], &byte_ptr);
 		        out_raw(byte_ptr, len, &attrval, "IP4_dns");
		    }
		    if (dns_idx < 2 && !isanyaddr(&ia->dns[dns_idx]))
		    {
			dont_advance = TRUE;
		    }
 		    break;
		case INTERNAL_IP4_NBNS:
		    if (!isanyaddr(&ia->wins[wins_idx]))
		    {
			len = addrbytesptr(&ia->wins[wins_idx++], &byte_ptr);
			out_raw(byte_ptr, len, &attrval, "IP4_wins");
		    }
		    if (wins_idx < 2 && !isanyaddr(&ia->wins[wins_idx]))
		    {
			dont_advance = TRUE;
		    }
		    break;
		case XAUTH_TYPE:
		    break;
		case XAUTH_USER_NAME:
		    if (ia->xauth_secret.user_name.ptr != NULL)
		    {
			out_raw(ia->xauth_secret.user_name.ptr
			      , ia->xauth_secret.user_name.len
			      , &attrval, "xauth_user_name");
		    }
		    break;
		case XAUTH_USER_PASSWORD:
		    if (ia->xauth_secret.user_password.ptr != NULL)
		    {
			out_raw(ia->xauth_secret.user_password.ptr
			      , ia->xauth_secret.user_password.len
			      , &attrval, "xauth_user_password");
		    }
		    break;
		case XAUTH_STATUS:
		    break;
		case UNITY_BANNER:
		    if (ia->unity_banner != NULL)
		    {
			out_raw(ia->unity_banner
			      , strlen(ia->unity_banner)
			      , &attrval, "UNITY_BANNER");
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
		attr_set >>= 1;
	    }
	}
	close_message(&strattr);
    }

    modecfg_hash(r_hashval, r_hash_start, rbody->cur, st);
    close_message(rbody);
    encrypt_message(rbody, st);
    return STF_OK;
}

/*
 * Send ModeCfg message
 */
static stf_status
modecfg_send_msg(struct state *st, int isama_type, internal_addr_t *ia)
{
    pb_stream msg;
    pb_stream rbody;
    char buf[BUF_LEN];

    /* set up attr */
    init_pbs(&msg, buf, sizeof(buf), "ModeCfg msg buffer");

    /* this is the beginning of a new exchange */
    st->st_msgid = generate_msgid(st);
    init_phase2_iv(st, &st->st_msgid);

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

	if (!out_struct(&hdr, &isakmp_hdr_desc, &msg, &rbody))
	{
	    return STF_INTERNAL_ERROR;
	}
    }

    /* ATTR out */
    modecfg_build_msg(st, &rbody
			, isama_type
			, ia
			, 0 /* XXX isama_id */
		     );

    freeanychunk(st->st_tpacket);
    clonetochunk(st->st_tpacket, msg.start, pbs_offset(&msg), "ModeCfg msg");

    /* Transmit */
    send_packet(st, "ModeCfg msg");

    if (st->st_event->ev_type != EVENT_RETRANSMIT)
    {
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);
    }
    return STF_OK;
}

/*
 * Parse a ModeCfg attribute payload
 */
static stf_status
modecfg_parse_attributes(pb_stream *attrs, internal_addr_t *ia)
{
    struct isakmp_attribute attr;
    pb_stream strattr;

    while (pbs_left(attrs) >= sizeof(struct isakmp_attribute))
    {
	u_int16_t attr_type;
	u_int16_t attr_len;

	if (!in_struct(&attr, &isakmp_modecfg_attribute_desc, attrs, &strattr))
	{
	    return STF_FAIL;
	}
	attr_type = attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK;
	attr_len  = attr.isaat_lv;

	switch (attr_type)
	{
	case INTERNAL_IP4_ADDRESS:
	    if (attr_len == 4)
	    {
		initaddr((char *)(strattr.cur), 4, AF_INET, &ia->ipaddr);
	    }
	    /* fall through to set attribute flag */
	case INTERNAL_IP4_NETMASK:
	case INTERNAL_IP4_DNS:
	case INTERNAL_IP4_SUBNET:
	case INTERNAL_IP4_NBNS:
	    ia->attr_set |= LELEM(attr_type);
	    break;
	case APPLICATION_VERSION:
	    if (attr_len > 0)
	    {
		DBG(DBG_PARSING,
		    DBG_log("   '%.*s'", attr_len, strattr.cur)
		)
	    }
	    ia->attr_set |= LELEM(attr_type);
	    break;
	case XAUTH_TYPE:
	    ia->xauth_type = attr.isaat_lv;
	    ia->xauth_attr_set |= LELEM(attr_type - XAUTH_BASE);
	    break;
	case XAUTH_USER_NAME:
	    setchunk(ia->xauth_secret.user_name, strattr.cur, attr_len);
	    ia->xauth_attr_set |= LELEM(attr_type - XAUTH_BASE);
	    break;
	case XAUTH_USER_PASSWORD:
	    setchunk(ia->xauth_secret.user_password, strattr.cur, attr_len);
	    ia->xauth_attr_set |= LELEM(attr_type - XAUTH_BASE);
	    break;
	case XAUTH_STATUS:
	    ia->xauth_status = attr.isaat_lv;
	    ia->xauth_attr_set |= LELEM(attr_type - XAUTH_BASE);
	    break;
	case XAUTH_PASSCODE:
	case XAUTH_MESSAGE:
	case XAUTH_CHALLENGE:
	case XAUTH_DOMAIN:
	case XAUTH_NEXT_PIN:
	case XAUTH_ANSWER:
	    ia->xauth_attr_set |= LELEM(attr_type - XAUTH_BASE);
	    break;
	case UNITY_DDNS_HOSTNAME:
	    if (attr_len > 0)
	    {
		DBG(DBG_PARSING,
		    DBG_log("   '%.*s'", attr_len, strattr.cur)
		)
	    }
	    /* fall through to set attribute flag */
	case UNITY_BANNER:
	case UNITY_SAVE_PASSWD:
	case UNITY_DEF_DOMAIN:
	case UNITY_SPLITDNS_NAME:
	case UNITY_SPLIT_INCLUDE:
	case UNITY_NATT_PORT:
	case UNITY_LOCAL_LAN:
	case UNITY_PFS:
	case UNITY_FW_TYPE:
	case UNITY_BACKUP_SERVERS:
	    ia->unity_attr_set |= LELEM(attr_type - UNITY_BASE);
	    break;
	default:
	    plog("unsupported ModeCfg attribute %s received."
		, enum_show(&modecfg_attr_names, attr_type));
	    break;
	}
    }
    return STF_OK;
}

/* 
 * Parse a ModeCfg message
 */
static stf_status
modecfg_parse_msg(struct msg_digest *md, int isama_type, u_int16_t *isama_id
		, internal_addr_t *ia)
{
    struct state *const st = md->st;
    struct payload_digest *p;
    stf_status stat;

    st->st_msgid = md->hdr.isa_msgid;

    CHECK_QUICK_HASH(md, modecfg_hash(hash_val
				    , hash_pbs->roof
				    , md->message_pbs.roof, st)
		       , "MODECFG-HASH", "ISAKMP_CFG_MSG");

    /* process the ModeCfg payloads received */
    for (p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
    {
	internal_addr_t ia_candidate;

	init_internal_addr(&ia_candidate);

	if (p->payload.attribute.isama_type == isama_type)
	{
	    *isama_id = p->payload.attribute.isama_identifier;

	    stat = modecfg_parse_attributes(&p->pbs, &ia_candidate);
	    if (stat == STF_OK)
	    {
		/* return with a valid set of attributes */
		*ia = ia_candidate;
		return STF_OK;
	    }
	}
	else
	{
	    plog("expected %s, got %s instead (ignored)"
		, enum_name(&attr_msg_type_names, isama_type)
		, enum_name(&attr_msg_type_names, p->payload.attribute.isama_type));

	    stat = modecfg_parse_attributes(&p->pbs, &ia_candidate);
	}
	if (stat != STF_OK)
	    return stat;
    }
    return STF_IGNORE;
}

/*
 * Send ModeCfg request message from client to server in pull mode
 */
stf_status
modecfg_send_request(struct state *st)
{
    stf_status stat;
    internal_addr_t ia;

    init_internal_addr(&ia);

    ia.attr_set = LELEM(INTERNAL_IP4_ADDRESS)
	        | LELEM(INTERNAL_IP4_NETMASK);

    plog("sending ModeCfg request");
    st->st_state = STATE_MODE_CFG_I1;
    stat = modecfg_send_msg(st, ISAKMP_CFG_REQUEST, &ia);
    if (stat == STF_OK)
	st->st_modecfg.started = TRUE;
    return stat;
}

/* STATE_MODE_CFG_R0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * used in ModeCfg pull mode, on the server (responder)
 */
stf_status
modecfg_inR0(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    bool want_unity_banner;
    stf_status stat, stat_build;

    stat = modecfg_parse_msg(md, ISAKMP_CFG_REQUEST, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;

    want_unity_banner = (ia.unity_attr_set & LELEM(UNITY_BANNER - UNITY_BASE)) != LEMPTY;

    init_internal_addr(&ia);
    get_internal_addr(st->st_connection, &ia);

    if (want_unity_banner)
    {
	ia.unity_banner = UNITY_BANNER_STR;
	ia.unity_attr_set |= LELEM(UNITY_BANNER - UNITY_BASE);
    }

    plog("sending ModeCfg reply");

    stat_build = modecfg_build_msg(st, &md->rbody
				     , ISAKMP_CFG_REPLY
				     , &ia
				     , isama_id);
    if (stat_build != STF_OK)
	return stat_build;

    st->st_msgid = 0;
    return STF_OK;
}

/* STATE_MODE_CFG_I1:
 * HDR*, HASH, ATTR(REPLY=IP)
 *
 * used in ModeCfg pull mode, on the client (initiator) 
 */
stf_status
modecfg_inI1(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    stf_status stat;

    plog("parsing ModeCfg reply");

    stat = modecfg_parse_msg(md, ISAKMP_CFG_REPLY, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;

    st->st_modecfg.vars_set = set_internal_addr(st->st_connection, &ia);
    st->st_msgid = 0;
    return STF_OK;
}


/*
 * Send ModeCfg set message from server to client in push mode
 */
stf_status
modecfg_send_set(struct state *st)
{
    stf_status stat;
    internal_addr_t ia;

    init_internal_addr(&ia);
    get_internal_addr(st->st_connection, &ia);

#ifdef CISCO_QUIRKS
    ia.unity_banner = UNITY_BANNER_STR;
    ia.unity_attr_set |= LELEM(UNITY_BANNER - UNITY_BASE);
#endif

   plog("sending ModeCfg set");
    st->st_state = STATE_MODE_CFG_R3;
    stat = modecfg_send_msg(st, ISAKMP_CFG_SET, &ia);
    if (stat == STF_OK)
	st->st_modecfg.started = TRUE;
    return stat;
}

/* STATE_MODE_CFG_I0:
 *  HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * used in ModeCfg push mode, on the client (initiator).
 */
stf_status
modecfg_inI0(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    lset_t attr_set, unity_attr_set;
    stf_status stat, stat_build;

    plog("parsing ModeCfg set");

    stat = modecfg_parse_msg(md, ISAKMP_CFG_SET, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;

    st->st_modecfg.vars_set = set_internal_addr(st->st_connection, &ia);

    /* prepare ModeCfg ack which sends zero length attributes */
    attr_set = ia.attr_set;
    unity_attr_set = ia.unity_attr_set;
    init_internal_addr(&ia);
    ia.attr_set = attr_set & SUPPORTED_ATTR_SET;
    ia.unity_attr_set = unity_attr_set & SUPPORTED_UNITY_ATTR_SET;

    plog("sending ModeCfg ack");

    stat_build = modecfg_build_msg(st, &md->rbody
			 	     , ISAKMP_CFG_ACK
			 	     , &ia
			 	     , isama_id);
    if (stat_build != STF_OK)
	return stat_build;

    st->st_msgid = 0;
    return STF_OK;
}

/* STATE_MODE_CFG_R3:
 * HDR*, HASH, ATTR(ACK,OK)
 *
 * used in ModeCfg push mode, on the server (responder)
 */
stf_status
modecfg_inR3(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    stf_status stat;

    plog("parsing ModeCfg ack");

    stat = modecfg_parse_msg(md, ISAKMP_CFG_ACK, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;

    st->st_msgid = 0;
    return STF_OK;
}

/*
 * Send XAUTH credentials request (username + password)
 */
stf_status
xauth_send_request(struct state *st)
{
    stf_status stat;
    internal_addr_t ia;

    init_internal_addr(&ia);
    ia.xauth_attr_set = LELEM(XAUTH_USER_NAME     - XAUTH_BASE)
		      | LELEM(XAUTH_USER_PASSWORD - XAUTH_BASE);

    plog("sending XAUTH request");
    st->st_state = STATE_XAUTH_R1;
    stat = modecfg_send_msg(st, ISAKMP_CFG_REQUEST, &ia);
    if (stat == STF_OK)
	st->st_xauth.started = TRUE;
    return stat;
}

/* STATE_XAUTH_I0:
 * HDR*, HASH, ATTR(REQ) --> HDR*, HASH, ATTR(REPLY=USERNAME/PASSWORD)
 *
 * used on the XAUTH client (initiator)
 */
stf_status
xauth_inI0(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    stf_status stat, stat_build;

    plog("parsing XAUTH request");

    stat = modecfg_parse_msg(md, ISAKMP_CFG_REQUEST, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;
 
    /* check XAUTH attributes */
    if ((ia.xauth_attr_set & LELEM(XAUTH_TYPE - XAUTH_BASE)) != LEMPTY
    && ia.xauth_type != XAUTH_TYPE_GENERIC)
    {
	plog("xauth type %s is not supported", enum_name(&xauth_type_names, ia.xauth_type));
	stat = STF_FAIL;
    }
    else if ((ia.xauth_attr_set & LELEM(XAUTH_USER_NAME - XAUTH_BASE)) == LEMPTY)
    {
	plog("user name attribute is missing in XAUTH request");
	stat = STF_FAIL;
    }
    else if ((ia.xauth_attr_set & LELEM(XAUTH_USER_PASSWORD - XAUTH_BASE)) == LEMPTY)
    {
	plog("user password attribute is missing in XAUTH request");
	stat = STF_FAIL;
    }

    /* prepare XAUTH reply */
    init_internal_addr(&ia);

    if (stat == STF_OK)
    {
	/* get user credentials using a plugin function */
	if (!xauth_module.get_secret(&ia.xauth_secret))
	{
	    plog("xauth user credentials not found");
	    stat = STF_FAIL;
	}
    }
    if (stat == STF_OK)
    {
	DBG(DBG_CONTROL,
	    DBG_log("my xauth user name is '%.*s'"
		   , ia.xauth_secret.user_name.len
		   , ia.xauth_secret.user_name.ptr)
	)
	DBG(DBG_PRIVATE,
	    DBG_log("my xauth user password is '%.*s'"
		   , ia.xauth_secret.user_password.len
		   , ia.xauth_secret.user_password.ptr)
	)
	ia.xauth_attr_set = LELEM(XAUTH_USER_NAME     - XAUTH_BASE)
		 	  | LELEM(XAUTH_USER_PASSWORD - XAUTH_BASE);
    }
    else
    {
	ia.xauth_attr_set = LELEM(XAUTH_STATUS - XAUTH_BASE);
	ia.xauth_status = XAUTH_STATUS_FAIL;
    }

    plog("sending XAUTH reply");

    stat_build = modecfg_build_msg(st, &md->rbody
				     , ISAKMP_CFG_REPLY
				     , &ia
				     , isama_id);
    if (stat_build != STF_OK)
	return stat_build;

    if (stat == STF_OK)
    {
	st->st_xauth.started = TRUE;
	return STF_OK;
    }
    else
    {
	/* send XAUTH reply msg and then delete ISAKMP SA */
	freeanychunk(st->st_tpacket);
	clonetochunk(st->st_tpacket, md->reply.start
	    , pbs_offset(&md->reply), "XAUTH reply msg");
	send_packet(st, "XAUTH reply msg");
	delete_state(st);
	return STF_IGNORE;
    }
}

/* STATE_XAUTH_R1:
 *  HDR*, HASH, ATTR(REPLY=USERNAME/PASSWORD) --> HDR*, HASH, ATTR(STATUS)
 *
 *  used on the XAUTH server (responder)
 */
stf_status
xauth_inR1(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    stf_status stat, stat_build;

    plog("parsing XAUTH reply");

    stat = modecfg_parse_msg(md, ISAKMP_CFG_REPLY, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;
 
    /* did the client return an XAUTH FAIL status? */
    if ((ia.xauth_attr_set & LELEM(XAUTH_STATUS - XAUTH_BASE)) != LEMPTY)
    {
	plog("received FAIL status in XAUTH reply");

	/* client is not able to do XAUTH, delete ISAKMP SA */
	delete_state(st);
	return STF_IGNORE;
    }

    /* check XAUTH reply */
    if ((ia.xauth_attr_set & LELEM(XAUTH_USER_NAME - XAUTH_BASE)) == LEMPTY)
    {
	plog("user name attribute is missing in XAUTH reply");
	st->st_xauth.status = FALSE;
    }
    else if ((ia.xauth_attr_set & LELEM(XAUTH_USER_PASSWORD - XAUTH_BASE)) == LEMPTY)
    {
	plog("user password attribute is missing in XAUTH reply");
	st->st_xauth.status = FALSE;
    }
    else 
    {
	DBG(DBG_CONTROL,
	    DBG_log("peer xauth user name is '%.*s'"
		   , ia.xauth_secret.user_name.len
		   , ia.xauth_secret.user_name.ptr)
	)
	DBG(DBG_PRIVATE,
	    DBG_log("peer xauth user password is '%.*s'"
		   , ia.xauth_secret.user_password.len
		   , ia.xauth_secret.user_password.ptr)
	)
	/* verify the user credentials using a plugn function */
	st->st_xauth.status = xauth_module.verify_secret(&ia.xauth_secret);
	plog("extended authentication %s", st->st_xauth.status? "was successful":"failed");
    }

    /* prepare XAUTH set which sends the authentication status */
    init_internal_addr(&ia);
    ia.xauth_attr_set = LELEM(XAUTH_STATUS - XAUTH_BASE);
    ia.xauth_status = (st->st_xauth.status)? XAUTH_STATUS_OK : XAUTH_STATUS_FAIL;

    plog("sending XAUTH status:");

    stat_build = modecfg_build_msg(st, &md->rbody
			 	     , ISAKMP_CFG_SET
			 	     , &ia
			 	     , isama_id);
     if (stat_build != STF_OK)
	return stat_build;
    return STF_OK;
}

/* STATE_XAUTH_I1:
 * HDR*, HASH, ATTR(STATUS) --> HDR*, HASH, ATTR(ACK)
 *
 * used on the XAUTH client (initiator)
 */
stf_status
xauth_inI1(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    stf_status stat, stat_build;

    plog("parsing XAUTH status");
    stat = modecfg_parse_msg(md, ISAKMP_CFG_SET, &isama_id, &ia);
    if (stat != STF_OK)
    {
	/* notification payload - not exactly the right choice, but okay */
	md->note = ATTRIBUTES_NOT_SUPPORTED;
	return stat;
    }

    st->st_xauth.status = ia.xauth_status;
    plog("extended authentication %s", st->st_xauth.status? "was successful":"failed");

    plog("sending XAUTH ack");
    init_internal_addr(&ia);
    stat_build = modecfg_build_msg(st, &md->rbody
				     , ISAKMP_CFG_ACK
				     , &ia
				     , isama_id);
    if (stat_build != STF_OK)
	return stat_build;
 
    if (st->st_xauth.status)
    {
	st->st_msgid = 0;
	return STF_OK;
    }
    else
    {
	/* send XAUTH ack msg and then delete ISAKMP SA */
	freeanychunk(st->st_tpacket);
	clonetochunk(st->st_tpacket, md->reply.start
	    , pbs_offset(&md->reply), "XAUTH ack msg");
	send_packet(st, "XAUTH ack msg");
	delete_state(st);
	return STF_IGNORE;
    }
}

/* STATE_XAUTH_R2:
 * HDR*, ATTR(STATUS), HASH --> Done
 *
 * used on the XAUTH server (responder)
 */
stf_status
xauth_inR2(struct msg_digest *md)
{
    struct state *const st = md->st;
    u_int16_t isama_id;
    internal_addr_t ia;
    stf_status stat;

    plog("parsing XAUTH ack");

    stat = modecfg_parse_msg(md, ISAKMP_CFG_ACK, &isama_id, &ia);
    if (stat != STF_OK)
	return stat;

    st->st_msgid = 0;
    if (st->st_xauth.status)
    {
	return STF_OK;
    }
    else
    {
	delete_state(st);
	return STF_IGNORE;
    }
}
