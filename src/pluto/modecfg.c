/* Mode config related functions
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2006-2010 Andreas Steffen - Hochschule fuer Technik Rapperswil
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
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <freeswan.h>

#include <library.h>
#include <hydra.h>
#include <utils/linked_list.h>
#include <crypto/prfs/prf.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "demux.h"
#include "timer.h"
#include "ipsec_doi.h"
#include "log.h"
#include "crypto.h"
#include "modecfg.h"
#include "whack.h"
#include "pluto.h"

#define MAX_XAUTH_TRIES         3

#define DEFAULT_UNITY_BANNER	"Welcome to strongSwan - the Linux VPN Solution!\n"

/**
 * Creates a modecfg_attribute_t object
 */
static modecfg_attribute_t *modecfg_attribute_create(configuration_attribute_type_t type,
													 chunk_t value)
{
	modecfg_attribute_t *this;

	this = malloc_thing(modecfg_attribute_t);
	this->type = ((u_int16_t)type) & 0x7FFF;
	this->is_tv = FALSE;
	this->value = chunk_clone(value);
	this->handler = NULL;

	return this;
}

/**
 * Creates a modecfg_attribute_t object coded in TV format
 */
static modecfg_attribute_t *modecfg_attribute_create_tv(configuration_attribute_type_t type,
															 size_t value)
{
	modecfg_attribute_t *this;

	this = modecfg_attribute_create(type, chunk_empty);
	this->value.len = value;
	this->is_tv = TRUE;

	return this;
}

/**
 * Destroys a modecfg_attribute_t object
 */
void modecfg_attribute_destroy(modecfg_attribute_t *this)
{
	free(this->value.ptr);
	free(this);
}

/**
 * Get attributes to be sent to client
 */
static void get_attributes(connection_t *c, linked_list_t *ca_list)
{
	configuration_attribute_type_t type;
	modecfg_attribute_t *ca;
	enumerator_t *enumerator;
	chunk_t value;
	host_t *vip = NULL, *requested_vip = NULL;
	bool want_unity_banner = FALSE;
	int family;

#ifdef CISCO_QUIRKS
	/* always send banner in ModeCfg push mode */
	if (ca_list->get_count(ca_list) == 0)
	{
		want_unity_banner = TRUE;
	}
#endif

	/* scan list of requested attributes in ModeCfg pull mode */
	while (ca_list->remove_last(ca_list, (void **)&ca) == SUCCESS)
	{
		switch (ca->type)
		{
			case INTERNAL_IP4_ADDRESS:
			case INTERNAL_IP6_ADDRESS:
			{
				int family;

				family = (ca->type == INTERNAL_IP4_ADDRESS) ? AF_INET : AF_INET6;
				requested_vip = (ca->value.len) ?
								host_create_from_chunk(family, ca->value, 0) :
					 			host_create_any(family);
				plog("peer requested virtual IP %H", requested_vip);
				break;
			}
#ifdef CISCO_QUIRKS
			case UNITY_BANNER:
				want_unity_banner = TRUE;
				break;
#endif
			default:
				break;
		}
		modecfg_attribute_destroy(ca);
	}

	if (requested_vip == NULL)
	{
		requested_vip = host_create_any(AF_INET);
	}

	/* if no virtual IP has been assigned yet - acquire one */
	if (c->spd.that.host_srcip->is_anyaddr(c->spd.that.host_srcip))
	{
		if (c->spd.that.pool)
		{
			identification_t *client_id;

			client_id = (c->xauth_identity) ? c->xauth_identity : c->spd.that.id;
			vip = hydra->attributes->acquire_address(hydra->attributes,
								c->spd.that.pool, client_id, requested_vip);
			if (vip)
			{
				c->spd.that.host_srcip->destroy(c->spd.that.host_srcip);
				c->spd.that.host_srcip = vip;
			}
		}
		else
		{
			plog("no virtual IP found");
		}
	}

	requested_vip->destroy(requested_vip);

	/* if we have a virtual IP address - send it */
	if (!c->spd.that.host_srcip->is_anyaddr(c->spd.that.host_srcip))  
	{
		vip = c->spd.that.host_srcip;
		plog("assigning virtual IP %H to peer", vip);
		family = vip->get_family(vip);
		ca = modecfg_attribute_create((family == AF_INET) ?
									   INTERNAL_IP4_ADDRESS :
									   INTERNAL_IP6_ADDRESS,
									   vip->get_address(vip));
		ca_list->insert_last(ca_list, ca);

		/* set the remote client subnet to virtual IP */
		c->spd.that.client.addr     = *(ip_address*)vip->get_sockaddr(vip);
		c->spd.that.client.maskbits = (family == AF_INET) ? 32 : 128; 
		c->spd.that.has_client      = TRUE;
	}

	/* assign attributes from registered providers */
	enumerator = hydra->attributes->create_responder_enumerator(hydra->attributes,
											c->spd.that.id, vip);
	while (enumerator->enumerate(enumerator, &type, &value))
	{
		ca = modecfg_attribute_create(type, value);
		ca_list->insert_last(ca_list, ca);
		if (type == UNITY_BANNER)
		{
			want_unity_banner = FALSE;
		}
	}
	enumerator->destroy(enumerator);

	if (want_unity_banner)
	{
		ca = modecfg_attribute_create(UNITY_BANNER,
									  chunk_create(DEFAULT_UNITY_BANNER,
									  strlen(DEFAULT_UNITY_BANNER)));
		ca_list->insert_last(ca_list, ca);
	}
}

/**
 * Set srcip and client subnet to internal IP address
 */
static bool set_attributes(connection_t *c, linked_list_t *ca_list)
{
	host_t *vip, *srcip;
	modecfg_attribute_t *ca, *ca_handler;
	enumerator_t *enumerator;
	bool vip_set = FALSE;

	enumerator = ca_list->create_enumerator(ca_list);
	while (enumerator->enumerate(enumerator, &ca))
	{
		int family = AF_INET6;
		attribute_handler_t *handler = NULL;
		enumerator_t *e;

		switch (ca->type)
		{
			case INTERNAL_IP4_ADDRESS:
				family = AF_INET;
				/* fall */
			case INTERNAL_IP6_ADDRESS:
				if (ca->value.len == 0)
				{
					vip = host_create_any(family);
				}
				else
				{
					/* skip prefix byte in IPv6 payload*/
					if (family == AF_INET6)
					{
						ca->value.len = 16;
					}
					vip = host_create_from_chunk(family, ca->value, 0);
				}
				if (vip)
				{
					srcip = c->spd.this.host_srcip;

					if (srcip->is_anyaddr(srcip) || srcip->equals(srcip, vip))
					{
						plog("setting virtual IP source address to %H", vip);
					}
					else
					{
						plog("replacing virtual IP source address %H by %H",
							  srcip, vip);
					}
					srcip->destroy(srcip);
					c->spd.this.host_srcip = vip;

					/* setting client subnet to vip/32 */
					addrtosubnet((ip_address*)vip->get_sockaddr(vip),
								 &c->spd.this.client);
					setportof(0, &c->spd.this.client.addr);
					c->spd.this.has_client = TRUE;

					vip_set = TRUE;	
				}	
				continue;
			case APPLICATION_VERSION:
#ifdef CISCO_QUIRKS
			case UNITY_BANNER:
#endif
				if (ca->value.len > 0)
				{
					DBG(DBG_PARSING | DBG_CONTROLMORE,
						DBG_log("   '%.*s'", ca->value.len, ca->value.ptr)
					)
				}
				break;
			default:
				break;
		}

		/* find the first handler which requested this attribute */
		e = c->requested->create_enumerator(c->requested);
		while (e->enumerate(e, &ca_handler))
		{
			if (ca_handler->type == ca->type)
			{
				handler = ca_handler->handler;
				break;
			}
		}
		e->destroy(e);

		/* and pass it to the handle function */
		handler = hydra->attributes->handle(hydra->attributes,
							 c->spd.that.id, handler, ca->type, ca->value);
		if (handler)
		{
			ca_handler = modecfg_attribute_create(ca->type, ca->value);
			ca_handler->handler = handler;

			if (c->attributes == NULL)
			{
				c->attributes = linked_list_create();
			}
			c->attributes->insert_last(c->attributes, ca_handler);
		}
	}
	enumerator->destroy(enumerator);
	c->requested->destroy_function(c->requested, (void*)modecfg_attribute_destroy);
	c->requested = NULL;
	return vip_set;
}

/**
 * Register configuration attribute handlers
 */
static void register_attribute_handlers(connection_t *c)
{
	configuration_attribute_type_t type;
	modecfg_attribute_t *ca;
	chunk_t value;
	attribute_handler_t *handler;
	enumerator_t *enumerator;

	/* add configuration attributes requested by handlers */
	if (c->requested == NULL)
	{
		c->requested = linked_list_create();
	}
	enumerator = hydra->attributes->create_initiator_enumerator(
							hydra->attributes,c->spd.that.id, c->spd.this.host_srcip);
	while (enumerator->enumerate(enumerator, &handler, &type, &value))
	{
		ca = modecfg_attribute_create(type, value);
		ca->handler = handler;
		c->requested->insert_last(c->requested, ca);
	}
	enumerator->destroy(enumerator);
}

/**
 * Compute HASH of Mode Config.
 */
static size_t modecfg_hash(u_char *dest, u_char *start, u_char *roof,
						   const struct state *st)
{
	chunk_t msgid_chunk = chunk_from_thing(st->st_msgid);
	chunk_t msg_chunk = { start, roof - start };
	size_t prf_block_size;
	pseudo_random_function_t prf_alg;
	prf_t *prf;

	prf_alg = oakley_to_prf(st->st_oakley.hash);
	prf = lib->crypto->create_prf(lib->crypto, prf_alg);
	prf->set_key(prf, st->st_skeyid_a);
	prf->get_bytes(prf, msgid_chunk, NULL);
	prf->get_bytes(prf, msg_chunk, dest);
	prf_block_size = prf->get_block_size(prf);
	prf->destroy(prf);

	DBG(DBG_CRYPT,
		DBG_log("ModeCfg HASH computed:");
		DBG_dump("", dest, prf_block_size)
	)
	return prf_block_size;
}


/**
 * Generate an IKE message containing ModeCfg information (eg: IP, DNS, WINS)
 */
static stf_status modecfg_build_msg(struct state *st, pb_stream *rbody,
									u_int16_t msg_type,	linked_list_t *ca_list,
									u_int16_t ap_id)
{
	u_char *r_hash_start, *r_hashval;
	struct isakmp_mode_attr attrh;
	struct isakmp_attribute attr;
	pb_stream strattr,attrval;
	enumerator_t *enumerator;
	modecfg_attribute_t *ca;

	START_HASH_PAYLOAD(*rbody, ISAKMP_NEXT_ATTR);

	attrh.isama_np         = ISAKMP_NEXT_NONE;
	attrh.isama_type       = msg_type;
	attrh.isama_identifier = ap_id;

	if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
	{
		return STF_INTERNAL_ERROR;
	}

	enumerator = ca_list->create_enumerator(ca_list);
	while (enumerator->enumerate(enumerator, &ca))
	{
		DBG(DBG_CONTROLMORE,
			DBG_log("building %N attribute", configuration_attribute_type_names, ca->type)
		)
		if (ca->is_tv)
		{
			attr.isaat_af_type = ca->type | ISAKMP_ATTR_AF_TV;
			attr.isaat_lv = ca->value.len;
			out_struct(&attr, &isakmp_modecfg_attribute_desc, &strattr, &attrval);
		}
		else
		{
			char buf[BUF_LEN];

			attr.isaat_af_type = ca->type | ISAKMP_ATTR_AF_TLV;
			out_struct(&attr, &isakmp_modecfg_attribute_desc, &strattr, &attrval);
			snprintf(buf, BUF_LEN, "%N", configuration_attribute_type_names, ca->type);
			out_raw(ca->value.ptr, ca->value.len, &attrval, buf);
		}
		close_output_pbs(&attrval);
	}
	enumerator->destroy(enumerator);
	close_message(&strattr);
	
	modecfg_hash(r_hashval, r_hash_start, rbody->cur, st);
	close_message(rbody);
	encrypt_message(rbody, st);
	return STF_OK;
}

/**
 * Send ModeCfg message
 */
static stf_status modecfg_send_msg(struct state *st, int isama_type,
								   linked_list_t *ca_list)
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

		zero(&hdr);     /* default to 0 */
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

	/* ATTR out with isama_id of 0 */
	modecfg_build_msg(st, &rbody, isama_type, ca_list, 0);

	free(st->st_tpacket.ptr);
	st->st_tpacket = chunk_create(msg.start, pbs_offset(&msg));
	st->st_tpacket = chunk_clone(st->st_tpacket);

	/* Transmit */
	send_packet(st, "ModeCfg msg");

	if (st->st_event->ev_type != EVENT_RETRANSMIT)
	{
		delete_event(st);
		event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);
	}
	return STF_OK;
}

/**
 * Parse a ModeCfg attribute payload
 */
static stf_status modecfg_parse_attributes(pb_stream *attrs, linked_list_t *ca_list)
{
	struct isakmp_attribute attr;
	pb_stream strattr;
	u_int16_t attr_type;
	u_int16_t attr_len;
	chunk_t attr_chunk;
	modecfg_attribute_t *ca;

	while (pbs_left(attrs) >= sizeof(struct isakmp_attribute))
	{
		if (!in_struct(&attr, &isakmp_modecfg_attribute_desc, attrs, &strattr))
		{
			return STF_FAIL;
		}
		attr_type = attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK;
		attr_len  = attr.isaat_lv;
		DBG(DBG_CONTROLMORE,
			DBG_log("processing %N attribute",
					configuration_attribute_type_names, attr_type)
		)

		switch (attr_type)
		{
			case INTERNAL_IP4_ADDRESS:
			case INTERNAL_IP4_NETMASK:
			case INTERNAL_IP4_DNS:
			case INTERNAL_IP4_NBNS:
			case INTERNAL_ADDRESS_EXPIRY:
			case INTERNAL_IP4_DHCP:
				if (attr_len != 4 && attr_len != 0)
				{
					goto error;
				}
				break;
			case INTERNAL_IP4_SUBNET:
				if (attr_len != 8 && attr_len != 0)
				{
					goto error;
				}
				break;
			case INTERNAL_IP6_NETMASK:
			case INTERNAL_IP6_DNS:
			case INTERNAL_IP6_NBNS:
			case INTERNAL_IP6_DHCP:
				if (attr_len != 16 && attr_len != 0)
				{
					goto error;
				}
				break;
			case INTERNAL_IP6_ADDRESS:
				if (attr_len != 17 && attr_len != 16 && attr_len != 0)
				{
					goto error;
				}
				break;
			case INTERNAL_IP6_SUBNET:
				if (attr_len != 17 && attr_len != 0)
				{
					goto error;
				}
				break;
			case SUPPORTED_ATTRIBUTES:
				if (attr_len % 2)
				{
					goto error;
				}
				break;
			case APPLICATION_VERSION:
				break;
			/* XAUTH attributes */
			case XAUTH_TYPE:
			case XAUTH_STATUS:
			case XAUTH_USER_NAME:
			case XAUTH_USER_PASSWORD:
			case XAUTH_PASSCODE:
			case XAUTH_MESSAGE:
			case XAUTH_CHALLENGE:
			case XAUTH_DOMAIN:
			case XAUTH_NEXT_PIN:
			case XAUTH_ANSWER:
				break;
			/* Microsoft attributes */
			case INTERNAL_IP4_SERVER:
			case INTERNAL_IP6_SERVER:
				break;
			/* Cisco Unity attributes */
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
			case UNITY_DDNS_HOSTNAME:
				break;
			default:
				plog("unknown attribute type (%u)", attr_type);
				continue;
		}

		/* add attribute */
		if (attr.isaat_af_type & ISAKMP_ATTR_AF_TV)
		{
			ca = modecfg_attribute_create_tv(attr_type, attr_len);
		}
		else
		{
			attr_chunk = chunk_create(strattr.cur, attr_len);
			ca = modecfg_attribute_create(attr_type, attr_chunk);
		}
		ca_list->insert_last(ca_list, ca);
	}
	return STF_OK;

error:
	plog("%N attribute has invalid size of %u octets",
		 configuration_attribute_type_names, attr_type, attr_len);
	return STF_FAIL;
}

/**
 * Parse a ModeCfg message
 */
static stf_status modecfg_parse_msg(struct msg_digest *md, int isama_type,
									u_int16_t *isama_id, linked_list_t *ca_list)
{
	modecfg_attribute_t *ca;
	struct state *const st = md->st;
	struct payload_digest *p;
	stf_status stat;

	st->st_msgid = md->hdr.isa_msgid;

	CHECK_QUICK_HASH(md, modecfg_hash(hash_val, hash_pbs->roof,
					 md->message_pbs.roof, st), "MODECFG-HASH", "ISAKMP_CFG_MSG");

	/* process the ModeCfg payloads received */
	for (p = md->chain[ISAKMP_NEXT_ATTR]; p != NULL; p = p->next)
	{
		if (p->payload.attribute.isama_type == isama_type)
		{
			*isama_id = p->payload.attribute.isama_identifier;

			stat = modecfg_parse_attributes(&p->pbs, ca_list);
			if (stat == STF_OK)
			{
				/* return with a valid set of attributes */
				return STF_OK;
			}
		}
		else
		{
			plog("expected %s, got %s instead (ignored)"
				, enum_name(&attr_msg_type_names, isama_type)
				, enum_name(&attr_msg_type_names, p->payload.attribute.isama_type));

			stat = modecfg_parse_attributes(&p->pbs, ca_list);
		}

		/* abort if a parsing error occurred */
		if (stat != STF_OK)
		{
			ca_list->destroy_function(ca_list, (void*)modecfg_attribute_destroy);
			return stat;
		}
			
		/* discard the parsed attributes and look for another payload */
		while (ca_list->remove_last(ca_list, (void **)&ca) == SUCCESS) {}
	}
	return STF_IGNORE;
}

/**
 * Used in ModeCfg pull mode on the client (initiator)
 *   called in demux.c
 *   client -> CFG_REQUEST
 *   STF_OK transitions to STATE_MODE_CFG_I1
 */
stf_status modecfg_send_request(struct state *st)
{
	connection_t *c = st->st_connection;
	stf_status stat;
	modecfg_attribute_t *ca; 
	enumerator_t *enumerator;
	int family;
	chunk_t value;
	host_t *vip;
	linked_list_t *ca_list = linked_list_create();

	vip = c->spd.this.host_srcip;
	value = vip->is_anyaddr(vip) ? chunk_empty : vip->get_address(vip);
	family = vip->get_family(vip);
	ca = modecfg_attribute_create((family == AF_INET) ?
								   INTERNAL_IP4_ADDRESS : INTERNAL_IP6_ADDRESS,
								   value);
	ca_list->insert_last(ca_list, ca);

	register_attribute_handlers(c);	
	enumerator = c->requested->create_enumerator(c->requested);
	while (enumerator->enumerate(enumerator, &ca))
	{
		ca = modecfg_attribute_create(ca->type, chunk_empty);
		ca_list->insert_last(ca_list, ca);
	}
	enumerator->destroy(enumerator);

	plog("sending ModeCfg request");

	st->st_state = STATE_MODE_CFG_I1;
	stat = modecfg_send_msg(st, ISAKMP_CFG_REQUEST, ca_list);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	if (stat == STF_OK)
	{
		st->st_modecfg.started = TRUE;
	}
	return stat;
}

/**
 * Used in ModeCfg pull mode on the server (responder)
 *   called in demux.c from STATE_MODE_CFG_R0
 *   server <- CFG_REQUEST
 *   server -> CFG_REPLY
 *   STF_OK transitions to  STATE_MODE_CFG_R0
 */
stf_status modecfg_inR0(struct msg_digest *md)
{
	struct state *const st = md->st;
	u_int16_t isama_id;
	stf_status stat, stat_build;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing ModeCfg request");

	stat = modecfg_parse_msg(md, ISAKMP_CFG_REQUEST, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		return stat;
	}

	/* build the CFG_REPLY */
	get_attributes(st->st_connection, ca_list);

	plog("sending ModeCfg reply");

	stat_build = modecfg_build_msg(st, &md->rbody, ISAKMP_CFG_REPLY,
								   ca_list, isama_id);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);

	if (stat_build != STF_OK)
	{
		return stat_build;
	}
	st->st_msgid = 0;
	return STF_OK;
}

/**
 * Used in ModeCfg pull mode on the client (initiator)
 *   called in demux.c from STATE_MODE_CFG_I1
 *   client <- CFG_REPLY
 *   STF_OK transitions to  STATE_MODE_CFG_I2
 */
stf_status modecfg_inI1(struct msg_digest *md)
{
	struct state *const st = md->st;
	u_int16_t isama_id;
	stf_status stat;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing ModeCfg reply");

	stat = modecfg_parse_msg(md, ISAKMP_CFG_REPLY, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		return stat;
	}
	st->st_modecfg.vars_set = set_attributes(st->st_connection, ca_list);
	st->st_msgid = 0;
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	return STF_OK;
}

/**
 * Used in ModeCfg push mode on the server (responder)
 *   called in demux.c
 *   server -> CFG_SET
 *   STF_OK transitions to STATE_MODE_CFG_R3
 */
stf_status modecfg_send_set(struct state *st)
{
	stf_status stat;
	linked_list_t *ca_list = linked_list_create();


	plog("sending ModeCfg set");

	get_attributes(st->st_connection, ca_list);
	st->st_state = STATE_MODE_CFG_R3;
	stat = modecfg_send_msg(st, ISAKMP_CFG_SET, ca_list);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	if (stat == STF_OK)
	{
		st->st_modecfg.started = TRUE;
	}
	return stat;
}

/**
 * Used in ModeCfg push mode on the client (initiator)
 *   called in demux.c from STATE_MODE_CFG_I0
 *   client <- CFG_SET
 *   client -> CFG_ACK 
 *   STF_OK transitions to  STATE_MODE_CFG_I3
 */
stf_status modecfg_inI0(struct msg_digest *md)
{
	struct state *const st = md->st;
	u_int16_t isama_id;
	stf_status stat, stat_build;
	modecfg_attribute_t *ca;
	linked_list_t *ca_list, *ca_ack_list;

	plog("parsing ModeCfg set");

	ca_list = linked_list_create();
	stat = modecfg_parse_msg(md, ISAKMP_CFG_SET, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		return stat;
	}
	register_attribute_handlers(st->st_connection);
	st->st_modecfg.vars_set = set_attributes(st->st_connection, ca_list);

	/* prepare ModeCfg ack which sends zero length attributes */
	ca_ack_list = linked_list_create();
	while (ca_list->remove_last(ca_list, (void **)&ca) == SUCCESS)
	{
		switch (ca->type)
		{
			case INTERNAL_IP4_ADDRESS:
			case INTERNAL_IP4_DNS:
			case INTERNAL_IP4_NBNS:
			case APPLICATION_VERSION:
			case INTERNAL_IP6_ADDRESS:
			case INTERNAL_IP6_DNS:
			case INTERNAL_IP6_NBNS:
#ifdef CISCO_QUIRKS
			case UNITY_BANNER:
#endif
				/* supported attributes */
				ca->value.len = 0;
				ca_ack_list->insert_last(ca_ack_list, ca);
				break;
			default:
				/* unsupportd attributes */
				modecfg_attribute_destroy(ca);
		}
	}
	ca_list->destroy(ca_list);

	plog("sending ModeCfg ack");

	stat_build = modecfg_build_msg(st, &md->rbody, ISAKMP_CFG_ACK,
								   ca_ack_list, isama_id);
	ca_ack_list->destroy_function(ca_ack_list, (void *)modecfg_attribute_destroy);
	if (stat_build != STF_OK)
	{
		return stat_build;
	}
	st->st_msgid = 0;
	return STF_OK;
}

/**
 * Used in ModeCfg push mode on the server (responder)
 *   called in demux.c from STATE_MODE_CFG_R3
 *   server <- CFG_ACK 
 *   STF_OK transitions to  STATE_MODE_CFG_R4
 */
stf_status modecfg_inR3(struct msg_digest *md)
{
	struct state *const st = md->st;
	u_int16_t isama_id;
	stf_status stat;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing ModeCfg ack");

	stat = modecfg_parse_msg(md, ISAKMP_CFG_ACK, &isama_id, ca_list);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	if (stat != STF_OK)
	{
		return stat;
	}
	st->st_msgid = 0;
	return STF_OK;
}

/**
 * Used on the XAUTH server (responder)
 *   called in demux.c
 *   server -> CFG_REQUEST
 *   STF_OK transitions to STATE_XAUTH_R1
 */
stf_status xauth_send_request(struct state *st)
{
	stf_status stat;
	modecfg_attribute_t *ca;
	linked_list_t *ca_list = linked_list_create();

	ca = modecfg_attribute_create(XAUTH_USER_NAME, chunk_empty);
	ca_list->insert_last(ca_list, ca);
	ca = modecfg_attribute_create(XAUTH_USER_PASSWORD, chunk_empty);
	ca_list->insert_last(ca_list, ca);

	plog("sending XAUTH request");
	st->st_state = STATE_XAUTH_R1;
	stat = modecfg_send_msg(st, ISAKMP_CFG_REQUEST, ca_list);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	if (stat == STF_OK)
	{
		st->st_xauth.started = TRUE;
	}
	return stat;
}

/**
 * Used on the XAUTH client (initiator)
 *   called in demux.c from STATE_XAUTH_I0
 *   client <- CFG_REQUEST
 *   client -> CFG_REPLY
 *   STF_OK transitions to  STATE_XAUTH_I1
 */
stf_status xauth_inI0(struct msg_digest *md)
{
	struct state *const st = md->st;
	connection_t *c = st->st_connection;
	u_int16_t isama_id;
	stf_status stat, stat_build;
	modecfg_attribute_t *ca;
	bool xauth_user_name_present = FALSE;
	bool xauth_user_password_present = FALSE;
	bool xauth_type_present = FALSE;
	chunk_t xauth_user_name, xauth_user_password;
	identification_t *user_id;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing XAUTH request");

	stat = modecfg_parse_msg(md, ISAKMP_CFG_REQUEST, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		return stat;
	}

	while (ca_list->remove_last(ca_list, (void **)&ca) == SUCCESS)
	{
		switch (ca->type)
		{
			case XAUTH_TYPE:
				if (ca->value.len != XAUTH_TYPE_GENERIC)
				{
					plog("xauth type %s is not supported",
						  enum_name(&xauth_type_names, ca->value.len));
					stat = STF_FAIL;
				}
				else
				{
					xauth_type_present = TRUE;
				}
				break;
			case XAUTH_USER_NAME:
				xauth_user_name_present = TRUE;
				break;
			case XAUTH_USER_PASSWORD:
				xauth_user_password_present = TRUE;
				break;
			case XAUTH_MESSAGE:
				if (ca->value.len)
				{
					DBG(DBG_PARSING | DBG_CONTROLMORE,
						DBG_log("   '%.*s'", ca->value.len, ca->value.ptr)
					)
				}
				break;
			default:
				break;
		}
		modecfg_attribute_destroy(ca);
	}

	if (!xauth_user_name_present)
	{
		plog("user name attribute is missing in XAUTH request");
		stat = STF_FAIL;
	}
	if (!xauth_user_password_present)
	{
		plog("user password attribute is missing in XAUTH request");
		stat = STF_FAIL;
	}

	/* prepare XAUTH reply */
	if (stat == STF_OK)
	{
		/* get user credentials using a plugin function */
		if (!pluto->xauth->get_secret(pluto->xauth, c, &xauth_user_password))
		{
			plog("xauth user credentials not found");
			stat = STF_FAIL;
		}
	}
	if (stat == STF_OK)
	{
		/* insert xauth type if present */
		if (xauth_type_present)
		{
			ca = modecfg_attribute_create_tv(XAUTH_TYPE, XAUTH_TYPE_GENERIC);
			ca_list->insert_last(ca_list, ca);
		}

		/* insert xauth user name */
		user_id = (c->xauth_identity) ? c->xauth_identity : c->spd.this.id;
		xauth_user_name = user_id->get_encoding(user_id);
		DBG(DBG_CONTROL,
			DBG_log("my xauth user name is '%.*s'", xauth_user_name.len,
													xauth_user_name.ptr)
		)
		ca = modecfg_attribute_create(XAUTH_USER_NAME, xauth_user_name);
		ca_list->insert_last(ca_list, ca);

		/* insert xauth user password */
		DBG(DBG_PRIVATE,
			DBG_log("my xauth user password is '%.*s'",	xauth_user_password.len,
														xauth_user_password.ptr)
		)
		ca = modecfg_attribute_create(XAUTH_USER_PASSWORD, xauth_user_password);
		ca_list->insert_last(ca_list, ca);
		chunk_clear(&xauth_user_password);
	}
	else
	{
		ca = modecfg_attribute_create_tv(XAUTH_STATUS, XAUTH_STATUS_FAIL);
		ca_list->insert_last(ca_list, ca);
	}

	plog("sending XAUTH reply");
	stat_build = modecfg_build_msg(st, &md->rbody, ISAKMP_CFG_REPLY,
								   ca_list, isama_id);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	if (stat_build != STF_OK)
	{
		return stat_build;
	}
	if (stat == STF_OK)
	{
		st->st_xauth.started = TRUE;
		st->st_msgid = 0;
		return STF_OK;
	}
	else
	{
		/* send XAUTH reply msg and then delete ISAKMP SA */
		free(st->st_tpacket.ptr);
		st->st_tpacket = chunk_create(md->reply.start, pbs_offset(&md->reply));
		st->st_tpacket = chunk_clone(st->st_tpacket);
		send_packet(st, "XAUTH reply msg");
		delete_state(st);
		return STF_IGNORE;
	}
}

/**
 *  Used on the XAUTH server (responder)
 *    called in demux.c from STATE_XAUTH_R1
      server <- CFG_REPLY
      server -> CFG_SET
      STF_OK transitions to  STATE_XAUTH_R2
 */
stf_status xauth_inR1(struct msg_digest *md)
{
	struct state *const st = md->st;
	connection_t *c = st->st_connection;
	u_int16_t isama_id;
	stf_status stat, stat_build;
	chunk_t xauth_user_name, xauth_user_password;
	int xauth_status = XAUTH_STATUS_OK;
	modecfg_attribute_t *ca;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing XAUTH reply");

	stat = modecfg_parse_msg(md, ISAKMP_CFG_REPLY, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		return stat;
	}

	/* initialize xauth_secret */
	xauth_user_name = chunk_empty;
	xauth_user_password = chunk_empty;

	while (ca_list->remove_last(ca_list, (void **)&ca) == SUCCESS)
	{
		switch (ca->type)
		{
			case XAUTH_STATUS:
				xauth_status = ca->value.len;
				break;
			case XAUTH_USER_NAME:
				xauth_user_name = chunk_clone(ca->value);
				break;
			case XAUTH_USER_PASSWORD:
				xauth_user_password = chunk_clone(ca->value);
				break;
			default:
				break;
		}
		modecfg_attribute_destroy(ca);
	}
	/* did the client return an XAUTH FAIL status? */
	if (xauth_status == XAUTH_STATUS_FAIL)
	{
		plog("received FAIL status in XAUTH reply");

		/* client is not able to do XAUTH, delete ISAKMP SA */
		free(xauth_user_name.ptr);
		free(xauth_user_password.ptr);
		delete_state(st);
		ca_list->destroy(ca_list);
		return STF_IGNORE;
	}

	/* check XAUTH reply */
	if (xauth_user_name.ptr == NULL)
	{
		plog("user name attribute is missing in XAUTH reply");
		st->st_xauth.status = FALSE;
	}
	else if (xauth_user_password.ptr == NULL)
	{
		plog("user password attribute is missing in XAUTH reply");
		st->st_xauth.status = FALSE;
	}
	else
	{
		DBG(DBG_CONTROL,
			DBG_log("peer xauth user name is '%.*s'", xauth_user_name.len,
													  xauth_user_name.ptr)
		)
		DESTROY_IF(c->xauth_identity);
		c->xauth_identity = identification_create_from_data(xauth_user_name);		

		DBG(DBG_PRIVATE,
			DBG_log("peer xauth user password is '%.*s'", xauth_user_password.len,
														  xauth_user_password.ptr)
		)
		/* verify the user credentials using a plugin function */
		st->st_xauth.status = pluto->xauth->verify_secret(pluto->xauth, c,
														  xauth_user_password);
		plog("extended authentication %s", st->st_xauth.status? "was successful":"failed");
	}
	chunk_clear(&xauth_user_name);
	chunk_clear(&xauth_user_password);

	plog("sending XAUTH status");
	xauth_status = (st->st_xauth.status) ? XAUTH_STATUS_OK : XAUTH_STATUS_FAIL;
	ca = modecfg_attribute_create_tv(XAUTH_STATUS, xauth_status);
	ca_list->insert_last(ca_list, ca);
	stat_build = modecfg_send_msg(st, ISAKMP_CFG_SET, ca_list);
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
	if (stat_build != STF_OK)
	{
		return stat_build;
	}
	return STF_OK;
}

/**
 * Used on the XAUTH client (initiator)
 *   called in demux.c from STATE_XAUTH_I1
 *   client <- CFG_SET
 *   client -> CFG_ACK
 *   STF_OK transitions to  STATE_XAUTH_I2
 */
stf_status xauth_inI1(struct msg_digest *md)
{
	struct state *const st = md->st;
	u_int16_t isama_id;
	stf_status stat, stat_build;
	modecfg_attribute_t *ca;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing XAUTH status");
	stat = modecfg_parse_msg(md, ISAKMP_CFG_SET, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		/* notification payload - not exactly the right choice, but okay */
		md->note = ISAKMP_ATTRIBUTES_NOT_SUPPORTED;
		return stat;
	}

	st->st_xauth.status = FALSE;
	while (ca_list->remove_last(ca_list, (void **)&ca) == SUCCESS)
	{
		if (ca->type == XAUTH_STATUS)
		{
			st->st_xauth.status = (ca->value.len == XAUTH_STATUS_OK);
		}
		modecfg_attribute_destroy(ca);
	}
	plog("extended authentication %s", st->st_xauth.status? "was successful":"failed");

	plog("sending XAUTH ack");
	stat_build = modecfg_build_msg(st, &md->rbody, ISAKMP_CFG_ACK, ca_list, isama_id);
	ca_list->destroy(ca_list);

	if (stat_build != STF_OK)
	{
		return stat_build;
	}
	if (st->st_xauth.status)
	{
		st->st_msgid = 0;
		return STF_OK;
	}
	else
	{
		/* send XAUTH ack msg and then delete ISAKMP SA */
		free(st->st_tpacket.ptr);
		st->st_tpacket = chunk_create(md->reply.start, pbs_offset(&md->reply));
		st->st_tpacket = chunk_clone(st->st_tpacket);
		send_packet(st, "XAUTH ack msg");
		delete_state(st);
		return STF_IGNORE;
	}
}

/**
 * Used on the XAUTH server (responder)
 *   called in demux.c from STATE_XAUTH_R2
 *   server <- CFG_ACK
 *   STF_OK transitions to  STATE_XAUTH_R3
 */
stf_status xauth_inR2(struct msg_digest *md)
{
	struct state *const st = md->st;
	u_int16_t isama_id;
	stf_status stat;
	linked_list_t *ca_list = linked_list_create();

	plog("parsing XAUTH ack");

	stat = modecfg_parse_msg(md, ISAKMP_CFG_ACK, &isama_id, ca_list);
	if (stat != STF_OK)
	{
		return stat;
	}
	ca_list->destroy_function(ca_list, (void *)modecfg_attribute_destroy);
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
