/*
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * $Id$
 */

#include "radius_message.h"

#include <daemon.h>
#include <crypto/hashers/hasher.h>

typedef struct private_radius_message_t private_radius_message_t;
typedef struct rmsg_t rmsg_t;
typedef struct rattr_t rattr_t;

/**
 * RADIUS message header
 */
struct rmsg_t {
	/** message code, radius_message_code_t */
	u_int8_t code;
	/** message identifier */
	u_int8_t identifier;
	/** length of Code, Identifier, Length, Authenticator and Attributes */
	u_int16_t length;
	/** message authenticator, MD5 hash */
	u_int8_t authenticator[HASH_SIZE_MD5];
	/** variable list of packed attributes */
	u_int8_t attributes[];
} __attribute__((packed));

/**
 * RADIUS message attribute.
 */
struct rattr_t {
	/** attribute type, radius_attribute_type_t */
	u_int8_t type;
	/** length of the attriubte, including the Type, Length and Value fields */
	u_int8_t length;
	/** variable length attribute value */
	u_int8_t value[];
} __attribute__((packed));

/**
 * Private data of an radius_message_t object.
 */
struct private_radius_message_t {
	
	/**
	 * Public radius_message_t interface.
	 */
	radius_message_t public;
	
	/**
	 * message data, allocated
	 */
	rmsg_t *msg;
};

ENUM_BEGIN(radius_message_code_names, RMC_ACCESS_REQUEST, RMC_ACCOUNTING_RESPONSE,
	"Access-Request",
	"Access-Accept",
	"Access-Reject",
	"Accounting-Request",
	"Accounting-Response");
ENUM_NEXT(radius_message_code_names, RMC_ACCESS_CHALLENGE, RMC_ACCESS_CHALLENGE, RMC_ACCOUNTING_RESPONSE,
	"Access-Challenge");
ENUM_END(radius_message_code_names, RMC_ACCESS_CHALLENGE);

ENUM(radius_attribute_type_names, RAT_USER_NAME, RAT_MIP6_HOME_LINK_PREFIX,
	"User-Name",
	"User-Password",
	"CHAP-Password",
	"NAS-IP-Address",
	"NAS-Port",
	"Service-Type",
	"Framed-Protocol",
	"Framed-IP-Address",
	"Framed-IP-Netmask",
	"Framed-Routing",
	"Filter-Id",
	"Framed-MTU",
	"Framed-Compression",
	"Login-IP-Host",
	"Login-Service",
	"Login-TCP-Port",
	"Unassigned",
	"Reply-Message",
	"Callback-Number",
	"Callback-Id",
	"Unassigned",
	"Framed-Route",
	"Framed-IPX-Network",
	"State",
	"Class",
	"Vendor-Specific",
	"Session-Timeout",
	"Idle-Timeout",
	"Termination-Action",
	"Called-Station-Id",
	"Calling-Station-Id",
	"NAS-Identifier",
	"Proxy-State",
	"Login-LAT-Service",
	"Login-LAT-Node",
	"Login-LAT-Group",
	"Framed-AppleTalk-Link",
	"Framed-AppleTalk-Network",
	"Framed-AppleTalk-Zone",
	"Acct-Status-Type",
	"Acct-Delay-Time",
	"Acct-Input-Octets",
	"Acct-Output-Octets",
	"Acct-Session-Id",
	"Acct-Authentic",
	"Acct-Session-Time",
	"Acct-Input-Packets",
	"Acct-Output-Packets",
	"Acct-Terminate-Cause",
	"Acct-Multi-Session-Id",
	"Acct-Link-Count",
	"Acct-Input-Gigawords",
	"Acct-Output-Gigawords",
	"Unassigned",
	"Event-Timestamp",
	"Egress-VLANID",
	"Ingress-Filters",
	"Egress-VLAN-Name",
	"User-Priority-Table",
	"CHAP-Challenge",
	"NAS-Port-Type",
	"Port-Limit",
	"Login-LAT-Port",
	"Tunnel-Type",
	"Tunnel-Medium-Type",
	"Tunnel-Client-Endpoint",
	"Tunnel-Server-Endpoint",
	"Acct-Tunnel-Connection",
	"Tunnel-Password",
	"ARAP-Password",
	"ARAP-Features",
	"ARAP-Zone-Access",
	"ARAP-Security",
	"ARAP-Security-Data",
	"Password-Retry",
	"Prompt",
	"Connect-Info",
	"Configuration-Token",
	"EAP-Message",
	"Message-Authenticator",
	"Tunnel-Private-Group-ID",
	"Tunnel-Assignment-ID",
	"Tunnel-Preference",
	"ARAP-Challenge-Response",
	"Acct-Interim-Interval",
	"Acct-Tunnel-Packets-Lost",
	"NAS-Port-Id",
	"Framed-Pool",
	"CUI",
	"Tunnel-Client-Auth-ID",
	"Tunnel-Server-Auth-ID",
	"NAS-Filter-Rule",
	"Unassigned",
	"Originating-Line-Info",
	"NAS-IPv6-Address",
	"Framed-Interface-Id",
	"Framed-IPv6-Prefix",
	"Login-IPv6-Host",
	"Framed-IPv6-Route",
	"Framed-IPv6-Pool",
	"Error-Cause",
	"EAP-Key-Name",
	"Digest-Response",
	"Digest-Realm",
	"Digest-Nonce",
	"Digest-Response-Auth",
	"Digest-Nextnonce",
	"Digest-Method",
	"Digest-URI",
	"Digest-Qop",
	"Digest-Algorithm",
	"Digest-Entity-Body-Hash",
	"Digest-CNonce",
	"Digest-Nonce-Count",
	"Digest-Username",
	"Digest-Opaque",
	"Digest-Auth-Param",
	"Digest-AKA-Auts",
	"Digest-Domain",
	"Digest-Stale",
	"Digest-HA1",
	"SIP-AOR",
	"Delegated-IPv6-Prefix",
	"MIP6-Feature-Vector",
	"MIP6-Home-Link-Prefix");

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator interface */
	enumerator_t public;
	/** currently pointing attribute */
	rattr_t *next;
	/** bytes left */
	int left;
} attribute_enumerator_t;


/**
 * Implementation of attribute_enumerator_t.enumerate
 */
static bool attribute_enumerate(attribute_enumerator_t *this,
								int *type, chunk_t *data)

{
	if (this->left == 0)
	{
		return FALSE;
	}
	if (this->left < sizeof(rattr_t) ||
		this->left < this->next->length)
	{
		DBG1(DBG_IKE, "RADIUS message truncated");
		return FALSE;
	}
	*type = this->next->type;
	data->ptr = this->next->value;
	data->len = this->next->length - sizeof(rattr_t);
	this->left -= this->next->length;
	this->next = ((void*)this->next) + this->next->length;
	return TRUE;
}

/**
 * Implementation of radius_message_t.create_enumerator
 */
static enumerator_t* create_enumerator(private_radius_message_t *this)
{
	attribute_enumerator_t *e;
	
	if (ntohs(this->msg->length) < sizeof(rmsg_t) + sizeof(rattr_t))
	{
		return enumerator_create_empty();
	}
	
	e = malloc_thing(attribute_enumerator_t);
	e->public.enumerate = (void*)attribute_enumerate;
	e->public.destroy = (void*)free;
	e->next = (rattr_t*)this->msg->attributes;
	e->left = ntohs(this->msg->length) - sizeof(rmsg_t);
	return &e->public;
}

/**
 * Implementation of radius_message_t.add
 */
static void add(private_radius_message_t *this, radius_attribute_type_t type,
				chunk_t data)
{
	rattr_t *attribute;
	
	this->msg = realloc(this->msg,
						ntohs(this->msg->length) + sizeof(rattr_t) + data.len);
	attribute = ((void*)this->msg) + ntohs(this->msg->length);
	attribute->type = type;
	attribute->length = data.len + sizeof(rattr_t);
	memcpy(attribute->value, data.ptr, data.len);
	this->msg->length = htons(ntohs(this->msg->length) + attribute->length);
}

/**
 * Implementation of radius_message_t.sign
 */
static void sign(private_radius_message_t *this, rng_t *rng, signer_t *signer)
{
	char buf[HASH_SIZE_MD5];
	
	/* build Request-Authenticator */
	rng->get_bytes(rng, HASH_SIZE_MD5, this->msg->authenticator);
	
	/* build Message-Authenticator attribute, using 16 null bytes */
	memset(buf, 0, sizeof(buf));
	add(this, RAT_MESSAGE_AUTHENTICATOR, chunk_create(buf, sizeof(buf)));
	signer->get_signature(signer,
				chunk_create((u_char*)this->msg, ntohs(this->msg->length)),
				((u_char*)this->msg) + ntohs(this->msg->length) - HASH_SIZE_MD5);
}

/**
 * Implementation of radius_message_t.verify
 */
static bool verify(private_radius_message_t *this, u_int8_t *req_auth,
				   chunk_t secret, hasher_t *hasher, signer_t *signer)
{
	char buf[HASH_SIZE_MD5], res_auth[HASH_SIZE_MD5];
	enumerator_t *enumerator;
	int type;
	chunk_t data, msg;
	
	/* replace Response by Request Authenticator for verification */
	memcpy(res_auth, this->msg->authenticator, HASH_SIZE_MD5);
	memcpy(this->msg->authenticator, req_auth, HASH_SIZE_MD5);
	msg = chunk_create((u_char*)this->msg, ntohs(this->msg->length));
	
	/* verify Response-Authenticator */
	hasher->get_hash(hasher, msg, NULL);
	hasher->get_hash(hasher, secret, buf);
	if (!memeq(buf, res_auth, HASH_SIZE_MD5))
	{
		DBG1(DBG_CFG, "RADIUS Response-Authenticator verification failed");
		return FALSE;
	}
	
	/* verify Message-Authenticator attribute */
	enumerator = create_enumerator(this);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_MESSAGE_AUTHENTICATOR)
		{
			if (data.len != HASH_SIZE_MD5)
			{
				DBG1(DBG_CFG, "RADIUS Message-Authenticator invalid length");
				enumerator->destroy(enumerator);
				return FALSE;
			}
			memcpy(buf, data.ptr, data.len);
			memset(data.ptr, 0, data.len);
			if (signer->verify_signature(signer, msg,
										 chunk_create(buf, sizeof(buf))))
			{	/* good, restore Authenticators */
				memcpy(this->msg->authenticator, res_auth, HASH_SIZE_MD5);
				memcpy(data.ptr, buf, data.len);
				enumerator->destroy(enumerator);
				return TRUE;
			}
			else
			{
				DBG1(DBG_CFG, "RADIUS Message-Authenticator verification failed");
				enumerator->destroy(enumerator);
				return FALSE;
			}
		}
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_CFG, "RADIUS Message-Authenticator attribute missing");
	return FALSE;
}

/**
 * Implementation of radius_message_t.get_code
 */
static radius_message_code_t get_code(private_radius_message_t *this)
{
	return this->msg->code;
}

/**
 * Implementation of radius_message_t.get_identifier
 */
static u_int8_t get_identifier(private_radius_message_t *this)
{
	return this->msg->identifier;
}

/**
 * Implementation of radius_message_t.set_identifier
 */
static void set_identifier(private_radius_message_t *this, u_int8_t identifier)
{
	this->msg->identifier = identifier;
}

/**
 * Implementation of radius_message_t.get_authenticator
 */
static u_int8_t* get_authenticator(private_radius_message_t *this)
{
	return this->msg->authenticator;
}


/**
 * Implementation of radius_message_t.get_encoding
 */
static chunk_t get_encoding(private_radius_message_t *this)
{
	return chunk_create((u_char*)this->msg, ntohs(this->msg->length));
}

/**
 * Implementation of radius_message_t.destroy.
 */
static void destroy(private_radius_message_t *this)
{
	free(this->msg);
	free(this);
}

/**
 * Generic constructor
 */
static private_radius_message_t *radius_message_create()
{
	private_radius_message_t *this = malloc_thing(private_radius_message_t);
	
	this->public.create_enumerator = (enumerator_t*(*)(radius_message_t*))create_enumerator;
	this->public.add = (void(*)(radius_message_t*, radius_attribute_type_t,chunk_t))add;
	this->public.get_code = (radius_message_code_t(*)(radius_message_t*))get_code;
	this->public.get_identifier = (u_int8_t(*)(radius_message_t*))get_identifier;
	this->public.set_identifier = (void(*)(radius_message_t*, u_int8_t identifier))set_identifier;
	this->public.get_authenticator = (u_int8_t*(*)(radius_message_t*))get_authenticator;
	this->public.get_encoding = (chunk_t(*)(radius_message_t*))get_encoding;
	this->public.sign = (void(*)(radius_message_t*, rng_t *rng, signer_t *signer))sign;
	this->public.verify = (bool(*)(radius_message_t*, u_int8_t *req_auth, chunk_t secret, hasher_t *hasher, signer_t *signer))verify;
	this->public.destroy = (void(*)(radius_message_t*))destroy;
	
	return this;
}

/**
 * See header
 */
radius_message_t *radius_message_create_request()
{
	private_radius_message_t *this = radius_message_create();
	
	this->msg = malloc_thing(rmsg_t);
	this->msg->code = RMC_ACCESS_REQUEST;
	this->msg->identifier = 0;
	this->msg->length = htons(sizeof(rmsg_t));
	
	return &this->public;
}

/**
 * See header
 */
radius_message_t *radius_message_parse_response(chunk_t data)
{
	private_radius_message_t *this = radius_message_create();
	
	this->msg = malloc(data.len);
	memcpy(this->msg, data.ptr, data.len);
	if (data.len < sizeof(rmsg_t) ||
		ntohs(this->msg->length) != data.len)
	{
		DBG1(DBG_IKE, "RADIUS message has invalid length");
		destroy(this);
		return NULL;
	}
	return &this->public;
}

