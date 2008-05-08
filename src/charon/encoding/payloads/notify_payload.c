/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <stddef.h>

#include "notify_payload.h"

#include <daemon.h>
#include <encoding/payloads/encodings.h>
#include <crypto/hashers/hasher.h>

ENUM_BEGIN(notify_type_names, UNSUPPORTED_CRITICAL_PAYLOAD, UNSUPPORTED_CRITICAL_PAYLOAD,
	"UNSUPPORTED_CRITICAL_PAYLOAD");
ENUM_NEXT(notify_type_names, INVALID_IKE_SPI, INVALID_MAJOR_VERSION, UNSUPPORTED_CRITICAL_PAYLOAD,
	"INVALID_IKE_SPI",
	"INVALID_MAJOR_VERSION");
ENUM_NEXT(notify_type_names, INVALID_SYNTAX, INVALID_SYNTAX, INVALID_MAJOR_VERSION,
	"INVALID_SYNTAX");
ENUM_NEXT(notify_type_names, INVALID_MESSAGE_ID, INVALID_MESSAGE_ID, INVALID_SYNTAX,
	"INVALID_MESSAGE_ID");
ENUM_NEXT(notify_type_names, INVALID_SPI, INVALID_SPI, INVALID_MESSAGE_ID,
	"INVALID_SPI");
ENUM_NEXT(notify_type_names, NO_PROPOSAL_CHOSEN, NO_PROPOSAL_CHOSEN, INVALID_SPI,
	"NO_PROPOSAL_CHOSEN");
ENUM_NEXT(notify_type_names, INVALID_KE_PAYLOAD, INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN,
	"INVALID_KE_PAYLOAD");
ENUM_NEXT(notify_type_names, AUTHENTICATION_FAILED, AUTHENTICATION_FAILED, INVALID_KE_PAYLOAD,
	"AUTHENTICATION_FAILED");
ENUM_NEXT(notify_type_names, SINGLE_PAIR_REQUIRED, UNEXPECTED_NAT_DETECTED, AUTHENTICATION_FAILED,
	"SINGLE_PAIR_REQUIRED",
	"NO_ADDITIONAL_SAS",
	"INTERNAL_ADDRESS_FAILURE",
	"FAILED_CP_REQUIRED",
	"TS_UNACCEPTABLE",
	"INVALID_SELECTORS",
	"UNACCEPTABLE_ADDRESSES",
	"UNEXPECTED_NAT_DETECTED");
ENUM_NEXT(notify_type_names, ME_CONNECT_FAILED, ME_CONNECT_FAILED, UNEXPECTED_NAT_DETECTED,
	"ME_CONNECT_FAILED");
ENUM_NEXT(notify_type_names, INITIAL_CONTACT, AUTH_LIFETIME, ME_CONNECT_FAILED,
	"INITIAL_CONTACT",
	"SET_WINDOW_SIZE",
	"ADDITIONAL_TS_POSSIBLE",
	"IPCOMP_SUPPORTED",
	"NAT_DETECTION_SOURCE_IP",
	"NAT_DETECTION_DESTINATION_IP",
	"COOKIE",
	"USE_TRANSPORT_MODE",
	"HTTP_CERT_LOOKUP_SUPPORTED",
	"REKEY_SA",
	"ESP_TFC_PADDING_NOT_SUPPORTED",
	"NON_FIRST_FRAGMENTS_ALSO",
	"MOBIKE_SUPPORTED",
	"ADDITIONAL_IP4_ADDRESS",
	"ADDITIONAL_IP6_ADDRESS",
	"NO_ADDITIONAL_ADDRESSES",
	"UPDATE_SA_ADDRESSES",
	"COOKIE2",
	"NO_NATS_ALLOWED",
	"AUTH_LIFETIME");
ENUM_NEXT(notify_type_names, EAP_ONLY_AUTHENTICATION, EAP_ONLY_AUTHENTICATION, AUTH_LIFETIME,
	"EAP_ONLY_AUTHENTICATION");
ENUM_NEXT(notify_type_names, USE_BEET_MODE, USE_BEET_MODE, EAP_ONLY_AUTHENTICATION,
	"USE_BEET_MODE");
ENUM_NEXT(notify_type_names, ME_MEDIATION, ME_RESPONSE, USE_BEET_MODE,
	"ME_MEDIATION",
	"ME_ENDPOINT",
	"ME_CALLBACK",
	"ME_CONNECTID",
	"ME_CONNECTKEY",
	"ME_CONNECTAUTH",
	"ME_RESPONSE");
ENUM_END(notify_type_names, ME_RESPONSE);


ENUM_BEGIN(notify_type_short_names, UNSUPPORTED_CRITICAL_PAYLOAD, UNSUPPORTED_CRITICAL_PAYLOAD,
	"CRIT");
ENUM_NEXT(notify_type_short_names, INVALID_IKE_SPI, INVALID_MAJOR_VERSION, UNSUPPORTED_CRITICAL_PAYLOAD,
	"INVAL_IKE_SPI",
	"INVAL_MAJOR");
ENUM_NEXT(notify_type_short_names, INVALID_SYNTAX, INVALID_SYNTAX, INVALID_MAJOR_VERSION,
	"INVAL_SYN");
ENUM_NEXT(notify_type_short_names, INVALID_MESSAGE_ID, INVALID_MESSAGE_ID, INVALID_SYNTAX,
	"INVAL_MID");
ENUM_NEXT(notify_type_short_names, INVALID_SPI, INVALID_SPI, INVALID_MESSAGE_ID,
	"INVAL_SPI");
ENUM_NEXT(notify_type_short_names, NO_PROPOSAL_CHOSEN, NO_PROPOSAL_CHOSEN, INVALID_SPI,
	"NO_PROP");
ENUM_NEXT(notify_type_short_names, INVALID_KE_PAYLOAD, INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN,
	"INVAL_KE");
ENUM_NEXT(notify_type_short_names, AUTHENTICATION_FAILED, AUTHENTICATION_FAILED, INVALID_KE_PAYLOAD,
	"AUTH_FAILED");
ENUM_NEXT(notify_type_short_names, SINGLE_PAIR_REQUIRED, UNEXPECTED_NAT_DETECTED, AUTHENTICATION_FAILED,
	"SINGLE_PAIR",
	"NO_ADD_SAS",
	"INT_ADDR_FAIL",
	"FAIL_CP_REQ",
	"TS_UNACCEPT",
	"INVAL_SEL",
	"UNACCEPT_ADDR",
	"UNEXPECT_NAT");
ENUM_NEXT(notify_type_short_names, ME_CONNECT_FAILED, ME_CONNECT_FAILED, UNEXPECTED_NAT_DETECTED,
	"ME_CONN_FAIL");
ENUM_NEXT(notify_type_short_names, INITIAL_CONTACT, AUTH_LIFETIME, ME_CONNECT_FAILED,
	"INIT_CONTACT",
	"SET_WINSIZE",
	"ADD_TS_POSS",
	"IPCOMP_SUPP",
	"NATD_S_IP",
	"NATD_D_IP",
	"COOKIE",
	"USE_TRANSP",
	"HTTP_CERT_LOOK",
	"REKEY_SA",
	"ESP_TFC_PAD_N",
	"NON_FIRST_FRAG",
	"MOBIKE_SUP",
	"ADD_4_ADDR",
	"ADD_6_ADDR",
	"NO_ADD_ADDR",
	"UPD_SA_ADDR",
	"COOKIE2",
	"NO_NATS",
	"AUTH_LFT");
ENUM_NEXT(notify_type_short_names, EAP_ONLY_AUTHENTICATION, EAP_ONLY_AUTHENTICATION, AUTH_LIFETIME,
	"EAP_ONLY");
ENUM_NEXT(notify_type_short_names, USE_BEET_MODE, USE_BEET_MODE, EAP_ONLY_AUTHENTICATION,
	"BEET_MODE");
ENUM_NEXT(notify_type_short_names, ME_MEDIATION, ME_RESPONSE, USE_BEET_MODE,
	"ME_MED",
	"ME_EP",
	"ME_CB",
	"ME_CID",
	"ME_CKEY",
	"ME_CAUTH",
	"ME_R");
ENUM_END(notify_type_short_names, ME_RESPONSE);


typedef struct private_notify_payload_t private_notify_payload_t;

/**
 * Private data of an notify_payload_t object.
 * 
 */
struct private_notify_payload_t {
	/**
	 * Public notify_payload_t interface.
	 */
	notify_payload_t public;
	
	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;
		
	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;
		
	/**
	 * Protocol id.
	 */
	u_int8_t protocol_id;
	
	/**
	 * Spi size.
	 */
	u_int8_t spi_size;
	
	/**
	 * Notify message type.
	 */
	u_int16_t notify_type;
	
	/**
	 * Security parameter index (spi).
	 */
	chunk_t spi;

	/**
	 * Notification data.
	 */
	chunk_t notification_data;
};

/**
 * Encoding rules to parse or generate a IKEv2-Notify Payload.
 * 
 * The defined offsets are the positions in a object of type 
 * private_notify_payload_t.
 * 
 */
encoding_rule_t notify_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_notify_payload_t, next_payload) 		},
	/* the critical bit */
	{ FLAG,				offsetof(private_notify_payload_t, critical) 			},	
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_notify_payload_t, payload_length) 		},	
	/* Protocol ID as 8 bit field*/
	{ U_INT_8,			offsetof(private_notify_payload_t, protocol_id) 			},
	/* SPI Size as 8 bit field*/
	{ SPI_SIZE,			offsetof(private_notify_payload_t, spi_size) 			},
	/* Notify message type as 16 bit field*/
	{ U_INT_16,			offsetof(private_notify_payload_t, notify_type)	},
	/* SPI as variable length field*/
	{ SPI,				offsetof(private_notify_payload_t, spi)		 			},
	/* Key Exchange Data is from variable size */
	{ NOTIFICATION_DATA,	offsetof(private_notify_payload_t, notification_data) 	}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !  Protocol ID  !   SPI Size    !      Notify Message Type      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                Security Parameter Index (SPI)                 ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       Notification Data                       ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_notify_payload_t *this)
{
	bool bad_length = FALSE;

	switch (this->protocol_id)
	{
		case PROTO_NONE:
		case PROTO_IKE:
		case PROTO_AH:
		case PROTO_ESP:
			break;
		default:
			DBG1(DBG_ENC, "Unknown protocol (%d)", this->protocol_id);
			return FAILED;
	}
	
	switch (this->notify_type)
	{
		case INVALID_KE_PAYLOAD:
		{
			if (this->notification_data.len != 2)
			{
				bad_length = TRUE;
			}
			break;
		}
		case NAT_DETECTION_SOURCE_IP:
		case NAT_DETECTION_DESTINATION_IP:
		case ME_CONNECTAUTH:
		{
			if (this->notification_data.len != HASH_SIZE_SHA1)
			{
				bad_length = TRUE;
			}
			break;
		}
		case INVALID_SYNTAX:
		case INVALID_MAJOR_VERSION:
		case NO_PROPOSAL_CHOSEN:
		{
			if (this->notification_data.len != 0)
			{
				bad_length = TRUE;
			}
			break;
		}
		case ADDITIONAL_IP4_ADDRESS:
		{
			if (this->notification_data.len != 4)
			{
				bad_length = TRUE;
			}
			break;
		}
		case ADDITIONAL_IP6_ADDRESS:
		{
			if (this->notification_data.len != 16)
			{
				bad_length = TRUE;
			}
			break;
		}
		case AUTH_LIFETIME:
		{
			if (this->notification_data.len != 4)
			{
				bad_length = TRUE;
			}
			break;
		}
		case IPCOMP_SUPPORTED:
		{
			if (this->notification_data.len != 3)
			{
				bad_length = TRUE;
			}
			break;
		}
		case ME_ENDPOINT:
			if (this->notification_data.len != 8 &&
				this->notification_data.len != 12 &&
				this->notification_data.len != 24)
			{
				bad_length = TRUE;
			}
			break;
		case ME_CONNECTID:
			if (this->notification_data.len < 4 ||
				this->notification_data.len > 16)
			{
				bad_length = TRUE;
			}
			break;
		case ME_CONNECTKEY:
			if (this->notification_data.len < 16 ||
				this->notification_data.len > 32)
			{
				bad_length = TRUE;
			}
			break;
		default:
			/* TODO: verify */
			break;
	}
	if (bad_length)
	{
		DBG1(DBG_ENC, "invalid notify data length for %N (%d)",
			 notify_type_names, this->notify_type,
			 this->notification_data.len);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_notify_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = notify_payload_encodings;
	*rule_count = sizeof(notify_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_notify_payload_t *this)
{
	return NOTIFY;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_notify_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_notify_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * recompute the payloads length.
 */
static void compute_length (private_notify_payload_t *this)
{
	size_t length = NOTIFY_PAYLOAD_HEADER_LENGTH;
	if (this->notification_data.ptr != NULL)
	{
		length += this->notification_data.len;
	}
	if (this->spi.ptr != NULL)
	{
		length += this->spi.len;
	}
	this->payload_length = length;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_notify_payload_t *this)
{
	compute_length(this);
	return this->payload_length;
}

/**
 * Implementation of notify_payload_t.get_protocol_id.
 */
static u_int8_t get_protocol_id(private_notify_payload_t *this)
{
	return this->protocol_id;
}

/**
 * Implementation of notify_payload_t.set_protocol_id.
 */
static void set_protocol_id(private_notify_payload_t *this, u_int8_t protocol_id)
{
	this->protocol_id = protocol_id;
}

/**
 * Implementation of notify_payload_t.get_notify_type.
 */
static notify_type_t get_notify_type(private_notify_payload_t *this)
{
	return this->notify_type;
}

/**
 * Implementation of notify_payload_t.set_notify_type.
 */
static void set_notify_type(private_notify_payload_t *this, u_int16_t notify_type)
{
	this->notify_type = notify_type;
}

/**
 * Implementation of notify_payload_t.get_spi.
 */
static u_int32_t get_spi(private_notify_payload_t *this)
{
	switch (this->protocol_id)
	{
		case PROTO_AH:
		case PROTO_ESP:
			if (this->spi.len == 4)
			{
				return *((u_int32_t*)this->spi.ptr);
			}
		default:
			break;
	}
	return 0;
}

/**
 * Implementation of notify_payload_t.set_spi.
 */
static void set_spi(private_notify_payload_t *this, u_int32_t spi)
{
	chunk_free(&this->spi);
	switch (this->protocol_id)
	{
		case PROTO_AH:
		case PROTO_ESP:
			this->spi = chunk_alloc(4);
			*((u_int32_t*)this->spi.ptr) = spi;
			break;
		default:
			break;
	}
	this->spi_size = this->spi.len;
	compute_length(this);
}

/**
 * Implementation of notify_payload_t.get_notification_data.
 */
static chunk_t get_notification_data(private_notify_payload_t *this)
{
	return (this->notification_data);
}

/**
 * Implementation of notify_payload_t.set_notification_data.
 */
static status_t set_notification_data(private_notify_payload_t *this, chunk_t notification_data)
{
	chunk_free(&this->notification_data);
	if (notification_data.len > 0)
	{
		this->notification_data = chunk_clone(notification_data);
	}
	compute_length(this);
	return SUCCESS;
}

/**
 * Implementation of notify_payload_t.destroy and notify_payload_t.destroy.
 */
static status_t destroy(private_notify_payload_t *this)
{
	chunk_free(&this->notification_data);
	chunk_free(&this->spi);
	free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
notify_payload_t *notify_payload_create()
{
	private_notify_payload_t *this = malloc_thing(private_notify_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;

	/* public functions */
	this->public.get_protocol_id = (u_int8_t (*) (notify_payload_t *)) get_protocol_id;
	this->public.set_protocol_id  = (void (*) (notify_payload_t *,u_int8_t)) set_protocol_id;
	this->public.get_notify_type = (notify_type_t (*) (notify_payload_t *)) get_notify_type;
	this->public.set_notify_type = (void (*) (notify_payload_t *,notify_type_t)) set_notify_type;
	this->public.get_spi = (u_int32_t (*) (notify_payload_t *)) get_spi;
	this->public.set_spi = (void (*) (notify_payload_t *,u_int32_t)) set_spi;
	this->public.get_notification_data = (chunk_t (*) (notify_payload_t *)) get_notification_data;
	this->public.set_notification_data = (void (*) (notify_payload_t *,chunk_t)) set_notification_data;
	this->public.destroy = (void (*) (notify_payload_t *)) destroy;
	
	/* set default values of the fields */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = NOTIFY_PAYLOAD_HEADER_LENGTH;
	this->protocol_id = 0;
	this->notify_type = 0;
	this->spi.ptr = NULL;
	this->spi.len = 0;
	this->spi_size = 0;
	this->notification_data.ptr = NULL;
	this->notification_data.len = 0;
	
	return &this->public;
}

/*
 * Described in header.
 */
notify_payload_t *notify_payload_create_from_protocol_and_type(protocol_id_t protocol_id, notify_type_t notify_type)
{
	notify_payload_t *notify = notify_payload_create();

	notify->set_notify_type(notify,notify_type);
	notify->set_protocol_id(notify,protocol_id);
	
	return notify;
}
