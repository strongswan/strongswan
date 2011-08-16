/*
 * Copyright (C) 2006-2007 Tobias Brunner
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 * Copyright (C) 2006 Daniel Roethlisberger
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
 */

#include <stdlib.h>
#include <string.h>

#include "message.h"

#include <library.h>
#include <daemon.h>
#include <sa/ike_sa_id.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <utils/linked_list.h>
#include <encoding/payloads/encodings.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/encryption_payload.h>
#include <encoding/payloads/unknown_payload.h>
#include <encoding/payloads/cp_payload.h>

/**
 * Max number of notify payloads per IKEv2 Message
 */
#define MAX_NOTIFY_PAYLOADS 20

/**
 * Max number of delete payloads per IKEv2 Message
 */
#define MAX_DELETE_PAYLOADS 20

/**
 * Max number of certificate payloads per IKEv2 Message
 */
#define MAX_CERT_PAYLOADS 8

/**
 * Max number of Vendor ID payloads per IKEv2 Message
 */
#define MAX_VID_PAYLOADS 20

/**
 * A payload rule defines the rules for a payload
 * in a specific message rule. It defines if and how
 * many times a payload must/can occur in a message
 * and if it must be encrypted.
 */
typedef struct {
	/* Payload type */
	 payload_type_t type;
	/* Minimal occurrence of this payload. */
	size_t min_occurence;
	/* Max occurrence of this payload. */
	size_t max_occurence;
	/* TRUE if payload must be encrypted */
	bool encrypted;
	/* If payload occurs, the message rule is fulfilled */
	bool sufficient;
} payload_rule_t;

/**
 * payload ordering structure allows us to reorder payloads according to RFC.
 */
typedef struct {
	/** payload type */
	payload_type_t type;
	/** notify type, if payload == NOTIFY */
	notify_type_t notify;
} payload_order_t;

/**
 * A message rule defines the kind of a message,
 * if it has encrypted contents and a list
 * of payload ordering rules and payload parsing rules.
 */
typedef struct {
	/** Type of message. */
	exchange_type_t exchange_type;
	/** Is message a request or response. */
	bool is_request;
	/** Message contains encrypted payloads. */
	bool encrypted;
	/** Number of payload rules which will follow */
	int rule_count;
	/** Pointer to first payload rule */
	payload_rule_t *rules;
	/** Number of payload order rules */
	int order_count;
	/** payload ordering rules */
	payload_order_t *order;
} message_rule_t;

/**
 * Message rule for IKE_SA_INIT from initiator.
 */
static payload_rule_t ike_sa_init_i_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	FALSE,	FALSE},
	{SECURITY_ASSOCIATION,			1,	1,						FALSE,	FALSE},
	{KEY_EXCHANGE,					1,	1,						FALSE,	FALSE},
	{NONCE,							1,	1,						FALSE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		FALSE,	FALSE},
};

/**
 * payload order for IKE_SA_INIT initiator
 */
static payload_order_t ike_sa_init_i_order[] = {
/*	payload type					notify type */
	{NOTIFY,						COOKIE},
	{SECURITY_ASSOCIATION,			0},
	{KEY_EXCHANGE,					0},
	{NONCE,							0},
	{NOTIFY,						NAT_DETECTION_SOURCE_IP},
	{NOTIFY,						NAT_DETECTION_DESTINATION_IP},
	{NOTIFY,						0},
	{VENDOR_ID,						0},
};

/**
 * Message rule for IKE_SA_INIT from responder.
 */
static payload_rule_t ike_sa_init_r_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	FALSE,	TRUE},
	{SECURITY_ASSOCIATION,			1,	1,						FALSE,	FALSE},
	{KEY_EXCHANGE,					1,	1,						FALSE,	FALSE},
	{NONCE,							1,	1,						FALSE,	FALSE},
	{CERTIFICATE_REQUEST,			0,	1,						FALSE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		FALSE,	FALSE},
};

/**
 * payload order for IKE_SA_INIT responder
 */
static payload_order_t ike_sa_init_r_order[] = {
/*	payload type					notify type */
	{SECURITY_ASSOCIATION,			0},
	{KEY_EXCHANGE,					0},
	{NONCE,							0},
	{NOTIFY,						NAT_DETECTION_SOURCE_IP},
	{NOTIFY,						NAT_DETECTION_DESTINATION_IP},
	{NOTIFY,						HTTP_CERT_LOOKUP_SUPPORTED},
	{CERTIFICATE_REQUEST,			0},
	{NOTIFY,						0},
	{VENDOR_ID,						0},
};

/**
 * Message rule for IKE_AUTH from initiator.
 */
static payload_rule_t ike_auth_i_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	FALSE},
	{EXTENSIBLE_AUTHENTICATION,		0,	1,						TRUE,	TRUE},
	{AUTHENTICATION,				0,	1,						TRUE,	TRUE},
	{ID_INITIATOR,					0,	1,						TRUE,	FALSE},
	{CERTIFICATE,					0,	MAX_CERT_PAYLOADS,		TRUE,	FALSE},
	{CERTIFICATE_REQUEST,			0,	1,						TRUE,	FALSE},
	{ID_RESPONDER,					0,	1,						TRUE,	FALSE},
#ifdef ME
	{SECURITY_ASSOCIATION,			0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,	0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,	0,	1,						TRUE,	FALSE},
#else
	{SECURITY_ASSOCIATION,			0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,	0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,	0,	1,						TRUE,	FALSE},
#endif /* ME */
	{CONFIGURATION,					0,	1,						TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE},
};

/**
 * payload order for IKE_AUTH initiator
 */
static payload_order_t ike_auth_i_order[] = {
/*	payload type					notify type */
	{ID_INITIATOR,					0},
	{CERTIFICATE,					0},
	{NOTIFY,						INITIAL_CONTACT},
	{NOTIFY,						HTTP_CERT_LOOKUP_SUPPORTED},
	{CERTIFICATE_REQUEST,			0},
	{ID_RESPONDER,					0},
	{AUTHENTICATION,				0},
	{EXTENSIBLE_AUTHENTICATION,		0},
	{CONFIGURATION,					0},
	{NOTIFY,						IPCOMP_SUPPORTED},
	{NOTIFY,						USE_TRANSPORT_MODE},
	{NOTIFY,						ESP_TFC_PADDING_NOT_SUPPORTED},
	{NOTIFY,						NON_FIRST_FRAGMENTS_ALSO},
	{SECURITY_ASSOCIATION,			0},
	{TRAFFIC_SELECTOR_INITIATOR,	0},
	{TRAFFIC_SELECTOR_RESPONDER,	0},
	{NOTIFY,						MOBIKE_SUPPORTED},
	{NOTIFY,						ADDITIONAL_IP4_ADDRESS},
	{NOTIFY,						ADDITIONAL_IP6_ADDRESS},
	{NOTIFY,						NO_ADDITIONAL_ADDRESSES},
	{NOTIFY,						0},
	{VENDOR_ID,						0},
};

/**
 * Message rule for IKE_AUTH from responder.
 */
static payload_rule_t ike_auth_r_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	TRUE},
	{EXTENSIBLE_AUTHENTICATION,		0,	1,						TRUE,	TRUE},
	{AUTHENTICATION,				0,	1,						TRUE,	TRUE},
	{CERTIFICATE,					0,	MAX_CERT_PAYLOADS,		TRUE,	FALSE},
	{ID_RESPONDER,					0,	1,						TRUE,	FALSE},
	{SECURITY_ASSOCIATION,			0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,	0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,	0,	1,						TRUE,	FALSE},
	{CONFIGURATION,					0,	1,						TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE},
};

/**
 * payload order for IKE_AUTH responder
 */
static payload_order_t ike_auth_r_order[] = {
/*	payload type					notify type */
	{ID_RESPONDER,					0},
	{CERTIFICATE,					0},
	{AUTHENTICATION,				0},
	{EXTENSIBLE_AUTHENTICATION,		0},
	{CONFIGURATION,					0},
	{NOTIFY,						IPCOMP_SUPPORTED},
	{NOTIFY,						USE_TRANSPORT_MODE},
	{NOTIFY,						ESP_TFC_PADDING_NOT_SUPPORTED},
	{NOTIFY,						NON_FIRST_FRAGMENTS_ALSO},
	{SECURITY_ASSOCIATION,			0},
	{TRAFFIC_SELECTOR_INITIATOR,	0},
	{TRAFFIC_SELECTOR_RESPONDER,	0},
	{NOTIFY,						AUTH_LIFETIME},
	{NOTIFY,						MOBIKE_SUPPORTED},
	{NOTIFY,						ADDITIONAL_IP4_ADDRESS},
	{NOTIFY,						ADDITIONAL_IP6_ADDRESS},
	{NOTIFY,						NO_ADDITIONAL_ADDRESSES},
	{NOTIFY,						0},
	{VENDOR_ID,						0},
};

/**
 * Message rule for INFORMATIONAL from initiator.
 */
static payload_rule_t informational_i_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	FALSE},
	{CONFIGURATION,					0,	1,						TRUE,	FALSE},
	{DELETE,						0,	MAX_DELETE_PAYLOADS,	TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE},
};

/**
 * payload order for INFORMATIONAL initiator
 */
static payload_order_t informational_i_order[] = {
/*	payload type					notify type */
	{NOTIFY,						UPDATE_SA_ADDRESSES},
	{NOTIFY,						NAT_DETECTION_SOURCE_IP},
	{NOTIFY,						NAT_DETECTION_DESTINATION_IP},
	{NOTIFY,						COOKIE2},
	{NOTIFY,						0},
	{DELETE,						0},
	{CONFIGURATION,					0},
};

/**
 * Message rule for INFORMATIONAL from responder.
 */
static payload_rule_t informational_r_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	FALSE},
	{CONFIGURATION,					0,	1,						TRUE,	FALSE},
	{DELETE,						0,	MAX_DELETE_PAYLOADS,	TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE},
};

/**
 * payload order for INFORMATIONAL responder
 */
static payload_order_t informational_r_order[] = {
/*	payload type					notify type */
	{NOTIFY,						UPDATE_SA_ADDRESSES},
	{NOTIFY,						NAT_DETECTION_SOURCE_IP},
	{NOTIFY,						NAT_DETECTION_DESTINATION_IP},
	{NOTIFY,						COOKIE2},
	{NOTIFY,						0},
	{DELETE,						0},
	{CONFIGURATION,					0},
};

/**
 * Message rule for CREATE_CHILD_SA from initiator.
 */
static payload_rule_t create_child_sa_i_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	FALSE},
	{SECURITY_ASSOCIATION,			1,	1,						TRUE,	FALSE},
	{NONCE,							1,	1,						TRUE,	FALSE},
	{KEY_EXCHANGE,					0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,	0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,	0,	1,						TRUE,	FALSE},
	{CONFIGURATION,					0,	1,						TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE},
};

/**
 * payload order for CREATE_CHILD_SA from initiator.
 */
static payload_order_t create_child_sa_i_order[] = {
/*	payload type					notify type */
	{NOTIFY,						REKEY_SA},
	{NOTIFY,						IPCOMP_SUPPORTED},
	{NOTIFY,						USE_TRANSPORT_MODE},
	{NOTIFY,						ESP_TFC_PADDING_NOT_SUPPORTED},
	{NOTIFY,						NON_FIRST_FRAGMENTS_ALSO},
	{SECURITY_ASSOCIATION,			0},
	{NONCE,							0},
	{KEY_EXCHANGE,					0},
	{TRAFFIC_SELECTOR_INITIATOR,	0},
	{TRAFFIC_SELECTOR_RESPONDER,	0},
	{NOTIFY,						0},
};

/**
 * Message rule for CREATE_CHILD_SA from responder.
 */
static payload_rule_t create_child_sa_r_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	TRUE},
	{SECURITY_ASSOCIATION,			1,	1,						TRUE,	FALSE},
	{NONCE,							1,	1,						TRUE,	FALSE},
	{KEY_EXCHANGE,					0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_INITIATOR,	0,	1,						TRUE,	FALSE},
	{TRAFFIC_SELECTOR_RESPONDER,	0,	1,						TRUE,	FALSE},
	{CONFIGURATION,					0,	1,						TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE},
};

/**
 * payload order for CREATE_CHILD_SA from responder.
 */
static payload_order_t create_child_sa_r_order[] = {
/*	payload type					notify type */
	{NOTIFY,						IPCOMP_SUPPORTED},
	{NOTIFY,						USE_TRANSPORT_MODE},
	{NOTIFY,						ESP_TFC_PADDING_NOT_SUPPORTED},
	{NOTIFY,						NON_FIRST_FRAGMENTS_ALSO},
	{SECURITY_ASSOCIATION,			0},
	{NONCE,							0},
	{KEY_EXCHANGE,					0},
	{TRAFFIC_SELECTOR_INITIATOR,	0},
	{TRAFFIC_SELECTOR_RESPONDER,	0},
	{NOTIFY,						ADDITIONAL_TS_POSSIBLE},
	{NOTIFY,						0},
};

#ifdef ME
/**
 * Message rule for ME_CONNECT from initiator.
 */
static payload_rule_t me_connect_i_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	TRUE},
	{ID_PEER,						1,	1,						TRUE,	FALSE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE}
};

/**
 * payload order for ME_CONNECT from initiator.
 */
static payload_order_t me_connect_i_order[] = {
/*	payload type					notify type */
	{NOTIFY,						0},
	{ID_PEER,						0},
	{VENDOR_ID,						0},
};

/**
 * Message rule for ME_CONNECT from responder.
 */
static payload_rule_t me_connect_r_rules[] = {
/*	payload type					min	max						encr	suff */
	{NOTIFY,						0,	MAX_NOTIFY_PAYLOADS,	TRUE,	TRUE},
	{VENDOR_ID,						0,	MAX_VID_PAYLOADS,		TRUE,	FALSE}
};

/**
 * payload order for ME_CONNECT from responder.
 */
static payload_order_t me_connect_r_order[] = {
/*	payload type					notify type */
	{NOTIFY,						0},
	{VENDOR_ID,						0},
};
#endif /* ME */

/**
 * Message rules, defines allowed payloads.
 */
static message_rule_t message_rules[] = {
	{IKE_SA_INIT,		TRUE,	FALSE,
		countof(ike_sa_init_i_rules), ike_sa_init_i_rules,
		countof(ike_sa_init_i_order), ike_sa_init_i_order,
	},
	{IKE_SA_INIT,		FALSE,	FALSE,
		countof(ike_sa_init_r_rules), ike_sa_init_r_rules,
		countof(ike_sa_init_r_order), ike_sa_init_r_order,
	},
	{IKE_AUTH,			TRUE,	TRUE,
		countof(ike_auth_i_rules), ike_auth_i_rules,
		countof(ike_auth_i_order), ike_auth_i_order,
	},
	{IKE_AUTH,			FALSE,	TRUE,
		countof(ike_auth_r_rules), ike_auth_r_rules,
		countof(ike_auth_r_order), ike_auth_r_order,
	},
	{INFORMATIONAL,		TRUE,	TRUE,
		countof(informational_i_rules), informational_i_rules,
		countof(informational_i_order), informational_i_order,
	},
	{INFORMATIONAL,		FALSE,	TRUE,
		countof(informational_r_rules), informational_r_rules,
		countof(informational_r_order), informational_r_order,
	},
	{CREATE_CHILD_SA,	TRUE,	TRUE,
		countof(create_child_sa_i_rules), create_child_sa_i_rules,
		countof(create_child_sa_i_order), create_child_sa_i_order,
	},
	{CREATE_CHILD_SA,	FALSE,	TRUE,
		countof(create_child_sa_r_rules), create_child_sa_r_rules,
		countof(create_child_sa_r_order), create_child_sa_r_order,
	},
#ifdef ME
	{ME_CONNECT,		TRUE,	TRUE,
		countof(me_connect_i_rules), me_connect_i_rules,
		countof(me_connect_i_order), me_connect_i_order,
	},
	{ME_CONNECT,		FALSE,	TRUE,
		countof(me_connect_r_rules), me_connect_r_rules,
		countof(me_connect_r_order), me_connect_r_order,
	},
#endif /* ME */
};


typedef struct private_message_t private_message_t;

/**
 * Private data of an message_t object.
 */
struct private_message_t {

	/**
	 * Public part of a message_t object.
	 */
	message_t public;

	/**
	 * Minor version of message.
	 */
	u_int8_t major_version;

	/**
	 * Major version of message.
	 */
	u_int8_t minor_version;

	/**
	 * First Payload in message.
	 */
	payload_type_t first_payload;

	/**
	 * Assigned exchange type.
	 */
	exchange_type_t exchange_type;

	/**
	 * TRUE if message is a request, FALSE if a reply.
	 */
	bool is_request;

	/**
	 * Higher version supported?
	 */
	bool version_flag;

	/**
	 * Reserved bits in IKE header
	 */
	bool reserved[5];

	/**
	 * Sorting of message disabled?
	 */
	bool sort_disabled;

	/**
	 * Message ID of this message.
	 */
	u_int32_t message_id;

	/**
	 * ID of assigned IKE_SA.
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * Assigned UDP packet, stores incoming packet or last generated one.
	 */
	packet_t *packet;

	/**
	 * Linked List where payload data are stored in.
	 */
	linked_list_t *payloads;

	 /**
	  * Assigned parser to parse Header and Body of this message.
	  */
	parser_t *parser;

	/**
	 * The message rule for this message instance
	 */
	message_rule_t *rule;
};

/**
 * Get the message rule that applies to this message
 */
static message_rule_t* get_message_rule(private_message_t *this)
{
	int i;

	for (i = 0; i < countof(message_rules); i++)
	{
		if ((this->exchange_type == message_rules[i].exchange_type) &&
			(this->is_request == message_rules[i].is_request))
		{
			return &message_rules[i];
		}
	}
	return NULL;
}

/**
 * Look up a payload rule
 */
static payload_rule_t* get_payload_rule(private_message_t *this,
										payload_type_t type)
{
	int i;

	for (i = 0; i < this->rule->rule_count;i++)
	{
		if (this->rule->rules[i].type == type)
		{
			return &this->rule->rules[i];
		}
	}
	return NULL;
}

METHOD(message_t, set_ike_sa_id, void,
	private_message_t *this,ike_sa_id_t *ike_sa_id)
{
	DESTROY_IF(this->ike_sa_id);
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
}

METHOD(message_t, get_ike_sa_id, ike_sa_id_t*,
	private_message_t *this)
{
	return this->ike_sa_id;
}

METHOD(message_t, set_message_id, void,
	private_message_t *this,u_int32_t message_id)
{
	this->message_id = message_id;
}

METHOD(message_t, get_message_id, u_int32_t,
	private_message_t *this)
{
	return this->message_id;
}

METHOD(message_t, get_initiator_spi, u_int64_t,
	private_message_t *this)
{
	return (this->ike_sa_id->get_initiator_spi(this->ike_sa_id));
}

METHOD(message_t, get_responder_spi, u_int64_t,
	private_message_t *this)
{
	return (this->ike_sa_id->get_responder_spi(this->ike_sa_id));
}

METHOD(message_t, set_major_version, void,
	private_message_t *this, u_int8_t major_version)
{
	this->major_version = major_version;
}

METHOD(message_t, get_major_version, u_int8_t,
	private_message_t *this)
{
	return this->major_version;
}

METHOD(message_t, set_minor_version, void,
	private_message_t *this,u_int8_t minor_version)
{
	this->minor_version = minor_version;
}

METHOD(message_t, get_minor_version, u_int8_t,
	private_message_t *this)
{
	return this->minor_version;
}

METHOD(message_t, set_exchange_type, void,
	private_message_t *this, exchange_type_t exchange_type)
{
	this->exchange_type = exchange_type;
}

METHOD(message_t, get_exchange_type, exchange_type_t,
	private_message_t *this)
{
	return this->exchange_type;
}

METHOD(message_t, get_first_payload_type, payload_type_t,
	private_message_t *this)
{
	return this->first_payload;
}

METHOD(message_t, set_request, void,
	private_message_t *this, bool request)
{
	this->is_request = request;
}

METHOD(message_t, get_request, bool,
	private_message_t *this)
{
	return this->is_request;
}

METHOD(message_t, set_version_flag, void,
	private_message_t *this)
{
	this->version_flag = TRUE;
}

METHOD(message_t, get_reserved_header_bit, bool,
	private_message_t *this, u_int nr)
{
	if (nr < countof(this->reserved))
	{
		return this->reserved[nr];
	}
	return FALSE;
}

METHOD(message_t, set_reserved_header_bit, void,
	private_message_t *this, u_int nr)
{
	if (nr < countof(this->reserved))
	{
		this->reserved[nr] = TRUE;
	}
}

METHOD(message_t, is_encoded, bool,
	private_message_t *this)
{
	return this->packet->get_data(this->packet).ptr != NULL;
}

METHOD(message_t, add_payload, void,
	private_message_t *this, payload_t *payload)
{
	payload_t *last_payload;

	if (this->payloads->get_count(this->payloads) > 0)
	{
		this->payloads->get_last(this->payloads, (void **)&last_payload);
		last_payload->set_next_type(last_payload, payload->get_type(payload));
	}
	else
	{
		this->first_payload = payload->get_type(payload);
	}
	payload->set_next_type(payload, NO_PAYLOAD);
	this->payloads->insert_last(this->payloads, payload);

	DBG2(DBG_ENC ,"added payload of type %N to message",
		 payload_type_names, payload->get_type(payload));
}

METHOD(message_t, add_notify, void,
	private_message_t *this, bool flush, notify_type_t type, chunk_t data)
{
	notify_payload_t *notify;
	payload_t *payload;

	if (flush)
	{
		while (this->payloads->remove_last(this->payloads,
												(void**)&payload) == SUCCESS)
		{
			payload->destroy(payload);
		}
	}
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	notify->set_notification_data(notify, data);
	add_payload(this, (payload_t*)notify);
}

METHOD(message_t, set_source, void,
	private_message_t *this, host_t *host)
{
	this->packet->set_source(this->packet, host);
}

METHOD(message_t, set_destination, void,
	private_message_t *this, host_t *host)
{
	this->packet->set_destination(this->packet, host);
}

METHOD(message_t, get_source, host_t*,
	private_message_t *this)
{
	return this->packet->get_source(this->packet);
}

METHOD(message_t, get_destination, host_t*,
	private_message_t *this)
{
	return this->packet->get_destination(this->packet);
}

METHOD(message_t, create_payload_enumerator, enumerator_t*,
	private_message_t *this)
{
	return this->payloads->create_enumerator(this->payloads);
}

METHOD(message_t, remove_payload_at, void,
	private_message_t *this, enumerator_t *enumerator)
{
	this->payloads->remove_at(this->payloads, enumerator);
}

METHOD(message_t, get_payload, payload_t*,
	private_message_t *this, payload_type_t type)
{
	payload_t *current, *found = NULL;
	enumerator_t *enumerator;

	enumerator = create_payload_enumerator(this);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->get_type(current) == type)
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(message_t, get_notify, notify_payload_t*,
	private_message_t *this, notify_type_t type)
{
	enumerator_t *enumerator;
	notify_payload_t *notify = NULL;
	payload_t *payload;

	enumerator = create_payload_enumerator(this);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify = (notify_payload_t*)payload;
			if (notify->get_notify_type(notify) == type)
			{
				break;
			}
			notify = NULL;
		}
	}
	enumerator->destroy(enumerator);
	return notify;
}

/**
 * get a string representation of the message
 */
static char* get_string(private_message_t *this, char *buf, int len)
{
	enumerator_t *enumerator;
	payload_t *payload;
	int written;
	char *pos = buf;

	memset(buf, 0, len);
	len--;

	written = snprintf(pos, len, "%N %s %d [",
					   exchange_type_names, this->exchange_type,
					   this->is_request ? "request" : "response",
					   this->message_id);
	if (written >= len || written < 0)
	{
		return "";
	}
	pos += written;
	len -= written;

	enumerator = create_payload_enumerator(this);
	while (enumerator->enumerate(enumerator, &payload))
	{
		written = snprintf(pos, len, " %N", payload_type_short_names,
						   payload->get_type(payload));
		if (written >= len || written < 0)
		{
			return buf;
		}
		pos += written;
		len -= written;
		if (payload->get_type(payload) == NOTIFY)
		{
			notify_payload_t *notify;
			notify_type_t type;
			chunk_t data;

			notify = (notify_payload_t*)payload;
			type = notify->get_notify_type(notify);
			data = notify->get_notification_data(notify);
			if (type == MS_NOTIFY_STATUS && data.len == 4)
			{
				written = snprintf(pos, len, "(%N(%d))", notify_type_short_names,
								   type, untoh32(data.ptr));
			}
			else
			{
				written = snprintf(pos, len, "(%N)", notify_type_short_names,
								   type);
			}
			if (written >= len || written < 0)
			{
				return buf;
			}
			pos += written;
			len -= written;
		}
		if (payload->get_type(payload) == EXTENSIBLE_AUTHENTICATION)
		{
			eap_payload_t *eap = (eap_payload_t*)payload;
			u_int32_t vendor;
			eap_type_t type;
			char method[64] = "";

			type = eap->get_type(eap, &vendor);
			if (type)
			{
				if (vendor)
				{
					snprintf(method, sizeof(method), "/%d-%d", type, vendor);
				}
				else
				{
					snprintf(method, sizeof(method), "/%N",
							 eap_type_short_names, type);
				}
			}
			written = snprintf(pos, len, "/%N%s", eap_code_short_names,
							   eap->get_code(eap), method);
			if (written >= len || written < 0)
			{
				return buf;
			}
			pos += written;
			len -= written;
		}
		if (payload->get_type(payload) == CONFIGURATION)
		{
			cp_payload_t *cp = (cp_payload_t*)payload;
			enumerator_t *attributes;
			configuration_attribute_t *attribute;
			bool first = TRUE;

			attributes = cp->create_attribute_enumerator(cp);
			while (attributes->enumerate(attributes, &attribute))
			{
				written = snprintf(pos, len, "%s%N", first ? "(" : " ",
								   configuration_attribute_type_short_names,
								   attribute->get_type(attribute));
				if (written >= len || written < 0)
				{
					return buf;
				}
				pos += written;
				len -= written;
				first = FALSE;
			}
			attributes->destroy(attributes);
			if (!first)
			{
				written = snprintf(pos, len, ")");
				if (written >= len || written < 0)
				{
					return buf;
				}
				pos += written;
				len -= written;
			}
		}
	}
	enumerator->destroy(enumerator);

	/* remove last space */
	snprintf(pos, len, " ]");
	return buf;
}

/**
 * reorder payloads depending on reordering rules
 */
static void order_payloads(private_message_t *this)
{
	linked_list_t *list;
	payload_t *payload;
	int i;

	/* move to temp list */
	list = linked_list_create();
	while (this->payloads->remove_last(this->payloads,
									   (void**)&payload) == SUCCESS)
	{
		list->insert_first(list, payload);
	}
	/* for each rule, ... */
	for (i = 0; i < this->rule->order_count; i++)
	{
		enumerator_t *enumerator;
		notify_payload_t *notify;
		payload_order_t order;

		order = this->rule->order[i];

		/* ... find all payload ... */
		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &payload))
		{
			/* ... with that type ... */
			if (payload->get_type(payload) == order.type)
			{
				notify = (notify_payload_t*)payload;

				/**... and check notify for type. */
				if (order.type != NOTIFY || order.notify == 0 ||
					order.notify == notify->get_notify_type(notify))
				{
					list->remove_at(list, enumerator);
					add_payload(this, payload);
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	/* append all payloads without a rule to the end */
	while (list->remove_last(list, (void**)&payload) == SUCCESS)
	{
		/* do not complain about payloads in private use space */
		if (payload->get_type(payload) < 128)
		{
			DBG1(DBG_ENC, "payload %N has no ordering rule in %N %s",
				 payload_type_names, payload->get_type(payload),
				 exchange_type_names, this->rule->exchange_type,
				 this->rule->is_request ? "request" : "response");
		}
		add_payload(this, payload);
	}
	list->destroy(list);
}

/**
 * Wrap payloads in a encryption payload
 */
static encryption_payload_t* wrap_payloads(private_message_t *this)
{
	encryption_payload_t *encryption;
	linked_list_t *payloads;
	payload_t *current;

	/* copy all payloads in a temporary list */
	payloads = linked_list_create();
	while (this->payloads->remove_first(this->payloads,
										(void**)&current) == SUCCESS)
	{
		payloads->insert_last(payloads, current);
	}

	encryption = encryption_payload_create();
	while (payloads->remove_first(payloads, (void**)&current) == SUCCESS)
	{
		payload_rule_t *rule;
		payload_type_t type;
		bool encrypt = TRUE;

		type = current->get_type(current);
		rule = get_payload_rule(this, type);
		if (rule)
		{
			encrypt = rule->encrypted;
		}
		if (encrypt)
		{
			DBG2(DBG_ENC, "insert payload %N to encryption payload",
				 payload_type_names, type);
			encryption->add_payload(encryption, current);
		}
		else
		{
			DBG2(DBG_ENC, "insert payload %N unencrypted",
				 payload_type_names, type);
			add_payload(this, current);
		}
	}
	payloads->destroy(payloads);

	return encryption;
}

METHOD(message_t, disable_sort, void,
	private_message_t *this)
{
	this->sort_disabled = TRUE;
}

METHOD(message_t, generate, status_t,
	private_message_t *this, aead_t *aead, packet_t **packet)
{
	generator_t *generator;
	ike_header_t *ike_header;
	payload_t *payload, *next;
	encryption_payload_t *encryption = NULL;
	enumerator_t *enumerator;
	chunk_t chunk;
	char str[BUF_LEN];
	u_int32_t *lenpos;
	bool *reserved;
	int i;

	if (this->exchange_type == EXCHANGE_TYPE_UNDEFINED)
	{
		DBG1(DBG_ENC, "exchange type is not defined");
		return INVALID_STATE;
	}

	if (this->packet->get_source(this->packet) == NULL ||
		this->packet->get_destination(this->packet) == NULL)
	{
		DBG1(DBG_ENC, "source/destination not defined");
		return INVALID_STATE;
	}

	this->rule = get_message_rule(this);
	if (!this->rule)
	{
		DBG1(DBG_ENC, "no message rules specified for this message type");
		return NOT_SUPPORTED;
	}

	if (!this->sort_disabled)
	{
		order_payloads(this);
	}

	DBG1(DBG_ENC, "generating %s", get_string(this, str, sizeof(str)));

	if (aead && this->rule->encrypted)
	{
		encryption = wrap_payloads(this);
	}
	else
	{
		DBG2(DBG_ENC, "not encrypting payloads");
	}

	ike_header = ike_header_create();
	ike_header->set_maj_version(ike_header, this->major_version);
	ike_header->set_min_version(ike_header, this->minor_version);
	ike_header->set_exchange_type(ike_header, this->exchange_type);
	ike_header->set_message_id(ike_header, this->message_id);
	ike_header->set_response_flag(ike_header, !this->is_request);
	ike_header->set_version_flag(ike_header, this->version_flag);
	ike_header->set_initiator_flag(ike_header,
						this->ike_sa_id->is_initiator(this->ike_sa_id));
	ike_header->set_initiator_spi(ike_header,
						this->ike_sa_id->get_initiator_spi(this->ike_sa_id));
	ike_header->set_responder_spi(ike_header,
						this->ike_sa_id->get_responder_spi(this->ike_sa_id));

	for (i = 0; i < countof(this->reserved); i++)
	{
		reserved = payload_get_field(&ike_header->payload_interface,
									 RESERVED_BIT, i);
		if (reserved)
		{
			*reserved = this->reserved[i];
		}
	}

	generator = generator_create();

	/* generate all payloads with proper next type */
	payload = (payload_t*)ike_header;
	enumerator = create_payload_enumerator(this);
	while (enumerator->enumerate(enumerator, &next))
	{
		payload->set_next_type(payload, next->get_type(next));
		generator->generate_payload(generator, payload);
		payload = next;
	}
	enumerator->destroy(enumerator);
	payload->set_next_type(payload, encryption ? ENCRYPTED : NO_PAYLOAD);
	generator->generate_payload(generator, payload);
	ike_header->destroy(ike_header);

	if (encryption)
	{
		u_int32_t *lenpos;

		/* build associated data (without header of encryption payload) */
		chunk = generator->get_chunk(generator, &lenpos);
		encryption->set_transform(encryption, aead);
		/* fill in length, including encryption payload */
		htoun32(lenpos, chunk.len + encryption->get_length(encryption));

		this->payloads->insert_last(this->payloads, encryption);
		if (!encryption->encrypt(encryption, chunk))
		{
			generator->destroy(generator);
			return INVALID_STATE;
		}
		generator->generate_payload(generator, &encryption->payload_interface);
	}
	chunk = generator->get_chunk(generator, &lenpos);
	htoun32(lenpos, chunk.len);
	this->packet->set_data(this->packet, chunk_clone(chunk));
	generator->destroy(generator);

	*packet = this->packet->clone(this->packet);
	return SUCCESS;
}

METHOD(message_t, get_packet, packet_t*,
	private_message_t *this)
{
	if (this->packet == NULL)
	{
		return NULL;
	}
	return this->packet->clone(this->packet);
}

METHOD(message_t, get_packet_data, chunk_t,
	private_message_t *this)
{
	if (this->packet == NULL)
	{
		return chunk_empty;
	}
	return chunk_clone(this->packet->get_data(this->packet));
}

METHOD(message_t, parse_header, status_t,
	private_message_t *this)
{
	ike_header_t *ike_header;
	status_t status;
	bool *reserved;
	int i;

	DBG2(DBG_ENC, "parsing header of message");

	this->parser->reset_context(this->parser);
	status = this->parser->parse_payload(this->parser, HEADER,
										 (payload_t**)&ike_header);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "header could not be parsed");
		return status;

	}

	status = ike_header->payload_interface.verify(
										&ike_header->payload_interface);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "header verification failed");
		ike_header->destroy(ike_header);
		return status;
	}

	DESTROY_IF(this->ike_sa_id);
	this->ike_sa_id = ike_sa_id_create(ike_header->get_initiator_spi(ike_header),
									ike_header->get_responder_spi(ike_header),
									ike_header->get_initiator_flag(ike_header));

	this->exchange_type = ike_header->get_exchange_type(ike_header);
	this->message_id = ike_header->get_message_id(ike_header);
	this->is_request = !ike_header->get_response_flag(ike_header);
	this->major_version = ike_header->get_maj_version(ike_header);
	this->minor_version = ike_header->get_min_version(ike_header);
	this->first_payload = ike_header->payload_interface.get_next_type(
												&ike_header->payload_interface);
	for (i = 0; i < countof(this->reserved); i++)
	{
		reserved = payload_get_field(&ike_header->payload_interface,
									 RESERVED_BIT, i);
		if (reserved)
		{
			this->reserved[i] = *reserved;
		}
	}
	DBG2(DBG_ENC, "parsed a %N %s", exchange_type_names, this->exchange_type,
		 this->is_request ? "request" : "response");

	ike_header->destroy(ike_header);

	this->rule = get_message_rule(this);
	if (!this->rule)
	{
		DBG1(DBG_ENC, "no message rules specified for a %N %s",
			 exchange_type_names, this->exchange_type,
			 this->is_request ? "request" : "response");
	}
	return status;
}

/**
 * Check if a payload is for a mediation extension connectivity check
 */
static bool is_connectivity_check(private_message_t *this, payload_t *payload)
{
#ifdef ME
	if (this->exchange_type == INFORMATIONAL &&
		payload->get_type(payload) == NOTIFY)
	{
		notify_payload_t *notify = (notify_payload_t*)payload;

		switch (notify->get_notify_type(notify))
		{
			case ME_CONNECTID:
			case ME_ENDPOINT:
			case ME_CONNECTAUTH:
				return TRUE;
			default:
				break;
		}
	}
#endif /* !ME */
	return FALSE;
}

/**
 * Decrypt payload from the encryption payload
 */
static status_t decrypt_payloads(private_message_t *this, aead_t *aead)
{
	bool was_encrypted = FALSE;
	payload_t *payload, *previous = NULL;
	enumerator_t *enumerator;
	payload_rule_t *rule;
	payload_type_t type;
	status_t status = SUCCESS;

	enumerator = this->payloads->create_enumerator(this->payloads);
	while (enumerator->enumerate(enumerator, &payload))
	{
		type = payload->get_type(payload);

		DBG2(DBG_ENC, "process payload of type %N", payload_type_names, type);

		if (type == ENCRYPTED)
		{
			encryption_payload_t *encryption;
			payload_t *encrypted;
			chunk_t chunk;

			encryption = (encryption_payload_t*)payload;

			DBG2(DBG_ENC, "found an encryption payload");

			if (this->payloads->has_more(this->payloads, enumerator))
			{
				DBG1(DBG_ENC, "encrypted payload is not last payload");
				status = VERIFY_ERROR;
				break;
			}
			encryption->set_transform(encryption, aead);
			chunk = this->packet->get_data(this->packet);
			if (chunk.len < encryption->get_length(encryption))
			{
				DBG1(DBG_ENC, "invalid payload length");
				status = VERIFY_ERROR;
				break;
			}
			chunk.len -= encryption->get_length(encryption);
			status = encryption->decrypt(encryption, chunk);
			if (status != SUCCESS)
			{
				break;
			}

			was_encrypted = TRUE;
			this->payloads->remove_at(this->payloads, enumerator);

			while ((encrypted = encryption->remove_payload(encryption)))
			{
				type = encrypted->get_type(encrypted);
				if (previous)
				{
					previous->set_next_type(previous, type);
				}
				else
				{
					this->first_payload = type;
				}
				DBG2(DBG_ENC, "insert decrypted payload of type "
					 "%N at end of list", payload_type_names, type);
				this->payloads->insert_last(this->payloads, encrypted);
				previous = encrypted;
			}
			encryption->destroy(encryption);
		}
		if (payload_is_known(type) && !was_encrypted &&
			!is_connectivity_check(this, payload))
		{
			rule = get_payload_rule(this, type);
			if (!rule || rule->encrypted)
			{
				DBG1(DBG_ENC, "payload type %N was not encrypted",
					 payload_type_names, type);
				status = FAILED;
				break;
			}
		}
		previous = payload;
	}
	enumerator->destroy(enumerator);
	return status;
}

/**
 * Verify a message and all payload according to message/payload rules
 */
static status_t verify(private_message_t *this)
{
	bool complete = FALSE;
	int i;

	DBG2(DBG_ENC, "verifying message structure");

	/* check for payloads with wrong count*/
	for (i = 0; i < this->rule->rule_count; i++)
	{
		enumerator_t *enumerator;
		payload_t *payload;
		payload_rule_t *rule;
		int found = 0;

		rule = &this->rule->rules[i];
		enumerator = create_payload_enumerator(this);
		while (enumerator->enumerate(enumerator, &payload))
		{
			payload_type_t type;

			type = payload->get_type(payload);
			if (type == rule->type)
			{
				found++;
				DBG2(DBG_ENC, "found payload of type %N",
					 payload_type_names, type);
				if (found > rule->max_occurence)
				{
					DBG1(DBG_ENC, "payload of type %N more than %d times (%d) "
						 "occurred in current message", payload_type_names,
						 type, rule->max_occurence, found);
					enumerator->destroy(enumerator);
					return VERIFY_ERROR;
				}
			}
		}
		enumerator->destroy(enumerator);

		if (!complete && found < rule->min_occurence)
		{
			DBG1(DBG_ENC, "payload of type %N not occurred %d times (%d)",
				 payload_type_names, rule->type, rule->min_occurence, found);
			return VERIFY_ERROR;
		}
		if (found && rule->sufficient)
		{
			complete = TRUE;
		}
	}
	return SUCCESS;
}

METHOD(message_t, parse_body, status_t,
	private_message_t *this, aead_t *aead)
{
	status_t status = SUCCESS;
	payload_t *payload;
	payload_type_t type;
	char str[BUF_LEN];

	type = this->first_payload;

	DBG2(DBG_ENC, "parsing body of message, first payload is %N",
		 payload_type_names, type);

	while (type != NO_PAYLOAD)
	{
		DBG2(DBG_ENC, "starting parsing a %N payload",
			 payload_type_names, type);

		status = this->parser->parse_payload(this->parser, type, &payload);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "payload type %N could not be parsed",
				 payload_type_names, type);
			return this->exchange_type == IKE_SA_INIT ? PARSE_ERROR : FAILED;
		}

		DBG2(DBG_ENC, "verifying payload of type %N", payload_type_names, type);
		status = payload->verify(payload);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "%N payload verification failed",
				 payload_type_names, type);
			payload->destroy(payload);
			return this->exchange_type == IKE_SA_INIT ? VERIFY_ERROR : FAILED;
		}

		DBG2(DBG_ENC, "%N payload verified. Adding to payload list",
			 payload_type_names, type);
		this->payloads->insert_last(this->payloads, payload);

		/* an encryption payload is the last one, so STOP here. decryption is
		 * done later */
		if (type == ENCRYPTED)
		{
			DBG2(DBG_ENC, "%N payload found. Stop parsing",
				 payload_type_names, type);
			break;
		}
		type = payload->get_next_type(payload);
	}

	status = decrypt_payloads(this, aead);
	if (status != SUCCESS)
	{
		DBG1(DBG_ENC, "could not decrypt payloads");
		return status;
	}

	status = verify(this);
	if (status != SUCCESS)
	{
		return status;
	}

	DBG1(DBG_ENC, "parsed %s", get_string(this, str, sizeof(str)));

	return SUCCESS;
}

METHOD(message_t, destroy, void,
	private_message_t *this)
{
	DESTROY_IF(this->ike_sa_id);
	this->payloads->destroy_offset(this->payloads, offsetof(payload_t, destroy));
	this->packet->destroy(this->packet);
	this->parser->destroy(this->parser);
	free(this);
}

/*
 * Described in Header-File
 */
message_t *message_create_from_packet(packet_t *packet)
{
	private_message_t *this;

	INIT(this,
		.public = {
			.set_major_version = _set_major_version,
			.get_major_version = _get_major_version,
			.set_minor_version = _set_minor_version,
			.get_minor_version = _get_minor_version,
			.set_message_id = _set_message_id,
			.get_message_id = _get_message_id,
			.get_initiator_spi = _get_initiator_spi,
			.get_responder_spi = _get_responder_spi,
			.set_ike_sa_id = _set_ike_sa_id,
			.get_ike_sa_id = _get_ike_sa_id,
			.set_exchange_type = _set_exchange_type,
			.get_exchange_type = _get_exchange_type,
			.get_first_payload_type = _get_first_payload_type,
			.set_request = _set_request,
			.get_request = _get_request,
			.set_version_flag = _set_version_flag,
			.get_reserved_header_bit = _get_reserved_header_bit,
			.set_reserved_header_bit = _set_reserved_header_bit,
			.add_payload = _add_payload,
			.add_notify = _add_notify,
			.disable_sort = _disable_sort,
			.generate = _generate,
			.is_encoded = _is_encoded,
			.set_source = _set_source,
			.get_source = _get_source,
			.set_destination = _set_destination,
			.get_destination = _get_destination,
			.create_payload_enumerator = _create_payload_enumerator,
			.remove_payload_at = _remove_payload_at,
			.get_payload = _get_payload,
			.get_notify = _get_notify,
			.parse_header = _parse_header,
			.parse_body = _parse_body,
			.get_packet = _get_packet,
			.get_packet_data = _get_packet_data,
			.destroy = _destroy,
		},
		.major_version = IKE_MAJOR_VERSION,
		.minor_version = IKE_MINOR_VERSION,
		.exchange_type = EXCHANGE_TYPE_UNDEFINED,
		.is_request = TRUE,
		.first_payload = NO_PAYLOAD,
		.packet = packet,
		.payloads = linked_list_create(),
		.parser = parser_create(packet->get_data(packet)),
	);

	return (&this->public);
}

/*
 * Described in Header.
 */
message_t *message_create()
{
	return message_create_from_packet(packet_create());
}

