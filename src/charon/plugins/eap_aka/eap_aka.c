/*
 * Copyright (C) 2006-2009 Martin Willi
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


/* The EAP-AKA method uses it's own simple parser for processing EAP-AKA
 * payloads, as the IKEv2 parser is not suitable for that job. There are
 * two simple methods for parsing payloads, read_header() and read_attribute().
 * Every EAP-AKA payload consists of a header and a list of attributes. Those
 * functions mentioned read the data and return the type of the found
 * attribute/EAP-AKA-type. For generating a EAP-AKA message, we have a
 * build_aka_payload(), which builds the whole message from a variable
 * argument list containing its attributes.
 * The processing of messages is split up in various functions:
 * - peer_process() - General processing multiplexer for the peer
 *   - peer_process_challenge() - Specific AKA-Challenge processor
 *   - peer_process_notification() - Processing of AKA-Notification
 * - server_process() - General processing multiplexer for the server
 *   - peer_process_challenge() - Processing of a received Challenge response
 *   - peer_process_synchronize() - Process a sequence number synchronization
 * - server_initiate() - Initiation method for the server, calls
 *   - server_initiate_challenge() - Initiation of AKA-Challenge
 */

#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>

#include "eap_aka.h"

#include <daemon.h>
#include <library.h>
#include <crypto/hashers/hasher.h>

#define MK_LEN		20
#define MSK_LEN		64
#define KAUTH_LEN	16
#define KENCR_LEN	16
#define AT_MAC_LEN	16

typedef enum aka_subtype_t aka_subtype_t;
typedef enum aka_attribute_t aka_attribute_t;

/**
 * Subtypes of AKA messages
 */
enum aka_subtype_t {
	AKA_CHALLENGE = 1,
	AKA_AUTHENTICATION_REJECT = 2,
	AKA_SYNCHRONIZATION_FAILURE = 4,
	AKA_IDENTITY = 5,
	AKA_NOTIFICATION = 12,
	AKA_REAUTHENTICATION = 13,
	AKA_CLIENT_ERROR = 14,
};

/**
 * Attribute types in AKA messages
 */
enum aka_attribute_t {
	/** defines the end of attribute list */
	AT_END = -1,
	AT_RAND = 1,
	AT_AUTN = 2,
	AT_RES = 3,
	AT_AUTS = 4,
	AT_PADDING = 6,
	AT_NONCE_MT = 7,
	AT_PERMANENT_ID_REQ = 10,
	AT_MAC = 11,
	AT_NOTIFICATION = 12,
	AT_ANY_ID_REQ = 13,
	AT_IDENTITY = 14,
	AT_VERSION_LIST = 15,
	AT_SELECTED_VERSION = 16,
	AT_FULLAUTH_ID_REQ = 17,
	AT_COUNTER = 19,
	AT_COUNTER_TOO_SMALL = 20,
	AT_NONCE_S = 21,
	AT_CLIENT_ERROR_CODE = 22,
	AT_IV = 129,
	AT_ENCR_DATA = 130,
	AT_NEXT_PSEUDONYM = 132,
	AT_NEXT_REAUTH_ID = 133,
	AT_CHECKCODE = 134,
	AT_RESULT_IND = 135,
};

ENUM_BEGIN(aka_subtype_names, AKA_CHALLENGE, AKA_IDENTITY,
	"AKA_CHALLENGE",
	"AKA_AUTHENTICATION_REJECT",
	"AKA_3",
	"AKA_SYNCHRONIZATION_FAILURE",
	"AKA_IDENTITY");
ENUM_NEXT(aka_subtype_names, AKA_NOTIFICATION, AKA_CLIENT_ERROR, AKA_IDENTITY,
	"AKA_NOTIFICATION",
	"AKA_REAUTHENTICATION",
	"AKA_CLIENT_ERROR");
ENUM_END(aka_subtype_names, AKA_CLIENT_ERROR);


ENUM_BEGIN(aka_attribute_names, AT_END, AT_CLIENT_ERROR_CODE,
	"AT_END",
	"AT_0",
	"AT_RAND",
	"AT_AUTN",
	"AT_RES",
	"AT_AUTS",
	"AT_5",
	"AT_PADDING",
	"AT_NONCE_MT",
	"AT_8",
	"AT_9",
	"AT_PERMANENT_ID_REQ",
	"AT_MAC",
	"AT_NOTIFICATION",
	"AT_ANY_ID_REQ",
	"AT_IDENTITY",
	"AT_VERSION_LIST",
	"AT_SELECTED_VERSION",
	"AT_FULLAUTH_ID_REQ",
	"AT_18",
	"AT_COUNTER",
	"AT_COUNTER_TOO_SMALL",
	"AT_NONCE_S",
	"AT_CLIENT_ERROR_CODE");
ENUM_NEXT(aka_attribute_names, AT_IV, AT_RESULT_IND, AT_CLIENT_ERROR_CODE,
	"AT_IV",
	"AT_ENCR_DATA",
	"AT_131",
	"AT_NEXT_PSEUDONYM",
	"AT_NEXT_REAUTH_ID",
	"AT_CHECKCODE",
	"AT_RESULT_IND");
ENUM_END(aka_attribute_names, AT_RESULT_IND);


typedef struct private_eap_aka_t private_eap_aka_t;
typedef struct eap_aka_header_t eap_aka_header_t;
typedef struct aka_attribute_header_t aka_attribute_header_t;

/**
 * Private data of an eap_aka_t object.
 */
struct private_eap_aka_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_aka_t public;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * SHA11 hasher
	 */
	hasher_t *sha1;

	/**
	 * MAC function used in EAP-AKA
	 */
	signer_t *signer;

	/**
	 * pseudo random function used in EAP-AKA
	 */
	prf_t *prf;

	/**
	 * MSK
	 */
	char msk[MSK_LEN];

	/**
	 * Has the MSK been calculated?
	 */
	bool derived;

	/**
	 * (Expected) Result (X)RES
	 */
	char res[AKA_RES_LEN];

	/**
	 * random value RAND (used by server only)
	 */
	char rand[AKA_RAND_LEN];
};

/**
 * packed EAP AKA header struct
 */
struct eap_aka_header_t {
	/** EAP code (REQUEST/RESPONSE) */
	u_int8_t code;
	/** unique message identifier */
	u_int8_t identifier;
	/** length of whole message */
	u_int16_t length;
	/** EAP type => EAP_AKA */
	u_int8_t type;
	/** AKA subtype */
	u_int8_t subtype;
	/** reserved bytes */
	u_int16_t reserved;
} __attribute__((__packed__));

/**
 * packed EAP AKA attribute header struct
 */
struct aka_attribute_header_t {
	/** attribute type */
	u_int8_t type;
	/** attibute length */
	u_int8_t length;
} __attribute__((__packed__));

/** AT_CLIENT_ERROR_CODE AKA attribute */
static chunk_t client_error_code = chunk_from_chars(0, 0);

/**
 * derive the keys needed for EAP_AKA
 */
static void derive_keys(private_eap_aka_t *this, identification_t *id,
						chunk_t ck, chunk_t ik)
{
	char mk[MK_LEN];
	chunk_t tmp, k_auth, identity;

	/* MK = SHA1( Identity | IK | CK ) */
	identity = id->get_encoding(id);
	DBG3(DBG_IKE, "Identity %B", &identity);
	this->sha1->get_hash(this->sha1, identity, NULL);
	this->sha1->get_hash(this->sha1, ik, NULL);
	this->sha1->get_hash(this->sha1, ck, mk);
	DBG3(DBG_IKE, "MK %b", mk, MK_LEN);

	/* K_encr | K_auth | MSK | EMSK = prf(0) | prf(0)
	 * FIPS PRF has 320 bit block size, we need 160 byte for keys
	 *  => run prf four times */
	this->prf->set_key(this->prf, chunk_create(mk, MK_LEN));
	tmp = chunk_alloca(this->prf->get_block_size(this->prf) * 4);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 4 * 1);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 4 * 2);
	this->prf->get_bytes(this->prf, chunk_empty, tmp.ptr + tmp.len / 4 * 3);

	/* skip K_encr, not required */
	tmp = chunk_skip(tmp, KENCR_LEN);
	k_auth = chunk_create(tmp.ptr, KAUTH_LEN);
	tmp = chunk_skip(tmp, KAUTH_LEN);
	memcpy(this->msk, tmp.ptr, MSK_LEN);
	/* ignore EMSK, not required */

	this->signer->set_key(this->signer, k_auth);

	DBG3(DBG_IKE, "PRF res %B", &tmp);
	DBG3(DBG_IKE, "K_auth %B", &k_auth);
	DBG3(DBG_IKE, "MSK %b", this->msk, MSK_LEN);

	this->derived = TRUE;
}

/**
 * skip EAP_AKA header in message and returns its AKA subtype
 */
static aka_subtype_t read_header(chunk_t *message)
{
	aka_subtype_t type;

	if (message->len < 8)
	{
		*message = chunk_empty;
		return 0;
	}
	type = *(message->ptr + 5);
	*message = chunk_skip(*message, 8);
	return type;
}

/**
 * read the next attribute from the message data
 */
static aka_attribute_t read_attribute(chunk_t *message, chunk_t *data)
{
	aka_attribute_t attribute;
	size_t length;

	DBG3(DBG_IKE, "reading attribute from %B", message);

	if (message->len < 2)
	{
		return AT_END;
	}
	attribute = message->ptr[0];
	length = message->ptr[1] * 4 - 2;
	*message = chunk_skip(*message, 2);
	DBG3(DBG_IKE, "found attribute %N with length %d",
		 aka_attribute_names, attribute, length);

	if (length > message->len)
	{
		return AT_END;
	}
	data->len = length;
	data->ptr = message->ptr;
	*message = chunk_skip(*message, length);
	return attribute;
}

/**
 * Build an AKA payload from different attributes.
 * The variable argument takes an aka_attribute_t
 * followed by its data in a chunk.
 */
static eap_payload_t *build_aka_payload(private_eap_aka_t *this, eap_code_t code,
									u_int8_t identifier, aka_subtype_t type, ...)
{
	chunk_t pos, data, message;
	eap_payload_t *payload;
	va_list args;
	u_int8_t *mac_pos = NULL;
	u_int16_t len;
	eap_aka_header_t *hdr;
	aka_attribute_t attr;
	aka_attribute_header_t *ahdr;

	pos = message = chunk_alloca(512);

	hdr = (eap_aka_header_t*)message.ptr;
	hdr->code = code;
	hdr->identifier = identifier;
	hdr->length = 0;
	hdr->type = EAP_AKA;
	hdr->subtype = type;
	hdr->reserved = 0;

	pos = chunk_skip(pos, sizeof(eap_aka_header_t));

	va_start(args, type);
	while ((attr = va_arg(args, aka_attribute_t)) != AT_END)
	{
		data = va_arg(args, chunk_t);

		DBG3(DBG_IKE, "building %N %B", aka_attribute_names, attr, &data);

		ahdr = (aka_attribute_header_t*)pos.ptr;
		ahdr->type = attr;
		pos = chunk_skip(pos, sizeof(aka_attribute_header_t));

		switch (attr)
		{
			case AT_RES:
			{
				ahdr->length = data.len / 4 + 1;
				/* RES length in bits */
				len = htons(data.len * 8);
				memcpy(pos.ptr, &len, sizeof(len));
				pos = chunk_skip(pos, sizeof(len));
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			case AT_AUTN:
			case AT_RAND:
			{
				ahdr->length = data.len / 4 + 1;
				memset(pos.ptr, 0, 2);
				pos = chunk_skip(pos, 2);
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			case AT_MAC:
			{
				ahdr->length = 5;
				memset(pos.ptr, 0, 2);
				pos = chunk_skip(pos, 2);
				mac_pos = pos.ptr;
				memset(mac_pos, 0, AT_MAC_LEN);
				pos = chunk_skip(pos, AT_MAC_LEN);
				break;
			}
			case AT_IDENTITY:
			{
				len = data.len;
				/* align up to four bytes */
				if (data.len % 4)
				{
					chunk_t tmp = chunk_alloca((data.len/4)*4 + 4);
					memset(tmp.ptr, 0, tmp.len);
					memcpy(tmp.ptr, data.ptr, data.len);
					data = tmp;
				}
				ahdr->length = data.len / 4 + 1;
				/* actual length in bytes */
				len = htons(len);
				memcpy(pos.ptr, &len, sizeof(len));
				pos = chunk_skip(pos, sizeof(len));
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
			default:
			{
				ahdr->length = data.len / 4 + 1;
				memcpy(pos.ptr, data.ptr, data.len);
				pos = chunk_skip(pos, data.len);
				break;
			}
		}
	}
	va_end(args);

	/* calculate message length, write into header */
	message.len = pos.ptr - message.ptr;
	len = htons(message.len);
	memcpy(&hdr->length, &len, sizeof(len));

	/* create MAC if AT_MAC attribte was included */
	if (mac_pos)
	{
		DBG3(DBG_IKE, "AT_MAC signature of %B", &message);
		this->signer->get_signature(this->signer, message, mac_pos);
		DBG3(DBG_IKE, "is %b", mac_pos, AT_MAC_LEN);
	}

	/* payload constructor takes data with some bytes skipped */
	payload = eap_payload_create_data(message);

	DBG3(DBG_IKE, "created EAP message %B", &message);
	return payload;
}

/**
 * check if an unknown attribute is skippable
 */
static bool attribute_skippable(aka_attribute_t attribute)
{
	if (attribute >= 0 && attribute <= 127)
	{
		DBG1(DBG_IKE, "ignoring skippable attribute %N",
			 aka_attribute_names, attribute);
		return TRUE;
	}
	return FALSE;
}

/**
 * build the error response if we received an unknown non-skippable attribute
 */
static eap_payload_t *build_non_skippable_error(private_eap_aka_t *this,
								aka_attribute_t attribute, u_char identifier)
{
	DBG1(DBG_IKE, "found non skippable attribute %N, sending %N %d",
		 aka_attribute_names, attribute,
		 aka_attribute_names, AT_CLIENT_ERROR_CODE, 0);
	return build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
							 AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
}

/**
 * generate a new non-zero identifier
 */
static u_char get_identifier()
{
	while (TRUE)
	{
		u_char id = random();

		if (id)
		{
			return id;
		}
	}
}

/**
 * Implementation of eap_method_t.initiate for an EAP_AKA server
 */
static status_t server_initiate(private_eap_aka_t *this, eap_payload_t **out)
{
	enumerator_t *enumerator;
	sim_provider_t *provider;
	char ck[AKA_CK_LEN], ik[AKA_IK_LEN], autn[AKA_AUTN_LEN];
	bool found = FALSE;

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_quintuplet(provider, this->peer, this->rand,
									 this->res, ck, ik, autn))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		DBG1(DBG_IKE, "no AKA provider found with quintuplets for %Y",
			 this->peer);
		return FAILED;
	}

	derive_keys(this, this->peer, chunk_create(ck, AKA_CK_LEN),
				chunk_create(ik, AKA_IK_LEN));

	*out = build_aka_payload(this, EAP_REQUEST, get_identifier(), AKA_CHALLENGE,
						AT_RAND, chunk_create(this->rand, AKA_RAND_LEN),
						AT_AUTN, chunk_create(autn, AKA_AUTN_LEN),
						AT_MAC, chunk_empty, AT_END);
	return NEED_MORE;
}

/**
 * Process synchronization request from peer
 */
static status_t server_process_synchronize(private_eap_aka_t *this,
									eap_payload_t *in, eap_payload_t **out)
{
	chunk_t attr, message, pos, auts = chunk_empty;
	aka_attribute_t attribute;
	enumerator_t *enumerator;
	sim_provider_t *provider;
	bool found = FALSE;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);

	while (TRUE)
	{
		attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_AUTS:
				auts = attr;
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				DBG1(DBG_IKE, "found non skippable attribute %N",
					 aka_attribute_names, attribute);
				return FAILED;
		}
		break;
	}

	if (auts.len != AKA_AUTS_LEN)
	{
		DBG1(DBG_IKE, "synchronization request didn't contain usable AUTS");
		return FAILED;
	}

	enumerator = charon->sim->create_provider_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->resync(provider, this->peer, this->rand, auts.ptr))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		return FAILED;
	}
	return server_initiate(this, out);
}

/**
 * process an AKA_Challenge response
 */
static status_t server_process_challenge(private_eap_aka_t *this, eap_payload_t *in)
{
	chunk_t attr, res = chunk_empty, at_mac = chunk_empty, pos, message;
	aka_attribute_t attribute;
	u_int16_t len;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);

	while (TRUE)
	{
		attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_RES:
				res = attr;
				if (attr.len == 2 + AKA_RES_LEN)
				{
					memcpy(&len, attr.ptr, 2);
					if (ntohs(len) == AKA_RES_LEN * 8)
					{
						res = chunk_skip(attr, 2);
					}
				}
				continue;
			case AT_MAC:
				attr = chunk_skip(attr, 2);
				at_mac = chunk_clonea(attr);
				/* zero MAC in message for MAC verification */
				memset(attr.ptr, 0, attr.len);
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				DBG1(DBG_IKE, "found non skippable attribute %N",
					 aka_attribute_names, attribute);
				return FAILED;
		}
		break;
	}

	/* verify EAP message MAC AT_MAC */
	DBG3(DBG_IKE, "verifying AT_MAC signature of %B", &message);
	if (!this->signer->verify_signature(this->signer, message, at_mac))
	{
		DBG1(DBG_IKE, "MAC in AT_MAC attribute verification failed");
		return FAILED;
	}

	/* compare received RES against stored precalculated XRES */
	if (!chunk_equals(res, chunk_create(this->res, AKA_RES_LEN)))
	{
		DBG1(DBG_IKE, "received RES does not match XRES");
		DBG3(DBG_IKE, "RES %B XRES %b", &res, this->res, AKA_RES_LEN);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.process for EAP_AKA servers
 */
static status_t server_process(private_eap_aka_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t message;
	aka_subtype_t type;

	message = in->get_data(in);
	type = read_header(&message);

	DBG3(DBG_IKE, "received EAP message %B",  &message);

	switch (type)
	{
		case AKA_CHALLENGE:
		{
			return server_process_challenge(this, in);
		}
		case AKA_AUTHENTICATION_REJECT:
		case AKA_CLIENT_ERROR:
		{
			DBG1(DBG_IKE, "received %N, authentication failed",
				 aka_subtype_names, type);
			return FAILED;
		}
		case AKA_SYNCHRONIZATION_FAILURE:
		{
			DBG1(DBG_IKE, "received %N, retrying with received SQN",
				 aka_subtype_names, type);
			return server_process_synchronize(this, in, out);
		}
		default:
			DBG1(DBG_IKE, "received unknown AKA subtype %N, authentication failed",
				 aka_subtype_names, type);
			return FAILED;
	}
}

/**
 * Process an incoming AKA-Challenge client side
 */
static status_t peer_process_challenge(private_eap_aka_t *this,
									   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t autn = chunk_empty, rand = chunk_empty, at_mac = chunk_empty;
	chunk_t message, pos, attr = chunk_empty;
	aka_attribute_t attribute;
	u_int8_t identifier;
	enumerator_t *enumerator;
	sim_card_t *card;
	u_char res[AKA_RES_LEN], ck[AKA_CK_LEN], ik[AKA_IK_LEN], auts[AKA_AUTS_LEN];
	status_t status = NOT_FOUND;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);
	identifier = in->get_identifier(in);

	DBG3(DBG_IKE, "reading attributes from %B", &pos);

	while (TRUE)
	{
		attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_RAND:
				rand = chunk_skip(attr, 2);
				continue;
			case AT_AUTN:
				autn = chunk_skip(attr, 2);
				continue;
			case AT_MAC:
				attr = chunk_skip(attr, 2);
				at_mac = chunk_clonea(attr);
				/* set MAC in message to zero for own MAC verification */
				memset(attr.ptr, 0, attr.len);
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				*out = build_non_skippable_error(this, attribute, identifier);
				return NEED_MORE;
		}
		break;
	}

	if (rand.len != AKA_RAND_LEN || autn.len != AKA_AUTN_LEN)
	{
		/* required attributes wrong/not found, abort */
		*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
								AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
		DBG1(DBG_IKE, "could not find valid RAND/AUTN attribute, sending %N %d",
			 aka_attribute_names, AT_CLIENT_ERROR_CODE, 0);
		return NEED_MORE;
	}

	enumerator = charon->sim->create_card_enumerator(charon->sim);
	while (enumerator->enumerate(enumerator, &card))
	{
		status = card->get_quintuplet(card, this->peer, rand.ptr, autn.ptr,
									  ck, ik, res);
		if (status != FAILED)
		{	/* try next on error */
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (status == INVALID_STATE &&
		card->resync(card, this->peer, rand.ptr, auts))
	{
		*out = build_aka_payload(this, EAP_RESPONSE,
						identifier, AKA_SYNCHRONIZATION_FAILURE,
						AT_AUTS, chunk_create(auts, AKA_AUTS_LEN), AT_END);
		DBG1(DBG_IKE, "received SQN invalid, sending %N",
			 aka_subtype_names, AKA_SYNCHRONIZATION_FAILURE);
		return NEED_MORE;
	}
	if (status != SUCCESS)
	{
		*out = build_aka_payload(this, EAP_RESPONSE, identifier,
					 AKA_AUTHENTICATION_REJECT, AT_END);
		DBG1(DBG_IKE, "no USIM found with quintuplets for %Y, sending %N",
			 this->peer, aka_subtype_names, AKA_AUTHENTICATION_REJECT);
		return NEED_MORE;
	}

	derive_keys(this, this->peer, chunk_create(ck, AKA_CK_LEN),
				chunk_create(ik, AKA_IK_LEN));

	/* verify EAP message MAC AT_MAC */
	DBG3(DBG_IKE, "verifying AT_MAC signature of %B", &message);
	if (!this->signer->verify_signature(this->signer, message, at_mac))
	{
		*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
						AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
		DBG1(DBG_IKE, "MAC in AT_MAC attribute verification "
			 "failed, sending %N %d", aka_attribute_names,
			 AT_CLIENT_ERROR_CODE, 0);
		return NEED_MORE;
	}

	*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CHALLENGE,
							 AT_RES, chunk_create(res, AKA_RES_LEN),
							 AT_MAC, chunk_empty, AT_END);
	return NEED_MORE;
}

/**
 * Process an incoming AKA-Identity client side
 */
static status_t peer_process_identity(private_eap_aka_t *this,
									  eap_payload_t *in, eap_payload_t **out)
{
	chunk_t identity = chunk_empty, message, pos, attr;
	u_int8_t identifier;

	identifier = in->get_identifier(in);
	pos = message = in->get_data(in);
	read_header(&pos);

	DBG3(DBG_IKE, "reading attributes from %B", &pos);

	while (TRUE)
	{
		aka_attribute_t attribute = read_attribute(&pos, &attr);

		switch (attribute)
		{
			case AT_END:
				break;
			case AT_PERMANENT_ID_REQ:
			case AT_FULLAUTH_ID_REQ:
			case AT_ANY_ID_REQ:
				/* always respond with full identity */
				identity = this->peer->get_encoding(this->peer);
				DBG1(DBG_IKE, "server requested %N, sending '%Y'",
					 aka_attribute_names, attribute, this->peer);
				continue;
			default:
				if (attribute_skippable(attribute))
				{
					continue;
				}
				*out = build_non_skippable_error(this, attribute, identifier);
				return NEED_MORE;
		}
		break;
	}

	/* build response */
	*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_IDENTITY,
							 AT_IDENTITY, identity, AT_END);
	return NEED_MORE;
}

/**
 * Process an incoming AKA-Notification as client
 */
static status_t peer_process_notification(private_eap_aka_t *this,
										  eap_payload_t *in, eap_payload_t **out)
{
	chunk_t message, pos, attr;
	aka_attribute_t attribute;
	u_int8_t identifier;

	message = in->get_data(in);
	pos = message;
	read_header(&pos);
	identifier = in->get_identifier(in);

	DBG3(DBG_IKE, "reading attributes from %B", &pos);

	while (TRUE)
	{
		attribute = read_attribute(&pos, &attr);
		switch (attribute)
		{
			case AT_END:
				break;
			case AT_NOTIFICATION:
			{
				u_int16_t code;

				if (attr.len != 2)
				{
					DBG1(DBG_IKE, "received invalid AKA notification, ignored");
					continue;
				}
				memcpy(&code, attr.ptr, 2);
				code = ntohs(code);
				switch (code)
				{
					case 0:
						DBG1(DBG_IKE, "received AKA notification 'general "
							 "failure after authentication' (%d)", code);
						return FAILED;
					case 16384:
						DBG1(DBG_IKE, "received AKA notification 'general "
							 "failure' (%d)", code);
						return FAILED;
					case 32768:
						DBG1(DBG_IKE, "received AKA notification 'successfully "
							 "authenticated' (%d)", code);
						continue;
					case 1026:
						DBG1(DBG_IKE, "received AKA notification 'access "
							 "temporarily denied' (%d)", code);
						return FAILED;
					case 1031:
						DBG1(DBG_IKE, "received AKA notification 'not "
							 "subscribed to service' (%d)", code);
						return FAILED;
					default:
						DBG1(DBG_IKE, "received AKA notification code %d, "
							 "ignored", code);
					continue;
				}
			}
			default:
				if (!attribute_skippable(attribute))
				{
					DBG1(DBG_IKE, "ignoring non-skippable attribute %N in %N",
						 aka_attribute_names, attribute, aka_subtype_names,
						 AKA_NOTIFICATION);
				}
				continue;
		}
		break;
	}
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process for an EAP_AKA peer
 */
static status_t peer_process(private_eap_aka_t *this,
							 eap_payload_t *in, eap_payload_t **out)
{
	aka_subtype_t type;
	chunk_t message;
	u_int8_t identifier;

	message = in->get_data(in);
	type = read_header(&message);
	identifier = in->get_identifier(in);

	DBG3(DBG_IKE, "received EAP message %B", &message);

	switch (type)
	{
		case AKA_CHALLENGE:
		{
			return peer_process_challenge(this, in, out);
		}
		case AKA_IDENTITY:
		{
			return peer_process_identity(this, in, out);
		}
		case AKA_NOTIFICATION:
		{
			return peer_process_notification(this, in, out);
		}
		default:
		{
			*out = build_aka_payload(this, EAP_RESPONSE, identifier, AKA_CLIENT_ERROR,
						AT_CLIENT_ERROR_CODE, client_error_code, AT_END);
			DBG1(DBG_IKE, "received unsupported %N request, sending %N %d",
				 aka_subtype_names, type,
				 aka_attribute_names, AT_CLIENT_ERROR_CODE, 0);
			return NEED_MORE;
		}
	}
}

/**
 * Implementation of eap_method_t.initiate for an EAP AKA peer
 */
static status_t peer_initiate(private_eap_aka_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_aka_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_AKA;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_aka_t *this, chunk_t *msk)
{
	if (this->derived)
	{
		*msk = chunk_create(this->msk, MSK_LEN);
		return SUCCESS;
	}
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_aka_t *this)
{
	return TRUE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_aka_t *this)
{
	this->peer->destroy(this->peer);
	DESTROY_IF(this->sha1);
	DESTROY_IF(this->signer);
	DESTROY_IF(this->prf);
	free(this);
}

/**
 * generic constructor used by client & server
 */
static private_eap_aka_t *eap_aka_create_generic(identification_t *peer)
{
	private_eap_aka_t *this = malloc_thing(private_eap_aka_t);

	this->public.eap_method_interface.initiate = NULL;
	this->public.eap_method_interface.process = NULL;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;

	this->peer = peer->clone(peer);
	this->derived = FALSE;

	this->sha1 = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	this->signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_SHA1_128);
	this->prf = lib->crypto->create_prf(lib->crypto, PRF_FIPS_SHA1_160);
	if (!this->sha1 || !this->signer || !this->prf)
	{
		DBG1(DBG_IKE, "unable to initiate EAP-AKA, FIPS-PRF/SHA1 not supported");
		destroy(this);
		return NULL;
	}
	return this;
}

/*
 * Described in header.
 */
eap_aka_t *eap_aka_create_server(identification_t *server, identification_t *peer)
{
	private_eap_aka_t *this = eap_aka_create_generic(peer);

	if (this)
	{
		this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))server_initiate;
		this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))server_process;
	}
	return (eap_aka_t*)this;
}

/*
 * Described in header.
 */
eap_aka_t *eap_aka_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_aka_t *this = eap_aka_create_generic(peer);

	if (this)
	{
		this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))peer_initiate;
		this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))peer_process;
	}
	return (eap_aka_t*)this;
}

