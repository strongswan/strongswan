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
 */

#include "simaka_message.h"

typedef struct private_simaka_message_t private_simaka_message_t;
typedef struct hdr_t hdr_t;
typedef struct attr_hdr_t attr_hdr_t;
typedef struct attr_t attr_t;

/**
 * packed EAP-SIM/AKA header struct
 */
struct hdr_t {
	/** EAP code (REQUEST/RESPONSE) */
	u_int8_t code;
	/** unique message identifier */
	u_int8_t identifier;
	/** length of whole message */
	u_int16_t length;
	/** EAP type => EAP_SIM/EAP_AKA */
	u_int8_t type;
	/** SIM subtype */
	u_int8_t subtype;
	/** reserved bytes */
	u_int16_t reserved;
} __attribute__((__packed__));

/**
 * packed EAP-SIM/AKA attribute header struct
 */
struct attr_hdr_t {
	/** attribute type */
	u_int8_t type;
	/** attibute length */
	u_int8_t length;
} __attribute__((__packed__));

/**
 * SIM/AKA attribute, parsed
 */
struct attr_t {
	/** type of attribute */
	simaka_attribute_t type;
	/** length of data */
	size_t len;
	/** start of data, variable length */
	char data[];
};

ENUM_BEGIN(simaka_subtype_names, AKA_CHALLENGE, AKA_IDENTITY,
	"AKA_CHALLENGE",
	"AKA_AUTHENTICATION_REJECT",
	"AKA_3",
	"AKA_SYNCHRONIZATION_FAILURE",
	"AKA_IDENTITY");
ENUM_NEXT(simaka_subtype_names, SIM_START, AKA_CLIENT_ERROR, AKA_IDENTITY,
	"SIM_START",
	"SIM_CHALLENGE",
	"SIM/AKA_NOTIFICATION",
	"SIM/AKA_REAUTHENTICATION",
	"SIM/AKA_CLIENT_ERROR");
ENUM_END(simaka_subtype_names, AKA_CLIENT_ERROR);


ENUM_BEGIN(simaka_attribute_names, AT_RAND, AT_CLIENT_ERROR_CODE,
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
ENUM_NEXT(simaka_attribute_names, AT_IV, AT_RESULT_IND, AT_CLIENT_ERROR_CODE,
	"AT_IV",
	"AT_ENCR_DATA",
	"AT_131",
	"AT_NEXT_PSEUDONYM",
	"AT_NEXT_REAUTH_ID",
	"AT_CHECKCODE",
	"AT_RESULT_IND");
ENUM_END(simaka_attribute_names, AT_RESULT_IND);


ENUM_BEGIN(simaka_notification_names, SIM_GENERAL_FAILURE_AA, SIM_GENERAL_FAILURE_AA,
	"General failure after authentication");
ENUM_NEXT(simaka_notification_names, SIM_TEMP_DENIED, SIM_TEMP_DENIED, SIM_GENERAL_FAILURE_AA,
	"User has been temporarily denied access");
ENUM_NEXT(simaka_notification_names, SIM_NOT_SUBSCRIBED, SIM_NOT_SUBSCRIBED, SIM_TEMP_DENIED,
	"User has not subscribed to the requested service");
ENUM_NEXT(simaka_notification_names, SIM_GENERAL_FAILURE, SIM_GENERAL_FAILURE, SIM_NOT_SUBSCRIBED,
	"General failure");
ENUM_NEXT(simaka_notification_names, SIM_SUCCESS, SIM_SUCCESS, SIM_GENERAL_FAILURE,
	"User has been successfully authenticated");
ENUM_END(simaka_notification_names, SIM_SUCCESS);


ENUM(simaka_client_error_names, SIM_UNABLE_TO_PROCESS, SIM_RANDS_NOT_FRESH,
	"unable to process packet",
	"unsupported version",
	"insufficient number of challenges",
	"RANDs are not fresh",
);

/**
 * Check if an EAP-SIM/AKA attribute is skippable
 */
bool simaka_attribute_skippable(simaka_attribute_t attribute)
{
	bool skippable = !(attribute >= 0 && attribute <= 127);

	DBG1(DBG_IKE, "%sskippable EAP-SIM/AKA attribute %N",
		 skippable ? "ignoring " : "found non-",
		 simaka_attribute_names, attribute);
	return skippable;
}

/**
 * Private data of an simaka_message_t object.
 */
struct private_simaka_message_t {

	/**
	 * Public simaka_message_t interface.
	 */
	simaka_message_t public;

	/**
	 * EAP message, starting with EAP header
	 */
	hdr_t *hdr;

	/**
	 * List of parsed attributes, attr_t
	 */
	linked_list_t *attributes;

	/**
	 * Currently parsing AT_ENCR_DATA wrapped attributes?
	 */
	bool encrypted;

	/**
	 * Phase a NOTIFICATION is sent within */
	bool p_bit;

	/**
	 * MAC value, pointing into message
	 */
	chunk_t mac;
};

/**
 * Implementation of simaka_message_t.is_request
 */
static bool is_request(private_simaka_message_t *this)
{
	return this->hdr->code == EAP_REQUEST;
}

/**
 * Implementation of simaka_message_t.get_identifier
 */
static u_int8_t get_identifier(private_simaka_message_t *this)
{
	return this->hdr->identifier;
}

/**
 * Implementation of simaka_message_t.get_subtype
 */
static simaka_subtype_t get_subtype(private_simaka_message_t *this)
{
	return this->hdr->subtype;
}

/**
 * Implementation of simaka_message_t.get_type
 */
static eap_type_t get_type(private_simaka_message_t *this)
{
	return this->hdr->type;
}

/**
 * convert attr_t to type and data enumeration
 */
static bool attr_enum_filter(void *null, attr_t **in, simaka_attribute_t *type,
							 void *dummy, chunk_t *data)
{
	attr_t *attr = *in;

	*type = attr->type;
	*data = chunk_create(attr->data, attr->len);
	return TRUE;
}

/**
 * Implementation of simaka_message_t.create_attribute_enumerator
 */
static enumerator_t* create_attribute_enumerator(private_simaka_message_t *this)
{
	return enumerator_create_filter(
						this->attributes->create_enumerator(this->attributes),
						(void*)attr_enum_filter, NULL, NULL);
}

/**
 * Implementation of simaka_message_t.add_attribute
 */
static void add_attribute(private_simaka_message_t *this,
						  simaka_attribute_t type, chunk_t data)
{
	attr_t *attr;

	attr = malloc(sizeof(attr_t) + data.len);
	attr->len = data.len;
	attr->type = type;
	memcpy(attr->data, data.ptr, data.len);

	this->attributes->insert_last(this->attributes, attr);
}

/**
 * Implementation of simaka_message_t.parse
 */
static bool parse(private_simaka_message_t *this, simaka_crypto_t *crypto,
				  chunk_t sigdata)
{
	chunk_t in, iv = chunk_empty, encr = chunk_empty;

	in = chunk_create((char*)(this->hdr + 1),
					  ntohs(this->hdr->length) - sizeof(hdr_t));

	while (in.len)
	{
		attr_hdr_t *hdr;
		chunk_t data;

		if (in.len < sizeof(attr_hdr_t))
		{
			DBG1(DBG_IKE, "found short %N attribute header",
				 eap_type_names, this->hdr->type);
			return FALSE;
		}
		hdr = (attr_hdr_t*)in.ptr;

		switch (hdr->type)
		{
			/* attributes without data */
			case AT_COUNTER_TOO_SMALL:
				if (!this->encrypted)
				{
					return FALSE;
				}
				/* FALL */
			case AT_ANY_ID_REQ:
			case AT_PERMANENT_ID_REQ:
			case AT_FULLAUTH_ID_REQ:
			{
				if (hdr->length != 1 || in.len < 4)
				{
					return FALSE;
				}
				data = chunk_empty;
				in = chunk_skip(in, 4);
				break;
			}
			/* attributes with two bytes data */
			case AT_COUNTER:
				if (!this->encrypted)
				{
					return FALSE;
				}
				/* FALL */
			case AT_CLIENT_ERROR_CODE:
			case AT_SELECTED_VERSION:
			case AT_NOTIFICATION:
			{
				if (hdr->length != 1 || in.len < 4)
				{
					return FALSE;
				}
				data = chunk_create(in.ptr + 2, 2);
				in = chunk_skip(in, 4);
				break;
			}
			/* attributes with an additional actual-length in bits or bytes */
			case AT_NEXT_PSEUDONYM:
			case AT_NEXT_REAUTH_ID:
				if (!this->encrypted)
				{
					return FALSE;
				}
				/* FALL */
			case AT_RES:
			case AT_IDENTITY:
			case AT_VERSION_LIST:
			{
				u_int16_t len;

				if (hdr->length < 1 || in.len < 4)
				{
					return FALSE;
				}
				memcpy(&len, in.ptr + 2, 2);
				len = ntohs(len);
				if (hdr->type == AT_RES)
				{	/* AT_RES uses length encoding in bits */
					len /= 8;
				}
				if (len > hdr->length * 4 || len > in.len)
				{
					return FALSE;
				}
				data = chunk_create(in.ptr + 4, len);
				in = chunk_skip(in, hdr->length * 4);
				break;
			}
			/* attributes with two reserved bytes, 16 bytes length */
			case AT_NONCE_S:
				if (!this->encrypted)
				{
					return FALSE;
				}
				/* FALL */
			case AT_AUTN:
			case AT_NONCE_MT:
			case AT_IV:
			case AT_MAC:
			{
				if (hdr->length != 5 || in.len < 20)
				{
					return FALSE;
				}
				data = chunk_create(in.ptr + 4, 16);
				in = chunk_skip(in, 20);
				break;
			}
			/* attributes with two reserved bytes, variable length */
			case AT_ENCR_DATA:
			case AT_RAND:
			{
				if (hdr->length * 4 > in.len || in.len < 4)
				{
					return FALSE;
				}
				data = chunk_create(in.ptr + 4, hdr->length * 4 - 4);
				in = chunk_skip(in, hdr->length * 4);
				break;
			}
			/* attributes with no reserved bytes, 14 bytes length */
			case AT_AUTS:
			{
				if (hdr->length != 4 || in.len < 16)
				{
					return FALSE;
				}
				data = chunk_create(in.ptr + 2, 14);
				in = chunk_skip(in, 16);
				break;
			}
			/* other attributes (with 4n + 2 length) */
			case AT_PADDING:
			default:
			{
				if (hdr->length * 4 > in.len || in.len < 4)
				{
					return FALSE;
				}
				data = chunk_create(in.ptr + 2, hdr->length * 4 - 2);
				in = chunk_skip(in, hdr->length * 4);
				break;
			}
		}

		/* handle special attributes */
		switch (hdr->type)
		{
			case AT_MAC:
				this->mac = data;
				break;
			case AT_IV:
				iv = data;
				break;
			case AT_ENCR_DATA:
				encr = data;
				break;
			case AT_PADDING:
				break;
			case AT_NOTIFICATION:
				if (this->p_bit)
				{	/* remember P bit for MAC verification */
					this->p_bit = !!(data.ptr[0] & 0x40);
				}
				else if (!this->encrypted)
				{	/* found a P bit notify in an unencrypted message */
					return FALSE;
				}
				/* FALL */
			default:
				add_attribute(this, hdr->type, data);
				break;
		}
	}

	/* decrypt, invoke parser recursively */
	if (iv.len && encr.len)
	{
		bool success;
		crypter_t *crypter;

		if (this->encrypted)
		{
			DBG1(DBG_IKE, "%N message is recursively encrypted",
				 eap_type_names, this->hdr->type);
			return FALSE;
		}
		crypter = crypto->get_crypter(crypto);
		if (!crypter)
		{
			DBG1(DBG_IKE, "%N message contains unexpected encrypted data",
				 eap_type_names, this->hdr->type);
			return FALSE;
		}
		if (encr.len % crypter->get_block_size(crypter))
		{
			DBG1(DBG_IKE, "%N ENCR_DATA not a multiple of block size",
				 eap_type_names, this->hdr->type);
			return FALSE;
		}

		/* decrypt inline */
		crypter->decrypt(crypter, encr, iv, NULL);

		this->encrypted = TRUE;
		success = parse(this, crypto, chunk_empty);
		this->encrypted = FALSE;
		return success;
	}
	return TRUE;
}

/**
 * Implementation of simaka_message_t.verify
 */
static bool verify(private_simaka_message_t *this,
				   simaka_crypto_t *crypto, chunk_t sigdata)
{
	chunk_t data, backup;
	signer_t *signer;

	signer = crypto->get_signer(crypto);

	switch (this->hdr->subtype)
	{
		case SIM_START:
		case SIM_CLIENT_ERROR:
		  /* AKA_CLIENT_ERROR: */
		case AKA_AUTHENTICATION_REJECT:
		case AKA_SYNCHRONIZATION_FAILURE:
		case AKA_IDENTITY:
			/* skip MAC if available */
			return TRUE;
		case SIM_CHALLENGE:
		case AKA_CHALLENGE:
		case SIM_REAUTHENTICATION:
		  /* AKA_REAUTHENTICATION: */
		{
			if (!this->mac.ptr || !signer)
			{	/* require MAC, but not found */
				DBG1(DBG_IKE, "%N message requires a MAC, but none found",
					 simaka_subtype_names, this->hdr->subtype);
				return FALSE;
			}
			break;
		}
		case SIM_NOTIFICATION:
		  /* AKA_NOTIFICATION: */
		{
			if (this->p_bit)
			{	/* MAC not verified if in Phase 1 */
				return TRUE;
			}
			if (!this->mac.ptr || !signer)
			{
				DBG1(DBG_IKE, "%N message has a phase 0 notify, but "
					 "no MAC found", simaka_subtype_names, this->hdr->subtype);
				return FALSE;
			}
			break;
		}
		default:
			/* unknown message? */
			DBG1(DBG_IKE, "signature rule for %N messages missing",
				 simaka_subtype_names, this->hdr->subtype);
			return FALSE;
	}

	/* zero MAC for verification */
	backup = chunk_clonea(this->mac);
	memset(this->mac.ptr, 0, this->mac.len);

	data = chunk_create((char*)this->hdr, ntohs(this->hdr->length));
	if (sigdata.len)
	{
		data = chunk_cata("cc", data, sigdata);
	}
	if (!signer->verify_signature(signer, data, backup))
	{
		DBG1(DBG_IKE, "%N MAC verification failed",
			 eap_type_names, this->hdr->type);
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of simaka_message_t.generate
 */
static eap_payload_t* generate(private_simaka_message_t *this,
							   simaka_crypto_t *crypto, chunk_t sigdata)
{
	/* buffers large enough for messages we generate */
	char out_buf[1024], encr_buf[512];
	enumerator_t *enumerator;
	chunk_t out, encr, data, *target, mac = chunk_empty;
	simaka_attribute_t type;
	attr_hdr_t *hdr;
	u_int16_t len;
	signer_t *signer;

	out = chunk_create(out_buf, sizeof(out_buf));
	encr = chunk_create(encr_buf, sizeof(encr_buf));

	/* copy header */
	memcpy(out.ptr, this->hdr, sizeof(hdr_t));
	out = chunk_skip(out, sizeof(hdr_t));

	/* encode attributes */
	enumerator = create_attribute_enumerator(this);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		/* encrypt this attribute? */
		switch (type)
		{
			case AT_NONCE_S:
			case AT_NEXT_PSEUDONYM:
			case AT_NEXT_REAUTH_ID:
			case AT_COUNTER:
			case AT_COUNTER_TOO_SMALL:
				target = &encr;
				break;
			case AT_NOTIFICATION:
				/* P bit not set, encrypt */
				if (!(data.ptr[0] & 0x40))
				{
					target = &encr;
					break;
				}
				/* FALL */
			default:
				target = &out;
				break;
		}

		hdr = (attr_hdr_t*)target->ptr;
		hdr->type = type;

		/* encode type specific */
		switch (type)
		{
			/* attributes without data */
			case AT_COUNTER_TOO_SMALL:
			case AT_ANY_ID_REQ:
			case AT_PERMANENT_ID_REQ:
			case AT_FULLAUTH_ID_REQ:
			{
				hdr->length = 1;
				memset(target->ptr + 2, 0, 2);
				*target = chunk_skip(*target, 4);
				break;
			}
			/* attributes with two bytes data */
			case AT_COUNTER:
			case AT_CLIENT_ERROR_CODE:
			case AT_SELECTED_VERSION:
			case AT_NOTIFICATION:
			{
				hdr->length = 1;
				memcpy(target->ptr + 2, data.ptr, 2);
				*target = chunk_skip(*target, 4);
				break;
			}
			/* attributes with an additional actual-length in bits or bytes */
			case AT_NEXT_PSEUDONYM:
			case AT_NEXT_REAUTH_ID:
			case AT_IDENTITY:
			case AT_VERSION_LIST:
			case AT_RES:
			{
				u_int16_t len, padding;

				len = htons(data.len);
				if (type == AT_RES)
				{	/* AT_RES uses length encoding in bits */
					len *= 8;
				}
				memcpy(target->ptr + 2, &len, sizeof(len));
				memcpy(target->ptr + 4, data.ptr, data.len);
				hdr->length = data.len / 4 + 1;
				padding = (4 - (data.len % 4)) % 4;
				if (padding)
				{
					hdr->length++;
					memset(target->ptr + 4 + data.len, 0, padding);
				}
				*target = chunk_skip(*target, hdr->length * 4);
				break;
			}
			/* attributes with two reserved bytes, 16 bytes length */
			case AT_NONCE_S:
			case AT_NONCE_MT:
			case AT_AUTN:
			{
				hdr->length = 5;
				memset(target->ptr + 2, 0, 2);
				memcpy(target->ptr + 4, data.ptr, data.len);
				*target = chunk_skip(*target, 20);
				break;
			}
			/* attributes with two reserved bytes, variable length */
			case AT_RAND:
			{
				hdr->length = 1 + data.len / 4;
				memset(target->ptr + 2, 0, 2);
				memcpy(target->ptr + 4, data.ptr, data.len);
				*target = chunk_skip(*target, data.len + 4);
				break;
			}
			/* attributes with no reserved bytes, 14 bytes length */
			case AT_AUTS:
			{
				hdr->length = 4;
				memcpy(target->ptr + 2, data.ptr, data.len);
				*target = chunk_skip(*target, 16);
				break;
			}
			default:
			{
				DBG1(DBG_IKE, "no rule to encode %N, skipped",
					 simaka_attribute_names, type);
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	/* encrypt attributes, if any */
	if (encr.len < sizeof(encr_buf))
	{
		chunk_t iv;
		size_t bs;
		crypter_t *crypter;
		rng_t *rng;

		crypter = crypto->get_crypter(crypto);
		encr = chunk_create(encr_buf, sizeof(encr_buf) - encr.len);
		bs = crypter->get_block_size(crypter);

		/* add IV attribute */
		hdr = (attr_hdr_t*)out.ptr;
		hdr->type = AT_IV;
		hdr->length = bs / 4 + 1;
		memset(out.ptr + 2, 0, 2);
		out = chunk_skip(out, 4);

		rng = crypto->get_rng(crypto);
		rng->get_bytes(rng, bs, out.ptr);

		iv = chunk_clonea(chunk_create(out.ptr, bs));
		out = chunk_skip(out, bs);

		/* inline encryption */
		crypter->encrypt(crypter, encr, iv, NULL);

		/* add ENCR_DATA attribute */
		hdr = (attr_hdr_t*)out.ptr;
		hdr->type = AT_ENCR_DATA;
		hdr->length = encr.len / 4 + 1;
		memset(out.ptr + 2, 0, 2);
		memcpy(out.ptr + 4, encr.ptr, encr.len);
		out = chunk_skip(out, encr.len + 4);
	}

	/* include MAC ? */
	signer = crypto->get_signer(crypto);
	switch (this->hdr->subtype)
	{
		case SIM_CHALLENGE:
		case AKA_CHALLENGE:
		case SIM_REAUTHENTICATION:
		  /* AKA_REAUTHENTICATION: */
		/* TODO: Notifications without P bit */
		{
			size_t bs;

			bs = signer->get_block_size(signer);
			hdr = (attr_hdr_t*)out.ptr;
			hdr->type = AT_MAC;
			hdr->length = bs / 4 + 1;
			memset(out.ptr + 2, 0, 2 + bs);
			mac = chunk_create(out.ptr + 4, bs);
			out = chunk_skip(out, bs + 4);
			break;
		}
		default:
			break;
	}

	/* calculate message length */
	out = chunk_create(out_buf, sizeof(out_buf) - out.len);
	len = htons(out.len);
	memcpy(out.ptr + 2, &len, sizeof(len));

	/* generate MAC */
	if (mac.len)
	{
		data = chunk_cata("cc", out, sigdata);
		signer->get_signature(signer, data, mac.ptr);
	}
	return eap_payload_create_data(out);
}

/**
 * Implementation of simaka_message_t.destroy.
 */
static void destroy(private_simaka_message_t *this)
{
	this->attributes->destroy_function(this->attributes, free);
	free(this->hdr);
	free(this);
}

/**
 * Generic constructor.
 */
static simaka_message_t *simaka_message_create_data(chunk_t data)
{
	private_simaka_message_t *this;
	hdr_t *hdr = (hdr_t*)data.ptr;

	if (data.len < sizeof(hdr_t) || hdr->length != htons(data.len))
	{
		DBG1(DBG_IKE, "EAP-SIM/AKA header has invalid length");
		return NULL;
	}
	if (hdr->code != EAP_REQUEST && hdr->code != EAP_RESPONSE)
	{
		DBG1(DBG_IKE, "invalid EAP code in EAP-SIM/AKA message",
			 eap_type_names, hdr->type);
		return NULL;
	}
	if (hdr->type != EAP_SIM && hdr->type != EAP_AKA)
	{
		DBG1(DBG_IKE, "invalid EAP type in EAP-SIM/AKA message",
			 eap_type_names, hdr->type);
		return NULL;
	}

	this = malloc_thing(private_simaka_message_t);

	this->public.is_request = (bool(*)(simaka_message_t*))is_request;
	this->public.get_identifier = (u_int8_t(*)(simaka_message_t*))get_identifier;
	this->public.get_type = (eap_type_t(*)(simaka_message_t*))get_type;
	this->public.get_subtype = (simaka_subtype_t(*)(simaka_message_t*))get_subtype;
	this->public.create_attribute_enumerator = (enumerator_t*(*)(simaka_message_t*))create_attribute_enumerator;
	this->public.add_attribute = (void(*)(simaka_message_t*, simaka_attribute_t type, chunk_t data))add_attribute;
	this->public.parse = (bool(*)(simaka_message_t*, simaka_crypto_t* crypto))parse;
	this->public.verify = (bool(*)(simaka_message_t*, simaka_crypto_t* crypto, chunk_t sigdata))verify;
	this->public.generate = (eap_payload_t*(*)(simaka_message_t*, simaka_crypto_t* crypto, chunk_t sigdata))generate;
	this->public.destroy = (void(*)(simaka_message_t*))destroy;

	this->attributes = linked_list_create();
	this->encrypted = FALSE;
	this->p_bit = TRUE;
	this->mac = chunk_empty;
	this->hdr = malloc(data.len);
	memcpy(this->hdr, hdr, data.len);

	return &this->public;
}

/**
 * See header.
 */
simaka_message_t *simaka_message_create_from_payload(eap_payload_t *payload)
{
	return simaka_message_create_data(payload->get_data(payload));
}

/**
 * See header.
 */
simaka_message_t *simaka_message_create(bool request, u_int8_t identifier,
									eap_type_t type, simaka_subtype_t subtype)
{
	hdr_t hdr = {
		.code = request ? EAP_REQUEST : EAP_RESPONSE,
		.identifier = identifier,
		.length = htons(sizeof(hdr_t)),
		.type = type,
		.subtype = subtype,
	};
	return simaka_message_create_data(chunk_create((char*)&hdr, sizeof(hdr)));
}

