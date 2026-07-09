/*
 * Copyright (C) 2009 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#include "simaka_manager.h"

#include <utils/debug.h>
#include <collections/linked_list.h>

typedef struct private_simaka_message_t private_simaka_message_t;
typedef struct hdr_t hdr_t;
typedef struct attr_hdr_t attr_hdr_t;
typedef struct attr_t attr_t;

/**
 * packed EAP-SIM/AKA header struct
 */
struct hdr_t {
	/** EAP code (REQUEST/RESPONSE) */
	uint8_t code;
	/** unique message identifier */
	uint8_t identifier;
	/** length of whole message */
	uint16_t length;
	/** EAP type => EAP_SIM/EAP_AKA */
	uint8_t type;
	/** SIM subtype */
	uint8_t subtype;
	/** reserved bytes */
	uint16_t reserved;
} __attribute__((__packed__));

/**
 * packed EAP-SIM/AKA attribute header struct
 */
struct attr_hdr_t {
	/** attribute type */
	uint8_t type;
	/** attribute length */
	uint8_t length;
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
	bool skippable = !((int)attribute >= 0 && attribute <= 127);

	DBG1(DBG_LIB, "%sskippable EAP-SIM/AKA attribute %N",
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
	 * crypto helper
	 */
	simaka_crypto_t *crypto;

	/**
	 * Phase a NOTIFICATION is sent within
	 */
	bool p_bit;

	/**
	 * MAC value, pointing into message
	 */
	chunk_t mac;

	/**
	 * ENCR_DATA value, pointing into message
	 */
	chunk_t encr;

	/**
	 * IV value, pointing into message
	 */
	chunk_t iv;
};

METHOD(simaka_message_t, is_request, bool,
	private_simaka_message_t *this)
{
	return this->hdr->code == EAP_REQUEST;
}

METHOD(simaka_message_t, get_identifier, uint8_t,
	private_simaka_message_t *this)
{
	return this->hdr->identifier;
}

METHOD(simaka_message_t, get_subtype, simaka_subtype_t,
	private_simaka_message_t *this)
{
	return this->hdr->subtype;
}

METHOD(simaka_message_t, get_type, eap_type_t,
	private_simaka_message_t *this)
{
	return this->hdr->type;
}

CALLBACK(attr_enum_filter, bool,
	void *null, enumerator_t *orig, va_list args)
{
	attr_t *attr;
	simaka_attribute_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);

	if (orig->enumerate(orig, &attr))
	{
		*type = attr->type;
		*data = chunk_create(attr->data, attr->len);
		return TRUE;
	}
	return FALSE;
}

METHOD(simaka_message_t, create_attribute_enumerator, enumerator_t*,
	private_simaka_message_t *this)
{
	return enumerator_create_filter(
						this->attributes->create_enumerator(this->attributes),
						attr_enum_filter, NULL, NULL);
}

METHOD(simaka_message_t, add_attribute, void,
	private_simaka_message_t *this, simaka_attribute_t type, chunk_t data)
{
	attr_t *attr;

	attr = malloc(sizeof(attr_t) + data.len);
	attr->len = data.len;
	attr->type = type;
	memcpy(attr->data, data.ptr, data.len);

	this->attributes->insert_last(this->attributes, attr);
}

/**
 * Determine if an attribute is only sent encrypted
 */
static bool is_encrypted_attribute(simaka_attribute_t type)
{
	switch (type)
	{
		case AT_NONCE_S:
		case AT_NEXT_PSEUDONYM:
		case AT_NEXT_REAUTH_ID:
		case AT_COUNTER:
		case AT_COUNTER_TOO_SMALL:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * Error handling for invalid length
 */
static bool invalid_length(simaka_attribute_t type)
{
	DBG1(DBG_LIB, "invalid length of %N", simaka_attribute_names, type);
	return FALSE;
}

/**
 * Call SIM/AKA message hooks
 */
static void call_hook(private_simaka_message_t *this,
					  bool inbound, bool decrypted)
{
	simaka_manager_t *mgr;

	switch (this->hdr->type)
	{
		case EAP_SIM:
			mgr = lib->get(lib, "sim-manager");
			break;
		case EAP_AKA:
			mgr = lib->get(lib, "aka-manager");
			break;
		default:
			return;
	}
	mgr->message_hook(mgr, &this->public, inbound, decrypted);
}

/**
 * Parse attributes from a chunk of data
 */
static bool parse_attributes(private_simaka_message_t *this, chunk_t in)
{
	while (in.len)
	{
		attr_hdr_t *hdr;
		chunk_t data;

		if (in.len < sizeof(attr_hdr_t))
		{
			DBG1(DBG_LIB, "found short %N attribute header",
				 eap_type_names, this->hdr->type);
			return FALSE;
		}
		hdr = (attr_hdr_t*)in.ptr;

		if (is_encrypted_attribute(hdr->type) && !this->encrypted)
		{
			DBG1(DBG_LIB, "received unencrypted %N", simaka_attribute_names,
				 hdr->type);
			return FALSE;
		}

		switch (hdr->type)
		{
			/* attributes without data */
			case AT_COUNTER_TOO_SMALL:
			case AT_ANY_ID_REQ:
			case AT_PERMANENT_ID_REQ:
			case AT_FULLAUTH_ID_REQ:
			{
				if (hdr->length != 1 || in.len < 4)
				{
					return invalid_length(hdr->type);
				}
				data = chunk_empty;
				in = chunk_skip(in, 4);
				break;
			}
			/* attributes with two bytes data */
			case AT_COUNTER:
			case AT_CLIENT_ERROR_CODE:
			case AT_SELECTED_VERSION:
			case AT_NOTIFICATION:
			{
				if (hdr->length != 1 || in.len < 4)
				{
					return invalid_length(hdr->type);
				}
				data = chunk_create(in.ptr + 2, 2);
				in = chunk_skip(in, 4);
				break;
			}
			/* attributes with an additional actual-length in bits or bytes */
			case AT_NEXT_PSEUDONYM:
			case AT_NEXT_REAUTH_ID:
			case AT_RES:
			case AT_IDENTITY:
			case AT_VERSION_LIST:
			{
				uint16_t len;

				if (hdr->length < 1 || in.len < hdr->length * 4)
				{
					return invalid_length(hdr->type);
				}
				memcpy(&len, in.ptr + 2, 2);
				len = ntohs(len);
				if (hdr->type == AT_RES)
				{	/* AT_RES uses length encoding in bits */
					len /= 8;
				}
				if (len > hdr->length * 4 - 4)
				{
					return invalid_length(hdr->type);
				}
				data = chunk_create(in.ptr + 4, len);
				in = chunk_skip(in, hdr->length * 4);
				break;
			}
			/* attributes with two reserved bytes, 16 bytes length */
			case AT_NONCE_S:
			case AT_AUTN:
			case AT_NONCE_MT:
			case AT_IV:
			case AT_MAC:
			{
				if (hdr->length != 5 || in.len < 20)
				{
					return invalid_length(hdr->type);
				}
				data = chunk_create(in.ptr + 4, 16);
				in = chunk_skip(in, 20);
				break;
			}
			/* attributes with two reserved bytes, variable length */
			case AT_ENCR_DATA:
			case AT_RAND:
			{
				if (hdr->length == 0 || hdr->length * 4 > in.len || in.len < 4)
				{
					return invalid_length(hdr->type);
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
					return invalid_length(hdr->type);
				}
				data = chunk_create(in.ptr + 2, 14);
				in = chunk_skip(in, 16);
				break;
			}
			/* other attributes (with 4n + 2 length) */
			case AT_PADDING:
			default:
			{
				if (hdr->length == 0 || hdr->length * 4 > in.len || in.len < 4)
				{
					return invalid_length(hdr->type);
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
				this->iv = data;
				break;
			case AT_ENCR_DATA:
				this->encr = data;
				break;
			case AT_PADDING:
				break;
			case AT_NOTIFICATION:
				/* remember P bit for MAC verification */
				this->p_bit &= !!(data.ptr[0] & 0x40);
				/* FALL */
			default:
				add_attribute(this, hdr->type, data);
				break;
		}
	}

	call_hook(this, TRUE, this->encrypted);

	return TRUE;
}

/**
 * Decrypt a message and parse the decrypted attributes
 */
static bool decrypt(private_simaka_message_t *this)
{
	bool success;
	crypter_t *crypter;
	chunk_t plain;

	crypter = this->crypto->get_crypter(this->crypto);
	if (!crypter || !this->iv.len || !this->encr.len || this->encrypted)
	{
		return TRUE;
	}
	if (this->encr.len % crypter->get_block_size(crypter))
	{
		DBG1(DBG_LIB, "%N ENCR_DATA not a multiple of block size",
			 eap_type_names, this->hdr->type);
		return FALSE;
	}
	if (!crypter->decrypt(crypter, this->encr, this->iv, &plain))
	{
		return FALSE;
	}

	this->encrypted = TRUE;
	success = parse_attributes(this, plain);
	this->encrypted = FALSE;
	free(plain.ptr);
	return success;
}

METHOD(simaka_message_t, parse, bool,
	private_simaka_message_t *this)
{
	chunk_t in;

	if (this->attributes->get_count(this->attributes))
	{	/* Already parsed. Try to decrypt and parse AT_ENCR_DATA. */
		return decrypt(this);
	}

	in = chunk_create((char*)this->hdr, ntohs(this->hdr->length));
	if (!parse_attributes(this, chunk_skip(in, sizeof(hdr_t))))
	{
		return FALSE;
	}
	/* try to decrypt if we already have keys */
	return decrypt(this);
}

METHOD(simaka_message_t, verify, bool,
	private_simaka_message_t *this, chunk_t sigdata)
{
	chunk_t data, backup;
	signer_t *signer;

	signer = this->crypto->get_signer(this->crypto);

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
				DBG1(DBG_LIB, "%N message requires a MAC, but none found",
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
				DBG1(DBG_LIB, "%N message has a phase 0 notify, but "
					 "no MAC found", simaka_subtype_names, this->hdr->subtype);
				return FALSE;
			}
			break;
		}
		default:
			/* unknown message? */
			DBG1(DBG_LIB, "signature rule for %N messages missing",
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
		DBG1(DBG_LIB, "%N MAC verification failed",
			 eap_type_names, this->hdr->type);
		return FALSE;
	}
	return TRUE;
}

/**
 * Encode the given attribute into buf. If buf is NULL, the required size is
 * returned.
 */
static bool encode_attribute(simaka_attribute_t type, chunk_t data,
							 chunk_t *buf, size_t *len)
{
	attr_hdr_t *hdr = NULL;

	if (buf)
	{
		hdr = (attr_hdr_t*)buf->ptr;
		hdr->type = type;
	}

	switch (type)
	{
		/* attributes without data */
		case AT_COUNTER_TOO_SMALL:
		case AT_ANY_ID_REQ:
		case AT_PERMANENT_ID_REQ:
		case AT_FULLAUTH_ID_REQ:
		{
			if (data.len)
			{
				return invalid_length(type);
			}
			if (!buf)
			{
				*len = 4;
				break;
			}
			hdr->length = 1;
			memset(buf->ptr + 2, 0, 2);
			*buf = chunk_skip(*buf, 4);
			break;
		}
		/* attributes with two bytes data */
		case AT_COUNTER:
		case AT_CLIENT_ERROR_CODE:
		case AT_SELECTED_VERSION:
		case AT_NOTIFICATION:
		{
			if (data.len != 2)
			{
				return invalid_length(type);
			}
			if (!buf)
			{
				*len = 4;
				break;
			}
			hdr->length = 1;
			memcpy(buf->ptr + 2, data.ptr, 2);
			*buf = chunk_skip(*buf, 4);
			break;
		}
		/* attributes with an additional actual-length in bits or bytes */
		case AT_NEXT_PSEUDONYM:
		case AT_NEXT_REAUTH_ID:
		case AT_IDENTITY:
		case AT_VERSION_LIST:
		case AT_RES:
		{
			uint16_t actual_len, padding;

			if (data.len > UINT8_MAX * 4 - 4)
			{
				return invalid_length(type);
			}
			if (!buf)
			{
				*len = round_up(4 + data.len, 4);
				break;
			}
			actual_len = data.len;
			if (type == AT_RES)
			{	/* AT_RES uses length encoding in bits */
				actual_len *= 8;
			}
			htoun16(buf->ptr + 2, actual_len);
			memcpy(buf->ptr + 4, data.ptr, data.len);
			hdr->length = data.len / 4 + 1;
			padding = pad_len(data.len, 4);
			if (padding)
			{
				hdr->length++;
				memset(buf->ptr + 4 + data.len, 0, padding);
			}
			*buf = chunk_skip(*buf, hdr->length * 4);
			break;
		}
		/* attributes with two reserved bytes, 16 bytes length */
		case AT_NONCE_S:
		case AT_NONCE_MT:
		case AT_AUTN:
		{
			if (data.len != 16)
			{
				return invalid_length(type);
			}
			if (!buf)
			{
				*len = 20;
				break;
			}
			hdr->length = 5;
			memset(buf->ptr + 2, 0, 2);
			memcpy(buf->ptr + 4, data.ptr, data.len);
			*buf = chunk_skip(*buf, 20);
			break;
		}
		/* attributes with two reserved bytes, variable length */
		case AT_RAND:
		{
			if (data.len % 4 || data.len > UINT8_MAX * 4 - 4)
			{
				return invalid_length(type);
			}
			if (!buf)
			{
				*len = 4 + data.len;
				break;
			}
			hdr->length = 1 + data.len / 4;
			memset(buf->ptr + 2, 0, 2);
			memcpy(buf->ptr + 4, data.ptr, data.len);
			*buf = chunk_skip(*buf, data.len + 4);
			break;
		}
		/* attributes with no reserved bytes, 14 bytes length */
		case AT_AUTS:
		{
			if (data.len != 14)
			{
				return invalid_length(type);
			}
			if (!buf)
			{
				*len = 16;
				break;
			}
			hdr->length = 4;
			memcpy(buf->ptr + 2, data.ptr, data.len);
			*buf = chunk_skip(*buf, 16);
			break;
		}
		default:
		{
			if (!buf)
			{
				*len = 0;
				break;
			}
			DBG1(DBG_LIB, "no rule to encode %N, skipped",
				 simaka_attribute_names, type);
			break;
		}
	}
	return TRUE;
}

METHOD(simaka_message_t, generate, bool,
	private_simaka_message_t *this, chunk_t sigdata, chunk_t *gen)
{
	enumerator_t *enumerator;
	chunk_t out_buf, out, encr_buf, encr, data, *target, mac;
	simaka_attribute_t type;
	attr_hdr_t *hdr;
	size_t out_len = sizeof(hdr_t), encr_len = 0, attr_len;
	size_t iv_len = 0, encr_pad = 0, mac_bs = 0;
	bool notify_no_p_bit = FALSE, add_mac = FALSE, success = FALSE;
	crypter_t *crypter = NULL;
	signer_t *signer = NULL;
	rng_t *rng = NULL;

	call_hook(this, FALSE, TRUE);

	enumerator = create_attribute_enumerator(this);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (!encode_attribute(type, data, NULL, &attr_len))
		{
			enumerator->destroy(enumerator);
			return FALSE;
		}
		if (!attr_len)
		{
			continue;
		}
		if (is_encrypted_attribute(type))
		{
			encr_len += attr_len;
		}
		else
		{
			if (type == AT_NOTIFICATION)
			{
				notify_no_p_bit |= !(data.ptr[0] & 0x40);
			}
			out_len += attr_len;
		}
	}
	enumerator->destroy(enumerator);

	if (encr_len)
	{
		crypter = this->crypto->get_crypter(this->crypto);
		if (!crypter)
		{
			DBG1(DBG_LIB, "%N message requires encryption, but no crypter found",
				 simaka_subtype_names, this->hdr->subtype);
			return FALSE;
		}
		rng = this->crypto->get_rng(this->crypto);
		if (!rng)
		{
			DBG1(DBG_LIB, "%N message requires RNG, but none found",
				 simaka_subtype_names, this->hdr->subtype);
			return FALSE;
		}
		iv_len = crypter->get_iv_size(crypter);
		encr_pad = pad_len(encr_len, crypter->get_block_size(crypter));
		/* AT_PADDING */
		encr_len += encr_pad;
		if (encr_len > UINT8_MAX * 4 - 4)
		{
			DBG1(DBG_LIB, "encrypted attributes exceed maximum length");
			return FALSE;
		}
		/* AT_IV */
		out_len += 4 + iv_len;
		/* AT_ENCR_DATA */
		out_len += 4 + encr_len;
	}

	switch (this->hdr->subtype)
	{
		case SIM_CHALLENGE:
		case AKA_CHALLENGE:
		case SIM_REAUTHENTICATION:
		  /* AKA_REAUTHENTICATION: */
			add_mac = TRUE;
			break;
		case SIM_NOTIFICATION:
		  /* AKA_NOTIFICATION: */
			add_mac = notify_no_p_bit;
			break;
		default:
			break;
	}

	if (add_mac)
	{
		signer = this->crypto->get_signer(this->crypto);
		if (!signer)
		{
			DBG1(DBG_LIB, "%N message requires AT_MAC, but no signer found",
				 simaka_subtype_names, this->hdr->subtype);
			return FALSE;
		}
		mac_bs = signer->get_block_size(signer);
		/* AT_MAC */
		out_len += 4 + mac_bs;
	}

	if (out_len > UINT16_MAX)
	{
		DBG1(DBG_LIB, "EAP-SIM/AKA message exceeds maximum length");
		return FALSE;
	}

	out = out_buf = chunk_alloc(out_len);
	encr = encr_buf = chunk_alloc(encr_len);

	/* copy header, set length */
	memcpy(out.ptr, this->hdr, sizeof(hdr_t));
	htoun16(out.ptr + 2, out.len);

	out = chunk_skip(out, sizeof(hdr_t));

	/* encode attributes */
	enumerator = create_attribute_enumerator(this);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		target = is_encrypted_attribute(type) ? &encr : &out;
		encode_attribute(type, data, target, NULL);
	}
	enumerator->destroy(enumerator);

	if (encr_len)
	{
		chunk_t iv;

		/* add AT_PADDING attribute */
		if (encr_pad)
		{
			hdr = (attr_hdr_t*)encr.ptr;
			hdr->type = AT_PADDING;
			hdr->length = encr_pad / 4;
			memset(encr.ptr + 2, 0, encr_pad - 2);
		}

		/* add IV attribute */
		hdr = (attr_hdr_t*)out.ptr;
		hdr->type = AT_IV;
		hdr->length = iv_len / 4 + 1;
		memset(out.ptr + 2, 0, 2);
		out = chunk_skip(out, 4);

		iv = chunk_create(out.ptr, iv_len);
		if (!rng->get_bytes(rng, iv.len, iv.ptr))
		{
			goto failed;
		}
		out = chunk_skip(out, iv.len);

		/* inline encryption */
		if (!crypter->encrypt(crypter, encr_buf, iv, NULL))
		{
			goto failed;
		}

		/* add ENCR_DATA attribute */
		hdr = (attr_hdr_t*)out.ptr;
		hdr->type = AT_ENCR_DATA;
		hdr->length = encr_buf.len / 4 + 1;
		memset(out.ptr + 2, 0, 2);
		memcpy(out.ptr + 4, encr_buf.ptr, encr_buf.len);
		out = chunk_skip(out, encr_buf.len + 4);
	}

	if (add_mac)
	{
		hdr = (attr_hdr_t*)out.ptr;
		hdr->type = AT_MAC;
		hdr->length = mac_bs / 4 + 1;
		memset(out.ptr + 2, 0, 2 + mac_bs);
		mac = chunk_create(out.ptr + 4, mac_bs);

		if (!signer->get_signature(signer, out_buf, NULL) ||
			!signer->get_signature(signer, sigdata, mac.ptr))
		{
			goto failed;
		}
	}

	call_hook(this, FALSE, FALSE);

	*gen = out_buf;
	success = TRUE;

failed:
	chunk_clear(&encr_buf);
	if (!success)
	{
		chunk_free(&out_buf);
	}
	return success;
}

METHOD(simaka_message_t, destroy, void,
	private_simaka_message_t *this)
{
	this->attributes->destroy_function(this->attributes, free);
	free(this->hdr);
	free(this);
}

/**
 * Generic constructor.
 */
static simaka_message_t *simaka_message_create_data(chunk_t data,
													simaka_crypto_t *crypto)
{
	private_simaka_message_t *this;
	hdr_t *hdr = (hdr_t*)data.ptr;

	if (data.len < sizeof(hdr_t) || hdr->length != htons(data.len))
	{
		DBG1(DBG_LIB, "EAP-SIM/AKA header has invalid length");
		return NULL;
	}
	if (hdr->code != EAP_REQUEST && hdr->code != EAP_RESPONSE)
	{
		DBG1(DBG_LIB, "invalid EAP code in EAP-SIM/AKA message",
			 eap_type_names, hdr->type);
		return NULL;
	}
	if (hdr->type != EAP_SIM && hdr->type != EAP_AKA)
	{
		DBG1(DBG_LIB, "invalid EAP type in EAP-SIM/AKA message",
			 eap_type_names, hdr->type);
		return NULL;
	}

	INIT(this,
		.public = {
			.is_request = _is_request,
			.get_identifier = _get_identifier,
			.get_type = _get_type,
			.get_subtype = _get_subtype,
			.create_attribute_enumerator = _create_attribute_enumerator,
			.add_attribute = _add_attribute,
			.parse = _parse,
			.verify = _verify,
			.generate = _generate,
			.destroy = _destroy,
		},
		.attributes = linked_list_create(),
		.crypto = crypto,
		.p_bit = TRUE,
		.hdr = malloc(data.len),
	);
	memcpy(this->hdr, hdr, data.len);

	return &this->public;
}

/**
 * See header.
 */
simaka_message_t *simaka_message_create_from_payload(chunk_t data,
													 simaka_crypto_t *crypto)
{
	return simaka_message_create_data(data, crypto);
}

/**
 * See header.
 */
simaka_message_t *simaka_message_create(bool request, uint8_t identifier,
									eap_type_t type, simaka_subtype_t subtype,
									simaka_crypto_t *crypto)
{
	hdr_t hdr = {
		.code = request ? EAP_REQUEST : EAP_RESPONSE,
		.identifier = identifier,
		.length = htons(sizeof(hdr_t)),
		.type = type,
		.subtype = subtype,
	};
	return simaka_message_create_data(chunk_create((char*)&hdr, sizeof(hdr)),
									  crypto);
}
