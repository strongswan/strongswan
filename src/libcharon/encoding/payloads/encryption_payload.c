/*
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 * Copyright (C) 2011 Tobias Brunner
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

#include <stddef.h>
#include <string.h>

#include "encryption_payload.h"

#include <daemon.h>
#include <encoding/payloads/encodings.h>
#include <collections/linked_list.h>
#include <encoding/generator.h>
#include <encoding/parser.h>

typedef struct private_encryption_payload_t private_encryption_payload_t;

/**
 * Private data of an encryption_payload_t' Object.
 *
 */
struct private_encryption_payload_t {

	/**
	 * Public encryption_payload_t interface.
	 */
	encryption_payload_t public;

	/**
	 * There is no next payload for an encryption payload,
	 * since encryption payload MUST be the last one.
	 * next_payload means here the first payload of the
	 * contained, encrypted payload.
	 */
	u_int8_t next_payload;

	/**
	 * Flags, including reserved bits
	 */
	u_int8_t flags;

	/**
	 * Length of this payload
	 */
	u_int16_t payload_length;

	/**
	 * Chunk containing the IV, plain, padding and ICV.
	 */
	chunk_t encrypted;

	/**
	 * AEAD transform to use
	 */
	aead_t *aead;

	/**
	 * Contained payloads
	 */
	linked_list_t *payloads;

	/**
	 * Type of payload, ENCRYPTED or ENCRYPTED_V1
	 */
	payload_type_t type;
};

/**
 * Encoding rules to parse or generate a IKEv2-Encryption Payload.
 *
 * The defined offsets are the positions in a object of type
 * private_encryption_payload_t.
 */
static encoding_rule_t encodings_v2[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_encryption_payload_t, next_payload)	},
	/* Critical and 7 reserved bits, all stored for reconstruction */
	{ U_INT_8,			offsetof(private_encryption_payload_t, flags)			},
	/* Length of the whole encryption payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_encryption_payload_t, payload_length)	},
	/* encrypted data, stored in a chunk. contains iv, data, padding */
	{ CHUNK_DATA,		offsetof(private_encryption_payload_t, encrypted)		},
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                     Initialization Vector                     !
      !         (length is block size for encryption algorithm)       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                    Encrypted IKE Payloads                     !
      +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !               !             Padding (0-255 octets)            !
      +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
      !                                               !  Pad Length   !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ~                    Integrity Checksum Data                    ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Encoding rules to parse or generate a complete encrypted IKEv1 message.
 *
 * The defined offsets are the positions in a object of type
 * private_encryption_payload_t.
 */
static encoding_rule_t encodings_v1[] = {
	/* encrypted data, stored in a chunk */
	{ ENCRYPTED_DATA,	offsetof(private_encryption_payload_t, encrypted)		},
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                    Encrypted IKE Payloads                     !
      +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !               !             Padding (0-255 octets)            !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_encryption_payload_t *this)
{
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, int,
	private_encryption_payload_t *this, encoding_rule_t **rules)
{
	if (this->type == ENCRYPTED)
	{
		*rules = encodings_v2;
		return countof(encodings_v2);
	}
	*rules = encodings_v1;
	return countof(encodings_v1);
}

METHOD(payload_t, get_header_length, int,
	private_encryption_payload_t *this)
{
	if (this->type == ENCRYPTED)
	{
		return 4;
	}
	return 0;
}

METHOD(payload_t, get_type, payload_type_t,
	private_encryption_payload_t *this)
{
	return this->type;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_encryption_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_encryption_payload_t *this, payload_type_t type)
{
	/* the next payload is set during add, still allow this for IKEv1 */
	this->next_payload = type;
}

/**
 * Compute the length of the whole payload
 */
static void compute_length(private_encryption_payload_t *this)
{
	enumerator_t *enumerator;
	payload_t *payload;
	size_t bs, length = 0;

	if (this->encrypted.len)
	{
		length = this->encrypted.len;
	}
	else
	{
		enumerator = this->payloads->create_enumerator(this->payloads);
		while (enumerator->enumerate(enumerator, &payload))
		{
			length += payload->get_length(payload);
		}
		enumerator->destroy(enumerator);

		if (this->aead)
		{
			/* append padding */
			bs = this->aead->get_block_size(this->aead);
			length += bs - (length % bs);
			/* add iv */
			length += this->aead->get_iv_size(this->aead);
			/* add icv */
			length += this->aead->get_icv_size(this->aead);
		}
	}
	length += get_header_length(this);
	this->payload_length = length;
}

METHOD2(payload_t, encryption_payload_t, get_length, size_t,
	private_encryption_payload_t *this)
{
	compute_length(this);
	return this->payload_length;
}

METHOD(encryption_payload_t, add_payload, void,
	private_encryption_payload_t *this, payload_t *payload)
{
	payload_t *last_payload;

	if (this->payloads->get_count(this->payloads) > 0)
	{
		this->payloads->get_last(this->payloads, (void **)&last_payload);
		last_payload->set_next_type(last_payload, payload->get_type(payload));
	}
	else
	{
		this->next_payload = payload->get_type(payload);
	}
	payload->set_next_type(payload, NO_PAYLOAD);
	this->payloads->insert_last(this->payloads, payload);
	compute_length(this);
}

METHOD(encryption_payload_t, remove_payload, payload_t *,
	private_encryption_payload_t *this)
{
	payload_t *payload;

	if (this->payloads->remove_first(this->payloads,
									 (void**)&payload) == SUCCESS)
	{
		return payload;
	}
	return NULL;
}

/**
 * Generate payload before encryption
 */
static chunk_t generate(private_encryption_payload_t *this,
						generator_t *generator)
{
	payload_t *current, *next;
	enumerator_t *enumerator;
	u_int32_t *lenpos;
	chunk_t chunk = chunk_empty;

	enumerator = this->payloads->create_enumerator(this->payloads);
	if (enumerator->enumerate(enumerator, &current))
	{
		this->next_payload = current->get_type(current);

		while (enumerator->enumerate(enumerator, &next))
		{
			current->set_next_type(current, next->get_type(next));
			generator->generate_payload(generator, current);
			current = next;
		}
		current->set_next_type(current, NO_PAYLOAD);
		generator->generate_payload(generator, current);

		chunk = generator->get_chunk(generator, &lenpos);
		DBG2(DBG_ENC, "generated content in encryption payload");
	}
	enumerator->destroy(enumerator);
	return chunk;
}

/**
 * Append the encryption payload header to the associated data
 */
static chunk_t append_header(private_encryption_payload_t *this, chunk_t assoc)
{
	struct {
		u_int8_t next_payload;
		u_int8_t flags;
		u_int16_t length;
	} __attribute__((packed)) header = {
		.next_payload = this->next_payload,
		.flags = this->flags,
		.length = htons(get_length(this)),
	};
	return chunk_cat("cc", assoc, chunk_from_thing(header));
}

METHOD(encryption_payload_t, encrypt, status_t,
	private_encryption_payload_t *this, u_int64_t mid, chunk_t assoc)
{
	chunk_t iv, plain, padding, icv, crypt;
	generator_t *generator;
	iv_gen_t *iv_gen;
	rng_t *rng;
	size_t bs;

	if (this->aead == NULL)
	{
		DBG1(DBG_ENC, "encrypting encryption payload failed, transform missing");
		return INVALID_STATE;
	}

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_ENC, "encrypting encryption payload failed, no RNG found");
		return NOT_SUPPORTED;
	}

	iv_gen = this->aead->get_iv_gen(this->aead);
	if (!iv_gen)
	{
		DBG1(DBG_ENC, "encrypting encryption payload failed, no IV generator");
		return NOT_SUPPORTED;
	}

	assoc = append_header(this, assoc);

	generator = generator_create();
	plain = generate(this, generator);
	bs = this->aead->get_block_size(this->aead);
	/* we need at least one byte padding to store the padding length */
	padding.len = bs - (plain.len % bs);
	iv.len = this->aead->get_iv_size(this->aead);
	icv.len = this->aead->get_icv_size(this->aead);

	/* prepare data to authenticate-encrypt:
	 * | IV | plain | padding | ICV |
	 *       \____crypt______/   ^
	 *              |           /
	 *              v          /
	 *     assoc -> + ------->/
	 */
	free(this->encrypted.ptr);
	this->encrypted = chunk_alloc(iv.len + plain.len + padding.len + icv.len);
	iv.ptr = this->encrypted.ptr;
	memcpy(iv.ptr + iv.len, plain.ptr, plain.len);
	plain.ptr = iv.ptr + iv.len;
	padding.ptr = plain.ptr + plain.len;
	icv.ptr = padding.ptr + padding.len;
	crypt = chunk_create(plain.ptr, plain.len + padding.len);
	generator->destroy(generator);

	if (!iv_gen->get_iv(iv_gen, mid, iv.len, iv.ptr) ||
		!rng->get_bytes(rng, padding.len - 1, padding.ptr))
	{
		DBG1(DBG_ENC, "encrypting encryption payload failed, no IV or padding");
		rng->destroy(rng);
		free(assoc.ptr);
		return FAILED;
	}
	padding.ptr[padding.len - 1] = padding.len - 1;
	rng->destroy(rng);

	DBG3(DBG_ENC, "encryption payload encryption:");
	DBG3(DBG_ENC, "IV %B", &iv);
	DBG3(DBG_ENC, "plain %B", &plain);
	DBG3(DBG_ENC, "padding %B", &padding);
	DBG3(DBG_ENC, "assoc %B", &assoc);

	if (!this->aead->encrypt(this->aead, crypt, assoc, iv, NULL))
	{
		free(assoc.ptr);
		return FAILED;
	}

	DBG3(DBG_ENC, "encrypted %B", &crypt);
	DBG3(DBG_ENC, "ICV %B", &icv);

	free(assoc.ptr);

	return SUCCESS;
}

METHOD(encryption_payload_t, encrypt_v1, status_t,
	private_encryption_payload_t *this, u_int64_t mid, chunk_t iv)
{
	generator_t *generator;
	chunk_t plain, padding;
	size_t bs;

	if (this->aead == NULL)
	{
		DBG1(DBG_ENC, "encryption failed, transform missing");
		return INVALID_STATE;
	}

	generator = generator_create();
	plain = generate(this, generator);
	bs = this->aead->get_block_size(this->aead);
	padding.len = bs - (plain.len % bs);

	/* prepare data to encrypt:
	 * | plain | padding | */
	free(this->encrypted.ptr);
	this->encrypted = chunk_alloc(plain.len + padding.len);
	memcpy(this->encrypted.ptr, plain.ptr, plain.len);
	plain.ptr = this->encrypted.ptr;
	padding.ptr = plain.ptr + plain.len;
	memset(padding.ptr, 0, padding.len);
	generator->destroy(generator);

	DBG3(DBG_ENC, "encrypting payloads:");
	DBG3(DBG_ENC, "plain %B", &plain);
	DBG3(DBG_ENC, "padding %B", &padding);

	if (!this->aead->encrypt(this->aead, this->encrypted, chunk_empty, iv, NULL))
	{
		return FAILED;
	}

	DBG3(DBG_ENC, "encrypted %B", &this->encrypted);

	return SUCCESS;
}

/**
 * Parse the payloads after decryption.
 */
static status_t parse(private_encryption_payload_t *this, chunk_t plain)
{
	parser_t *parser;
	payload_type_t type;

	parser = parser_create(plain);
	type = this->next_payload;
	while (type != NO_PAYLOAD)
	{
		payload_t *payload;

		if (plain.len < 4 || untoh16(plain.ptr + 2) > plain.len)
		{
			DBG1(DBG_ENC, "invalid %N payload length, decryption failed?",
				 payload_type_names, type);
			parser->destroy(parser);
			return PARSE_ERROR;
		}
		if (parser->parse_payload(parser, type, &payload) != SUCCESS)
		{
			parser->destroy(parser);
			return PARSE_ERROR;
		}
		if (payload->verify(payload) != SUCCESS)
		{
			DBG1(DBG_ENC, "%N verification failed",
				 payload_type_names, payload->get_type(payload));
			payload->destroy(payload);
			parser->destroy(parser);
			return VERIFY_ERROR;
		}
		type = payload->get_next_type(payload);
		this->payloads->insert_last(this->payloads, payload);
	}
	parser->destroy(parser);
	DBG2(DBG_ENC, "parsed content of encryption payload");
	return SUCCESS;
}

METHOD(encryption_payload_t, decrypt, status_t,
	private_encryption_payload_t *this, chunk_t assoc)
{
	chunk_t iv, plain, padding, icv, crypt;
	size_t bs;

	if (this->aead == NULL)
	{
		DBG1(DBG_ENC, "decrypting encryption payload failed, transform missing");
		return INVALID_STATE;
	}

	/* prepare data to authenticate-decrypt:
	 * | IV | plain | padding | ICV |
	 *       \____crypt______/   ^
	 *              |           /
	 *              v          /
	 *     assoc -> + ------->/
	 */

	bs = this->aead->get_block_size(this->aead);
	iv.len = this->aead->get_iv_size(this->aead);
	iv.ptr = this->encrypted.ptr;
	icv.len = this->aead->get_icv_size(this->aead);
	icv.ptr = this->encrypted.ptr + this->encrypted.len - icv.len;
	crypt.ptr = iv.ptr + iv.len;
	crypt.len = this->encrypted.len - iv.len;

	if (iv.len + icv.len > this->encrypted.len ||
		(crypt.len - icv.len) % bs)
	{
		DBG1(DBG_ENC, "decrypting encryption payload failed, invalid length");
		return FAILED;
	}

	assoc = append_header(this, assoc);

	DBG3(DBG_ENC, "encryption payload decryption:");
	DBG3(DBG_ENC, "IV %B", &iv);
	DBG3(DBG_ENC, "encrypted %B", &crypt);
	DBG3(DBG_ENC, "ICV %B", &icv);
	DBG3(DBG_ENC, "assoc %B", &assoc);

	if (!this->aead->decrypt(this->aead, crypt, assoc, iv, NULL))
	{
		DBG1(DBG_ENC, "verifying encryption payload integrity failed");
		free(assoc.ptr);
		return FAILED;
	}
	free(assoc.ptr);

	plain = chunk_create(crypt.ptr, crypt.len - icv.len);
	padding.len = plain.ptr[plain.len - 1] + 1;
	if (padding.len > plain.len)
	{
		DBG1(DBG_ENC, "decrypting encryption payload failed, "
			 "padding invalid %B", &crypt);
		return PARSE_ERROR;
	}
	plain.len -= padding.len;
	padding.ptr = plain.ptr + plain.len;

	DBG3(DBG_ENC, "plain %B", &plain);
	DBG3(DBG_ENC, "padding %B", &padding);

	return parse(this, plain);
}

METHOD(encryption_payload_t, decrypt_v1, status_t,
	private_encryption_payload_t *this, chunk_t iv)
{
	if (this->aead == NULL)
	{
		DBG1(DBG_ENC, "decryption failed, transform missing");
		return INVALID_STATE;
	}

	/* data must be a multiple of block size */
	if (iv.len != this->aead->get_block_size(this->aead) ||
		this->encrypted.len < iv.len || this->encrypted.len % iv.len)
	{
		DBG1(DBG_ENC, "decryption failed, invalid length");
		return FAILED;
	}

	DBG3(DBG_ENC, "decrypting payloads:");
	DBG3(DBG_ENC, "encrypted %B", &this->encrypted);

	if (!this->aead->decrypt(this->aead, this->encrypted, chunk_empty, iv, NULL))
	{
		return FAILED;
	}

	DBG3(DBG_ENC, "plain %B", &this->encrypted);

	return parse(this, this->encrypted);
}

METHOD(encryption_payload_t, set_transform, void,
	private_encryption_payload_t *this, aead_t* aead)
{
	this->aead = aead;
}

METHOD2(payload_t, encryption_payload_t, destroy, void,
	private_encryption_payload_t *this)
{
	this->payloads->destroy_offset(this->payloads, offsetof(payload_t, destroy));
	free(this->encrypted.ptr);
	free(this);
}

/*
 * Described in header
 */
encryption_payload_t *encryption_payload_create(payload_type_t type)
{
	private_encryption_payload_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_header_length = _get_header_length,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.get_length = _get_length,
			.add_payload = _add_payload,
			.remove_payload = _remove_payload,
			.set_transform = _set_transform,
			.encrypt = _encrypt,
			.decrypt = _decrypt,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payloads = linked_list_create(),
		.type = type,
	);
	this->payload_length = get_header_length(this);

	if (type == ENCRYPTED_V1)
	{
		this->public.encrypt = _encrypt_v1;
		this->public.decrypt = _decrypt_v1;
	}

	return &this->public;
}
