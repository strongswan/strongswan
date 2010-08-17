/*
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
 */

#include <stddef.h>
#include <string.h>

#include "encryption_payload.h"

#include <daemon.h>
#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <utils/iterator.h>
#include <crypto/signers/signer.h>


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
	 * Critical flag.
	 */
	bool critical;

	/**
	 * Length of this payload
	 */
	u_int16_t payload_length;

	/**
	 * Chunk containing the iv, data, padding,
	 * and (an eventually not calculated) signature.
	 */
	chunk_t encrypted;

	/**
	 * Chunk containing the data in decrypted (unpadded) form.
	 */
	chunk_t decrypted;

	/**
	 * Signer set by set_signer.
	 */
	signer_t *signer;

	/**
	 * Crypter, supplied by encrypt/decrypt
	 */
	crypter_t *crypter;

	/**
	 * Contained payloads of this encrpytion_payload.
	 */
	linked_list_t *payloads;
};

/**
 * Encoding rules to parse or generate a IKEv2-Encryption Payload.
 *
 * The defined offsets are the positions in a object of type
 * private_encryption_payload_t.
 */
encoding_rule_t encryption_payload_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_encryption_payload_t, next_payload)	},
	/* the critical bit */
	{ FLAG,				offsetof(private_encryption_payload_t, critical)		},
	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,		0														},
	{ RESERVED_BIT,		0														},
	{ RESERVED_BIT,		0														},
	{ RESERVED_BIT,		0														},
	{ RESERVED_BIT,		0														},
	{ RESERVED_BIT,		0														},
	{ RESERVED_BIT,		0														},
	/* Length of the whole encryption payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_encryption_payload_t, payload_length)	},
	/* encrypted data, stored in a chunk. contains iv, data, padding */
	{ ENCRYPTED_DATA,	offsetof(private_encryption_payload_t, encrypted)		},
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

METHOD(payload_t, verify, status_t,
	private_encryption_payload_t *this)
{
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, void,
	private_encryption_payload_t *this, encoding_rule_t **rules,
	size_t *count)
{
	*rules = encryption_payload_encodings;
	*count = countof(encryption_payload_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_encryption_payload_t *this)
{
	return ENCRYPTED;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_encryption_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_encryption_payload_t *this, payload_type_t type)
{
	/* the next payload is set during add */
}

/**
 * Compute the lenght of the whole payload
 */
static void compute_length(private_encryption_payload_t *this)
{
	enumerator_t *enumerator;
	payload_t *payload;
	size_t block_size, length = 0;

	enumerator = this->payloads->create_enumerator(this->payloads);
	while (enumerator->enumerate(enumerator, &payload))
	{
		length += payload->get_length(payload);
	}
	enumerator->destroy(enumerator);

	if (this->crypter && this->signer)
	{
		/* append one byte for padding length */
		length++;
		/* append padding */
		block_size = this->crypter->get_block_size(this->crypter);
		length += block_size - length % block_size;
		/* add iv */
		length += this->crypter->get_iv_size(this->crypter);
		/* add signature */
		length += this->signer->get_block_size(this->signer);
	}
	length += ENCRYPTION_PAYLOAD_HEADER_LENGTH;
	this->payload_length = length;
}

METHOD(payload_t, get_length, size_t,
	private_encryption_payload_t *this)
{
	compute_length(this);
	return this->payload_length;
}

METHOD(encryption_payload_t, create_payload_iterator, iterator_t*,
	private_encryption_payload_t *this, bool forward)
{
	return this->payloads->create_iterator(this->payloads, forward);
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

METHOD(encryption_payload_t, remove_first_payload, status_t,
	private_encryption_payload_t *this, payload_t **payload)
{
	return this->payloads->remove_first(this->payloads, (void**)payload);
}

METHOD(encryption_payload_t, get_payload_count, size_t,
	private_encryption_payload_t *this)
{
	return this->payloads->get_count(this->payloads);
}

/**
 * Generate payload before encryption.
 */
static void generate(private_encryption_payload_t *this)
{
	payload_t *current, *next;
	generator_t *generator;
	enumerator_t *enumerator;

	compute_length(this);
	chunk_free(&this->decrypted);

	enumerator = this->payloads->create_enumerator(this->payloads);
	if (enumerator->enumerate(enumerator, &current))
	{
		this->next_payload = current->get_type(current);

		generator = generator_create();
		while (enumerator->enumerate(enumerator, &next))
		{
			current->set_next_type(current, next->get_type(next));
			generator->generate_payload(generator, current);
			current = next;
		}
		enumerator->destroy(enumerator);
		current->set_next_type(current, NO_PAYLOAD);
		generator->generate_payload(generator, current);

		generator->write_to_chunk(generator, &this->decrypted);
		generator->destroy(generator);
		DBG2(DBG_ENC, "generated content in encryption payload");
	}
	else
	{
		DBG2(DBG_ENC, "generating contained payloads, but none available");
	}
	enumerator->destroy(enumerator);
}

METHOD(encryption_payload_t, encrypt, status_t,
	private_encryption_payload_t *this)
{
	chunk_t iv, padding, to_crypt, result;
	rng_t *rng;
	size_t block_size;

	if (this->signer == NULL || this->crypter == NULL)
	{
		DBG1(DBG_ENC, "could not encrypt, signer/crypter not set");
		return INVALID_STATE;
	}

	/* for random data in iv and padding */
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_ENC, "could not encrypt, no RNG found");
		return FAILED;
	}
	/* build payload chunk */
	generate(this);

	DBG2(DBG_ENC, "encrypting payloads");
	DBG3(DBG_ENC, "data to encrypt %B", &this->decrypted);

	/* build padding */
	block_size = this->crypter->get_block_size(this->crypter);
	padding.len = block_size - ((this->decrypted.len + 1) %  block_size);
	rng->allocate_bytes(rng, padding.len, &padding);

	/* concatenate payload data, padding, padding len */
	to_crypt.len = this->decrypted.len + padding.len + 1;
	to_crypt.ptr = malloc(to_crypt.len);

	memcpy(to_crypt.ptr, this->decrypted.ptr, this->decrypted.len);
	memcpy(to_crypt.ptr + this->decrypted.len, padding.ptr, padding.len);
	*(to_crypt.ptr + to_crypt.len - 1) = padding.len;

	/* build iv */
	iv.len = this->crypter->get_iv_size(this->crypter);
	rng->allocate_bytes(rng, iv.len, &iv);
	rng->destroy(rng);

	DBG3(DBG_ENC, "data before encryption with padding %B", &to_crypt);

	/* encrypt to_crypt chunk */
	free(this->encrypted.ptr);
	this->crypter->encrypt(this->crypter, to_crypt, iv, &result);
	free(padding.ptr);
	free(to_crypt.ptr);

	DBG3(DBG_ENC, "data after encryption %B", &result);

	/* build encrypted result with iv and signature */
	this->encrypted.len = iv.len + result.len + this->signer->get_block_size(this->signer);
	free(this->encrypted.ptr);
	this->encrypted.ptr = malloc(this->encrypted.len);

	/* fill in result, signature is left out */
	memcpy(this->encrypted.ptr, iv.ptr, iv.len);
	memcpy(this->encrypted.ptr + iv.len, result.ptr, result.len);

	free(result.ptr);
	free(iv.ptr);
	DBG3(DBG_ENC, "data after encryption with IV and (invalid) signature %B",
		 &this->encrypted);

	return SUCCESS;
}

/**
 * Parse the payloads after decryption.
 */
static status_t parse(private_encryption_payload_t *this)
{
	parser_t *parser;
	status_t status;
	payload_type_t type;

	parser = parser_create(this->decrypted);
	type = this->next_payload;
	while (type != NO_PAYLOAD)
	{
		payload_t *payload;

		status = parser->parse_payload(parser, type, &payload);
		if (status != SUCCESS)
		{
			parser->destroy(parser);
			return PARSE_ERROR;
		}
		status = payload->verify(payload);
		if (status != SUCCESS)
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
	private_encryption_payload_t *this)
{
	chunk_t iv, concatenated;
	u_int8_t padding_length;

	DBG2(DBG_ENC, "decrypting encryption payload");
	DBG3(DBG_ENC, "data before decryption with IV and (invalid) signature %B",
		 &this->encrypted);

	if (this->signer == NULL || this->crypter == NULL)
	{
		DBG1(DBG_ENC, "could not decrypt, no crypter/signer set");
		return INVALID_STATE;
	}

	/* get IV */
	iv.len = this->crypter->get_iv_size(this->crypter);
	if (iv.len > this->encrypted.len)
	{
		DBG1(DBG_ENC, "could not decrypt, input too short");
		return FAILED;
	}
	iv.ptr = this->encrypted.ptr;

	/* point concatenated to data + padding + padding_length */
	concatenated.ptr = this->encrypted.ptr + iv.len;
	concatenated.len = this->encrypted.len - iv.len -
								this->signer->get_block_size(this->signer);

	/* concatenated must be a multiple of block_size of crypter */
	if (concatenated.len < iv.len ||
		concatenated.len % this->crypter->get_block_size(this->crypter))
	{
		DBG1(DBG_ENC, "could not decrypt, invalid input");
		return FAILED;
	}

	/* free previus data, if any */
	free(this->decrypted.ptr);

	DBG3(DBG_ENC, "data before decryption %B", &concatenated);

	this->crypter->decrypt(this->crypter, concatenated, iv, &this->decrypted);

	DBG3(DBG_ENC, "data after decryption with padding %B", &this->decrypted);

	/* get padding length, sits just bevore signature */
	padding_length = *(this->decrypted.ptr + this->decrypted.len - 1);
	/* add one byte to the padding length, since the padding_length field is
	 * not included */
	padding_length++;

	/* check size again */
	if (padding_length > concatenated.len || padding_length > this->decrypted.len)
	{
		DBG1(DBG_ENC, "decryption failed, invalid padding length found. Invalid key?");
		/* decryption failed :-/ */
		return FAILED;
	}
	this->decrypted.len -= padding_length;

	/* free padding */
	this->decrypted.ptr = realloc(this->decrypted.ptr, this->decrypted.len);
	DBG3(DBG_ENC, "data after decryption without padding %B", &this->decrypted);
	DBG2(DBG_ENC, "decryption successful, trying to parse content");
	return parse(this);
}

METHOD(encryption_payload_t, set_transforms, void,
	private_encryption_payload_t *this, crypter_t* crypter, signer_t* signer)
{
	this->signer = signer;
	this->crypter = crypter;
}

METHOD(encryption_payload_t, build_signature, status_t,
	private_encryption_payload_t *this, chunk_t data)
{
	chunk_t data_without_sig = data;
	chunk_t sig;

	if (this->signer == NULL)
	{
		DBG1(DBG_ENC, "unable to build signature, no signer set");
		return INVALID_STATE;
	}

	sig.len = this->signer->get_block_size(this->signer);
	data_without_sig.len -= sig.len;
	sig.ptr = data.ptr + data_without_sig.len;
	DBG2(DBG_ENC, "building signature");
	this->signer->get_signature(this->signer, data_without_sig, sig.ptr);
	return SUCCESS;
}

METHOD(encryption_payload_t, verify_signature, status_t,
	private_encryption_payload_t *this, chunk_t data)
{
	chunk_t sig, data_without_sig;
	bool valid;

	if (this->signer == NULL)
	{
		DBG1(DBG_ENC, "unable to verify signature, no signer set");
		return INVALID_STATE;
	}
	/* find signature in data chunk */
	sig.len = this->signer->get_block_size(this->signer);
	if (data.len <= sig.len)
	{
		DBG1(DBG_ENC, "unable to verify signature, invalid input");
		return FAILED;
	}
	sig.ptr = data.ptr + data.len - sig.len;

	/* verify it */
	data_without_sig.len = data.len - sig.len;
	data_without_sig.ptr = data.ptr;
	valid = this->signer->verify_signature(this->signer, data_without_sig, sig);

	if (!valid)
	{
		DBG1(DBG_ENC, "signature verification failed");
		return FAILED;
	}

	DBG2(DBG_ENC, "signature verification successful");
	return SUCCESS;
}

METHOD2(payload_t, encryption_payload_t, destroy, void,
	private_encryption_payload_t *this)
{
	this->payloads->destroy_offset(this->payloads, offsetof(payload_t, destroy));
	free(this->encrypted.ptr);
	free(this->decrypted.ptr);
	free(this);
}

/*
 * Described in header
 */
encryption_payload_t *encryption_payload_create()
{
	private_encryption_payload_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.create_payload_iterator = _create_payload_iterator,
			.add_payload = _add_payload,
			.remove_first_payload = _remove_first_payload,
			.get_payload_count = _get_payload_count,
			.encrypt = _encrypt,
			.decrypt = _decrypt,
			.set_transforms = _set_transforms,
			.build_signature = _build_signature,
			.verify_signature = _verify_signature,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payload_length = ENCRYPTION_PAYLOAD_HEADER_LENGTH,
		.payloads = linked_list_create(),
	);

	return &this->public;
}
