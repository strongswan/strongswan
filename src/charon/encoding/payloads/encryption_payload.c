/**
 * @file encryption_payload.c
 * 
 * @brief Implementation of encryption_payload_t.
 * 
 */

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
#include <utils/logger.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <utils/iterator.h>
#include <utils/randomizer.h>
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
	
	/** 
	 * logger for this payload, uses MESSAGE context
	 */
	logger_t *logger;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_encryption_payload_t object
	 */
	void (*compute_length) (private_encryption_payload_t *this);
	
	/**
	 * @brief Generate payloads (unencrypted) in chunk decrypted.
	 * 
	 * @param this 	calling private_encryption_payload_t object
	 */
	void (*generate) (private_encryption_payload_t *this);
		
	/**
	 * @brief Parse payloads from a (unencrypted) chunk.
	 * 
	 * @param this 	calling private_encryption_payload_t object
	 */
	status_t (*parse) (private_encryption_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-Encryption Payload.
 * 
 * The defined offsets are the positions in a object of type 
 * private_encryption_payload_t.
 * 
 */
encoding_rule_t encryption_payload_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_encryption_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_encryption_payload_t, critical) 		},
	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,		0 														},
	{ RESERVED_BIT,		0 														},
	{ RESERVED_BIT,		0 														},
	{ RESERVED_BIT,		0 														},
	{ RESERVED_BIT,		0 														},
	{ RESERVED_BIT,		0 														},
	{ RESERVED_BIT,		0 														},
	/* Length of the whole encryption payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_encryption_payload_t, payload_length) 	},
	/* encrypted data, stored in a chunk. contains iv, data, padding */
	{ ENCRYPTED_DATA,	offsetof(private_encryption_payload_t, encrypted)			},
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
 * Implementation of payload_t.verify.
 */
static status_t verify(private_encryption_payload_t *this)
{
	return SUCCESS;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_encryption_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = encryption_payload_encodings;
	*rule_count = sizeof(encryption_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_encryption_payload_t *this)
{
	return ENCRYPTED;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_encryption_payload_t *this)
{
	/* returns first contained payload here */
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_encryption_payload_t *this, payload_type_t type)
{
	/* set next type is not allowed, since this payload MUST be the last one 
	 * and so nothing is done in here*/
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_encryption_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implementation of payload_t.create_payload_iterator.
 */
static  iterator_t *create_payload_iterator (private_encryption_payload_t *this, bool forward)
{
	return (this->payloads->create_iterator(this->payloads, forward));
}

/**
 * Implementation of payload_t.add_payload.
 */
static void add_payload(private_encryption_payload_t *this, payload_t *payload)
{
	payload_t *last_payload;
	if (this->payloads->get_count(this->payloads) > 0)
	{
		this->payloads->get_last(this->payloads,(void **) &last_payload);
		last_payload->set_next_type(last_payload, payload->get_type(payload));
	}
	else
	{
		this->next_payload = payload->get_type(payload);
	}
	payload->set_next_type(payload, NO_PAYLOAD);
	this->payloads->insert_last(this->payloads, (void*)payload);
	this->compute_length(this);
}

/**
 * Implementation of encryption_payload_t.remove_first_payload.
 */
static status_t remove_first_payload(private_encryption_payload_t *this, payload_t **payload)
{
	return this->payloads->remove_first(this->payloads, (void**)payload);
}

/**
 * Implementation of encryption_payload_t.get_payload_count.
 */
static size_t get_payload_count(private_encryption_payload_t *this)
{
	return this->payloads->get_count(this->payloads);
}


/**
 * Implementation of encryption_payload_t.encrypt.
 */
static status_t encrypt(private_encryption_payload_t *this)
{
	chunk_t iv, padding, to_crypt, result;
	randomizer_t *randomizer;
	status_t status;
	size_t block_size;
	
	if (this->signer == NULL || this->crypter == NULL)
	{
		this->logger->log(this->logger, ERROR, "could not encrypt, signer/crypter not set");
		return INVALID_STATE;
	}
	
	/* for random data in iv and padding */
	randomizer = randomizer_create();


	/* build payload chunk */
	this->generate(this);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "encrypting payloads");
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data to encrypt", this->decrypted);
	
	/* build padding */
	block_size = this->crypter->get_block_size(this->crypter);
	padding.len = block_size - ((this->decrypted.len + 1) %  block_size);
	status = randomizer->allocate_pseudo_random_bytes(randomizer, padding.len, &padding);
	if (status != SUCCESS)
	{
		randomizer->destroy(randomizer);
		return status;
	}
	
	/* concatenate payload data, padding, padding len */
	to_crypt.len = this->decrypted.len + padding.len + 1;
	to_crypt.ptr = malloc(to_crypt.len);

	memcpy(to_crypt.ptr, this->decrypted.ptr, this->decrypted.len);
	memcpy(to_crypt.ptr + this->decrypted.len, padding.ptr, padding.len);
	*(to_crypt.ptr + to_crypt.len - 1) = padding.len;
		
	/* build iv */
	iv.len = block_size;
	status = randomizer->allocate_pseudo_random_bytes(randomizer, iv.len, &iv);
	randomizer->destroy(randomizer);
	if (status != SUCCESS)
	{
		chunk_free(&to_crypt);
		chunk_free(&padding);
		return status;
	}
	
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data before encryption with padding", to_crypt);
		
	/* encrypt to_crypt chunk */
	free(this->encrypted.ptr);
	status = this->crypter->encrypt(this->crypter, to_crypt, iv, &result);
	free(padding.ptr);
	free(to_crypt.ptr);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "encryption failed");
		free(iv.ptr);
		return status;
	}
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data after encryption", result);
	
	
	/* build encrypted result with iv and signature */
	this->encrypted.len = iv.len + result.len + this->signer->get_block_size(this->signer);
	free(this->encrypted.ptr);
	this->encrypted.ptr = malloc(this->encrypted.len);
	
	/* fill in result, signature is left out */
	memcpy(this->encrypted.ptr, iv.ptr, iv.len);
	memcpy(this->encrypted.ptr + iv.len, result.ptr, result.len);
	
	free(result.ptr);
	free(iv.ptr);
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data after encryption with IV and (invalid) signature", this->encrypted);
	
	return SUCCESS;
}

/**
 * Implementation of encryption_payload_t.encrypt.
 */
static status_t decrypt(private_encryption_payload_t *this)
{
	chunk_t iv, concatenated;
	u_int8_t padding_length;
	status_t status;
	
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "decrypting encryption payload");
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data before decryption with IV and (invalid) signature", this->encrypted);
	
	
	if (this->signer == NULL || this->crypter == NULL)
	{
		this->logger->log(this->logger, ERROR, "could not decrypt, no crypter/signer set");
		return INVALID_STATE;
	}
	
	/* get IV */
	iv.len = this->crypter->get_block_size(this->crypter);
	
	iv.ptr = this->encrypted.ptr;
	
	/* point concatenated to data + padding + padding_length*/
	concatenated.ptr = this->encrypted.ptr + iv.len;
	concatenated.len = this->encrypted.len - iv.len - this->signer->get_block_size(this->signer);
		
	/* check the size of input:
	 * concatenated  must be at least on block_size of crypter
	 */
	if (concatenated.len < iv.len)
	{
		this->logger->log(this->logger, ERROR, "could not decrypt, invalid input");
		return FAILED;
	}
	
	/* free previus data, if any */
	free(this->decrypted.ptr);
	
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data before decryption", concatenated);
	
	status = this->crypter->decrypt(this->crypter, concatenated, iv, &(this->decrypted));
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "could not decrypt, decryption failed");
		return FAILED;
	}
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data after decryption with padding", this->decrypted);
	
	
	/* get padding length, sits just bevore signature */
	padding_length = *(this->decrypted.ptr + this->decrypted.len - 1);
	/* add one byte to the padding length, since the padding_length field is not included */
	padding_length++;
	this->decrypted.len -= padding_length;
	
	/* check size again */
	if (padding_length > concatenated.len || this->decrypted.len < 0)
	{
		this->logger->log(this->logger, ERROR, "decryption failed, invalid padding length found. Invalid key?");
		/* decryption failed :-/ */
		return FAILED;
	}
	
	/* free padding */
	this->decrypted.ptr = realloc(this->decrypted.ptr, this->decrypted.len);
	this->logger->log_chunk(this->logger, RAW|LEVEL2, "data after decryption without padding", this->decrypted);
	this->logger->log(this->logger, CONTROL|LEVEL2, "decryption successful, trying to parse content");
	return (this->parse(this));
}

/**
 * Implementation of encryption_payload_t.set_transforms.
 */
static void set_transforms(private_encryption_payload_t *this, crypter_t* crypter, signer_t* signer)
{
	this->signer = signer;
	this->crypter = crypter;
}

/**
 * Implementation of encryption_payload_t.build_signature.
 */
static status_t build_signature(private_encryption_payload_t *this, chunk_t data)
{
	chunk_t data_without_sig = data;
	chunk_t sig;
	
	if (this->signer == NULL)
	{
		this->logger->log(this->logger, ERROR, "unable to build signature, no signer set");
		return INVALID_STATE;
	}
	
	sig.len = this->signer->get_block_size(this->signer);
	data_without_sig.len -= sig.len;
	sig.ptr = data.ptr + data_without_sig.len;
	this->logger->log(this->logger, CONTROL|LEVEL2, "building signature");
	this->signer->get_signature(this->signer, data_without_sig, sig.ptr);
	return SUCCESS;
}

/**
 * Implementation of encryption_payload_t.verify_signature.
 */
static status_t verify_signature(private_encryption_payload_t *this, chunk_t data)
{
	chunk_t sig, data_without_sig;
	bool valid;
	
	if (this->signer == NULL)
	{
		this->logger->log(this->logger, ERROR, "unable to verify signature, no signer set");
		return INVALID_STATE;
	}
	/* find signature in data chunk */
	sig.len = this->signer->get_block_size(this->signer);
	if (data.len <= sig.len)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "unable to verify signature, invalid input");
		return FAILED;
	}
	sig.ptr = data.ptr + data.len - sig.len;
	
	/* verify it */
	data_without_sig.len = data.len - sig.len;
	data_without_sig.ptr = data.ptr;
	valid = this->signer->verify_signature(this->signer, data_without_sig, sig);
	
	if (!valid)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "signature verification failed");
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "signature verification successful");
	return SUCCESS;
}

/**
 * Implementation of private_encryption_payload_t.generate.
 */
static void generate(private_encryption_payload_t *this)
{
	payload_t *current_payload, *next_payload;
	generator_t *generator;
	iterator_t *iterator;
	
	/* recalculate length before generating */
	this->compute_length(this);
	
	/* create iterator */
	iterator = this->payloads->create_iterator(this->payloads, TRUE);
	
	/* get first payload */
	if (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_payload);
		this->next_payload = current_payload->get_type(current_payload);
	}
	else
	{
		/* no paylads? */
		this->logger->log(this->logger, CONTROL|LEVEL1, "generating contained payloads, but no available");
		free(this->decrypted.ptr);
		this->decrypted = CHUNK_INITIALIZER;
		iterator->destroy(iterator);
		return;
	}
	
	generator = generator_create();
	
	/* build all payload, except last */
	while(iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&next_payload);
		current_payload->set_next_type(current_payload, next_payload->get_type(next_payload));
		generator->generate_payload(generator, current_payload);
		current_payload = next_payload;
	}
	iterator->destroy(iterator);
	
	/* build last payload */
	current_payload->set_next_type(current_payload, NO_PAYLOAD);
	generator->generate_payload(generator, current_payload);
	
	/* free already generated data */
	free(this->decrypted.ptr);
	
	generator->write_to_chunk(generator, &(this->decrypted));
	generator->destroy(generator);
	this->logger->log(this->logger, CONTROL|LEVEL1, "successfully generated content in encrpytion payload");
}

/**
 * Implementation of private_encryption_payload_t.parse.
 */
static status_t parse(private_encryption_payload_t *this)
{
	parser_t *parser;
	status_t status;
	payload_type_t current_payload_type;
	
	/* build a parser on the decrypted data */
	parser = parser_create(this->decrypted);
	
	current_payload_type = this->next_payload;
	/* parse all payloads */
	while (current_payload_type != NO_PAYLOAD)
	{
		payload_t *current_payload;	
		
		status = parser->parse_payload(parser, current_payload_type, (payload_t**)&current_payload);
		if (status != SUCCESS)
		{
			parser->destroy(parser);
			return PARSE_ERROR;
		}

		status = current_payload->verify(current_payload);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "%s verification failed", 
								mapping_find(payload_type_m,current_payload->get_type(current_payload)));
			current_payload->destroy(current_payload);
			parser->destroy(parser);
			return VERIFY_ERROR;
		}

		/* get next payload type */
		current_payload_type = current_payload->get_next_type(current_payload);
		
		this->payloads->insert_last(this->payloads,current_payload);
	}
	parser->destroy(parser);
	this->logger->log(this->logger, CONTROL|LEVEL1, "succesfully parsed content of encryption payload");
	return SUCCESS;
}

/**
 * Implementation of private_encryption_payload_t.compute_length.
 */
static void compute_length(private_encryption_payload_t *this)
{
	iterator_t *iterator;
	size_t block_size, length = 0;
	iterator = this->payloads->create_iterator(this->payloads, TRUE);

	/* count payload length */
	while (iterator->has_next(iterator))
	{
		payload_t *current_payload;
		iterator->current(iterator, (void **) &current_payload);
		length += current_payload->get_length(current_payload);
	}
	iterator->destroy(iterator);
	
	if (this->crypter && this->signer)
	{
		/* append one byte for padding length */
		length++;
		/* append padding */
		block_size = this->crypter->get_block_size(this->crypter);
		length += block_size - length % block_size;
		/* add iv */
		length += block_size;
		/* add signature */
		length += this->signer->get_block_size(this->signer);
	}
	length += ENCRYPTION_PAYLOAD_HEADER_LENGTH;
	this->payload_length = length;
}


/**
 * Implementation of payload_t.destroy.
 */
static void destroy(private_encryption_payload_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->payloads->get_count(this->payloads) > 0)
	{
		payload_t *current_payload;
		this->payloads->remove_last(this->payloads,(void **)&current_payload);
		current_payload->destroy(current_payload);
	}
	this->payloads->destroy(this->payloads);
	free(this->encrypted.ptr);
	free(this->decrypted.ptr);
	free(this);
}

/*
 * Described in header
 */
encryption_payload_t *encryption_payload_create()
{
	private_encryption_payload_t *this = malloc_thing(private_encryption_payload_t);
	
	/* payload_t interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.create_payload_iterator = (iterator_t * (*) (encryption_payload_t *,bool)) create_payload_iterator;
	this->public.add_payload = (void (*) (encryption_payload_t *,payload_t *)) add_payload;
	this->public.remove_first_payload = (status_t (*)(encryption_payload_t*, payload_t **)) remove_first_payload;
	this->public.get_payload_count = (size_t (*)(encryption_payload_t*)) get_payload_count;
	
	this->public.encrypt = (status_t (*) (encryption_payload_t *)) encrypt;
	this->public.decrypt = (status_t (*) (encryption_payload_t *)) decrypt;
	this->public.set_transforms = (void (*) (encryption_payload_t*,crypter_t*,signer_t*)) set_transforms;
	this->public.build_signature = (status_t (*) (encryption_payload_t*, chunk_t)) build_signature;
	this->public.verify_signature = (status_t (*) (encryption_payload_t*, chunk_t)) verify_signature;
	this->public.destroy = (void (*) (encryption_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	this->generate = generate;
	this->parse = parse;
	this->logger = logger_manager->get_logger(logger_manager, ENCRYPTION_PAYLOAD);
	
	/* set default values of the fields */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = ENCRYPTION_PAYLOAD_HEADER_LENGTH;
	this->encrypted = CHUNK_INITIALIZER;
	this->decrypted = CHUNK_INITIALIZER;
	this->signer = NULL;
	this->crypter = NULL;
	this->payloads = linked_list_create();
	
	return (&(this->public));
}
