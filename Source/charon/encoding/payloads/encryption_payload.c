/**
 * @file encryption_payload.c
 * 
 * @brief Implementation of encryption_payload_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 
/* offsetof macro */
#include <stddef.h>

#include "encryption_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/allocator.h>
#include <utils/linked_list.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <utils/iterator.h>
#include <utils/randomizer.h>
#include <transforms/signers/signer.h>




typedef struct private_encryption_payload_t private_encryption_payload_t;

/**
 * Private data of an encryption_payload_t' Object
 * 
 */
struct private_encryption_payload_t {
	/**
	 * public encryption_payload_t interface
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
	 * Critical flag
	 */
	bool critical;
	
	/**
	 * Length of this payload
	 */
	u_int16_t payload_length;
	
	/**
	 * initialization vector
	 */
	chunk_t iv;
	
	/**
	 * integrity checksum
	 */
	chunk_t checksum;
	
	/**
	 * chunk containing the iv, data, padding,
	 * and (an eventually not calculated) signature
	 */
	chunk_t encrypted;
	
	/**
	 * chunk containing the data in decrypted (unpadded) form
	 */
	chunk_t decrypted;
	
	/**
	 * signer set by set_signer
	 */
	signer_t *signer;
	
	/**
	 * Contained payloads of this encrpytion_payload
	 */
	linked_list_t *payloads;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_encryption_payload_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*compute_length) (private_encryption_payload_t *this);
	
	/**
	 * @brief Generate payloads (unencrypted) in chunk decrypted.
	 * 
	 * @param this 	calling private_encryption_payload_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*generate) (private_encryption_payload_t *this);
	status_t (*parse) (private_encryption_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-Encryption Payload
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
 * Implements payload_t's verify function.
 * See #payload_s.verify for description.
 */
static status_t verify(private_encryption_payload_t *this)
{
// 	int proposal_number = 1;
	status_t status;
// 	iterator_t *iterator;
// 	bool first = TRUE;
// 	
// 	if (this->critical)
// 	{
// 		/* critical bit set! */
// 		return FAILED;
// 	}
// 
// 	/* check proposal numbering */		
// 	status = this->proposals->create_iterator(this->proposals,&iterator,TRUE);
// 	if (status != SUCCESS)
// 	{
// 		return status;
// 	}
// 	
// 	while(iterator->has_next(iterator))
// 	{
// 		proposal_substructure_t *current_proposal;
// 		status = iterator->current(iterator,(void **)&current_proposal);
// 		{
// 			break;
// 		}
// 		if (current_proposal->get_proposal_number(current_proposal) > proposal_number)
// 		{
// 			if (first) 
// 			{
// 				/* first number must be 1 */
// 				status = FAILED;
// 				break;
// 			}
// 			
// 			if (current_proposal->get_proposal_number(current_proposal) != (proposal_number + 1))
// 			{
// 				/* must be only one more then previous proposal */
// 				status = FAILED;
// 				break;
// 			}
// 		}
// 		else if (current_proposal->get_proposal_number(current_proposal) < proposal_number)
// 		{
// 			iterator->destroy(iterator);
// 			/* must not be smaller then proceeding one */
// 			status = FAILED;
// 			break;
// 		}
// 		first = FALSE;
// 	}
// 	
// 	iterator->destroy(iterator);
	return status;
}

/**
 * implements payload_t.destroy
 */
static status_t destroy(private_encryption_payload_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->payloads->get_count(this->payloads) > 0)
	{
		payload_t *current_payload;
		if (this->payloads->remove_last(this->payloads,(void **)&current_payload) != SUCCESS)
		{
			break;
		}
		current_payload->destroy(current_payload);
	}
	this->payloads->destroy(this->payloads);
		
	allocator_free(this->iv.ptr);
	allocator_free(this->encrypted.ptr);
	allocator_free(this->decrypted.ptr);
	allocator_free(this->checksum.ptr);
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * implements payload_t.get_encoding_rules
 */
static status_t get_encoding_rules(private_encryption_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = encryption_payload_encodings;
	*rule_count = sizeof(encryption_payload_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * implements payload_t.get_type
 */
static payload_type_t get_type(private_encryption_payload_t *this)
{
	return ENCRYPTED;
}

/**
 * implements payload_t.get_next_type
 */
static payload_type_t get_next_type(private_encryption_payload_t *this)
{
	/* returns first contained payload here */
	return (this->next_payload);
}

/**
 * implements payload_t.set_next_type
 */
static status_t set_next_type(private_encryption_payload_t *this, payload_type_t type)
{
	/* set next type is not allowed, since this payload MUST be the last one */
	return FAILED;
}

/**
 * implements payload_t.get_length
 */
static size_t get_length(private_encryption_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * implements encryption_payload_t.create_payload_iterator
 */
static status_t create_payload_iterator (private_encryption_payload_t *this, iterator_t **iterator, bool forward)
{
	return (this->payloads->create_iterator(this->payloads, iterator, forward));
}

/**
 * implements encryption_payload_t.add_payload
 */
static status_t add_payload(private_encryption_payload_t *this, payload_t *payload)
{
	payload_t *last_payload;
	if ((this->payloads->get_count(this->payloads) > 0) &&
		(this->payloads->get_last(this->payloads,(void **) &last_payload) != SUCCESS))
	{
		return OUT_OF_RES;	
	}
	
	if (this->payloads->insert_last(this->payloads, payload) != SUCCESS)
	{
		return OUT_OF_RES;	
	}
	if (this->payloads->get_count(this->payloads) == 1)
	{
		this->next_payload = payload->get_type(payload);
	}
	else
	{
		last_payload->set_next_type(last_payload, payload->get_type(payload));
	}
	payload->set_next_type(payload, NO_PAYLOAD);
	this->compute_length(this);
	return SUCCESS;
}

/**
 * implements encryption_payload_t.encrypt
 */
static status_t encrypt(private_encryption_payload_t *this, crypter_t *crypter)
{
	chunk_t iv, padding, concatenated;
	randomizer_t *randomizer;
	status_t status;
	
	if (this->signer == NULL)
	{
		return INVALID_STATE;
	}
	
	/* for random data in iv and padding */
	randomizer = randomizer_create();
	if (randomizer == NULL)
	{
		return OUT_OF_RES;
	}

	/* build payload chunk */
	status = this->generate(this);
	if (status != SUCCESS)
	{
		randomizer->destroy(randomizer);
		return status;
	}
	
	/* build padding */
	padding.len = (this->decrypted.len + 1) % crypter->get_block_size(crypter);
	status = randomizer->allocate_pseudo_random_bytes(randomizer, padding.len, &padding);
	if (status != SUCCESS)
	{
		randomizer->destroy(randomizer);
		return status;
	}
	
	/* concatenate payload data, padding, padding len */
	concatenated.len = this->decrypted.len + padding.len + 1;
	concatenated.ptr = allocator_alloc(concatenated.len);
	if (concatenated.ptr == NULL)
	{
		randomizer->destroy(randomizer);
		allocator_free(padding.ptr);
		return OUT_OF_RES;
	}
	memcpy(concatenated.ptr, this->decrypted.ptr, this->decrypted.len);
	memcpy(concatenated.ptr + this->decrypted.len, padding.ptr, padding.len);
	*(concatenated.ptr + concatenated.len - 1) = padding.len;

		
	/* build iv */
	iv.len = crypter->get_block_size(crypter);
	status = randomizer->allocate_pseudo_random_bytes(randomizer, iv.len, &iv);
	randomizer->destroy(randomizer);
	if (status != SUCCESS)
	{
		allocator_free(padding.ptr);
		allocator_free(concatenated.ptr);
		return status;
	}
		
		
	/* encrypt concatenated chunk */
	allocator_free(this->encrypted.ptr);
	status = crypter->encrypt(crypter, iv, concatenated, &(this->encrypted));
	allocator_free(padding.ptr);
	allocator_free(concatenated.ptr);
	allocator_free(iv.ptr);
	if (status != SUCCESS)
	{
		return status;
	}
	
	/* append an empty signature */
	this->encrypted.len += this->signer->get_block_size(this->signer);
	allocator_realloc(this->encrypted.ptr, this->encrypted.len);
	if (this->encrypted.ptr == NULL)
	{
		return OUT_OF_RES;
	}
	
	return SUCCESS;
}

/**
 * implements encryption_payload_t.decrypt
 */
static status_t decrypt(private_encryption_payload_t *this, crypter_t *crypter)
{
	chunk_t iv, concatenated;
	u_int8_t padding_length;
	status_t status;
	
	if (this->signer == NULL)
	{
		return INVALID_STATE;
	}
	
	/* get IV */
	iv.len = crypter->get_block_size(crypter);
	iv.ptr = this->encrypted.ptr;
	
	/* point concatenated to data + padding + padding_length*/
	concatenated.ptr = this->encrypted.ptr + iv.len;
	concatenated.len = this->encrypted.len - iv.len - this->signer->get_block_size(this->signer);
	
	/* check the size of input:
	 * concatenated  must be at least on block_size of crypter
	 */
	if (concatenated.len < iv.len)
	{
		return FAILED;
	}
	
	/* free previus data, if any */
	allocator_free(this->decrypted.ptr);
	
	status = crypter->decrypt(crypter, iv, concatenated, &(this->decrypted));
	if (status != SUCCESS)
	{
		return FAILED;
	}
	
	/* get padding length, sits just bevore signature */
	padding_length = *(this->decrypted.ptr + this->decrypted.len - 1);
	this->decrypted.len -= padding_length;
	
	/* check size again */
	if (padding_length > concatenated.len || this->decrypted.len < 0)
	{
		/* decryption failed :-/ */
		return FAILED;
	}
	
	/* free padding */
	this->decrypted.ptr = allocator_realloc(this->decrypted.ptr, this->decrypted.len);
	if (this->decrypted.ptr == NULL)
	{
		return OUT_OF_RES;
	}
	
	return SUCCESS;
}

/**
 * implements encryption_payload_t.set_signer
 */
static status_t set_signer(private_encryption_payload_t *this, signer_t* signer)
{
	this->signer = signer;
	return SUCCESS;
}

/**
 * implements encryption_payload_t.build_signature
 */
static status_t build_signature(private_encryption_payload_t *this, chunk_t data)
{
	chunk_t data_without_sig = data;
	chunk_t sig;
	
	if (this->signer == NULL)
	{
		return INVALID_STATE;
	}
	
	sig.len = this->signer->get_block_size(this->signer);
	data_without_sig.len -= sig.len;
	sig.ptr = data.ptr + data_without_sig.len;
	this->signer->get_signature(this->signer, data_without_sig, sig.ptr);
	return SUCCESS;
}

/**
 * implements encryption_payload_t.verify_signature
 */
static status_t verify_signature(private_encryption_payload_t *this, chunk_t data)
{
	chunk_t sig, data_without_sig;
	bool valid;
	
	if (this->signer == NULL)
	{
		return INVALID_STATE;
	}
	/* find signature in data chunk */
	sig.len = this->signer->get_block_size(this->signer);
	if (data.len <= sig.len)
	{
		return FAILED;
	}
	sig.ptr = data.ptr + data.len - sig.len;
	
	/* verify it */
	data_without_sig.len = data.len - sig.len;
	data_without_sig.ptr = data.ptr;
	this->signer->verify_signature(this->signer, data_without_sig, sig, &valid);
	
	if (!valid)
	{
		return FAILED;
	}
	
	return SUCCESS;
}

/**
 * implements private_encryption_payload_t.generate
 */
static status_t generate(private_encryption_payload_t *this)
{
	status_t status;
	payload_t *current_payload, *next_payload;
	generator_t *generator;
	iterator_t *iterator;
	
	/* create iterator */
	status = this->payloads->create_iterator(this->payloads, &iterator, TRUE);
	if (status != SUCCESS)
	{
		return status;
	}
	
	/* get first payload */
	if (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_payload);
		this->next_payload = current_payload->get_type(current_payload);
	}
	else
	{
		/* no paylads? */
		allocator_free(this->decrypted.ptr);
		this->decrypted = CHUNK_INITIALIZER;
		iterator->destroy(iterator);
		return SUCCESS;
	}
	
	generator = generator_create();
	if (generator == NULL)
	{
		iterator->destroy(iterator);
		return OUT_OF_RES;
	}
	
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
	allocator_free(this->decrypted.ptr);
	
	generator->write_to_chunk(generator, &(this->decrypted));
	generator->destroy(generator);
	return SUCCESS;
}

static status_t parse(private_encryption_payload_t *this)
{
	parser_t *parser;
	status_t status;
	payload_type_t current_payload_type;
	
	/* check if there is decrypted data */
	if (this->decrypted.ptr == NULL)
	{
		return INVALID_STATE;
	}
	
	/* build a parser on the decrypted data */
	parser = parser_create(this->decrypted);
	if (parser == NULL)
	{
		return OUT_OF_RES;
	}
	
	
	current_payload_type = this->next_payload;
	/* parse all payloads */
	while (current_payload_type != NO_PAYLOAD)
	{
		payload_t *current_payload;	
		
		status = parser->parse_payload(parser, current_payload_type, (payload_t**)&current_payload);
		if (status != SUCCESS)
		{
			return PARSE_ERROR;
		}
		
		status = current_payload->verify(current_payload);
		if (status != SUCCESS)
		{
			return VERIFY_ERROR;
		}

		/* get next payload type */
		current_payload_type = current_payload->get_next_type(current_payload);
		
		status = this->payloads->insert_last(this->payloads,current_payload);
		if (status != SUCCESS)
		{
			return OUT_OF_RES;	
		}
	}
	return SUCCESS;
}

/**
 * implements private_encryption_payload_t.compute_length
 */
static status_t compute_length(private_encryption_payload_t *this)
{
	iterator_t *iterator;
	status_t status;
	size_t length = ENCRYPTION_PAYLOAD_HEADER_LENGTH;
	status = this->payloads->create_iterator(this->payloads, &iterator, TRUE);
	if (status != SUCCESS)
	{
		return status;
	}
	while (iterator->has_next(iterator))
	{
		payload_t *current_payload;
		iterator->current(iterator, (void **) &current_payload);
		length += current_payload->get_length(current_payload);
	}
	iterator->destroy(iterator);
	
	this->payload_length = length;
		
	return SUCCESS;
}

/*
 * Described in header
 */
encryption_payload_t *encryption_payload_create()
{
	private_encryption_payload_t *this = allocator_alloc_thing(private_encryption_payload_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	/* payload_t interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (status_t (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.create_payload_iterator = (status_t (*) (encryption_payload_t *,iterator_t **,bool)) create_payload_iterator;
	this->public.add_payload = (status_t (*) (encryption_payload_t *,payload_t *)) add_payload;
	this->public.encrypt = (status_t (*) (encryption_payload_t *, crypter_t*)) encrypt;
	this->public.decrypt = (status_t (*) (encryption_payload_t *, crypter_t*)) decrypt;
	this->public.set_signer = (status_t (*) (encryption_payload_t *,signer_t*)) set_signer;
	this->public.build_signature = (status_t (*) (encryption_payload_t*, chunk_t)) build_signature;
	this->public.verify_signature = (status_t (*) (encryption_payload_t*, chunk_t)) verify_signature;
	this->public.destroy = (status_t (*) (encryption_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	this->generate = generate;
	this->parse = parse;
	
	/* set default values of the fields */
	this->critical = TRUE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = ENCRYPTION_PAYLOAD_HEADER_LENGTH;
	this->iv = CHUNK_INITIALIZER;
	this->encrypted = CHUNK_INITIALIZER;
	this->decrypted = CHUNK_INITIALIZER;
	this->checksum = CHUNK_INITIALIZER;
	this->signer = NULL;

	this->payloads = linked_list_create();
	
	if (this->payloads == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	return (&(this->public));
}


