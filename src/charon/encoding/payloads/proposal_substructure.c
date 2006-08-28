/**
 * @file proposal_substructure.h
 * 
 * @brief Implementation of proposal_substructure_t.
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

#include "proposal_substructure.h"

#include <encoding/payloads/encodings.h>
#include <encoding/payloads/transform_substructure.h>
#include <types.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>


/**
 * IKEv1 Value for a proposal payload.
 */
#define PROPOSAL_TYPE_VALUE 2


typedef struct private_proposal_substructure_t private_proposal_substructure_t;

/**
 * Private data of an proposal_substructure_t object.
 * 
 */
struct private_proposal_substructure_t {
	/**
	 * Public proposal_substructure_t interface.
	 */
	proposal_substructure_t public;
	
	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Length of this payload.
	 */
	u_int16_t proposal_length;
	
	/**
	 * Proposal number.
	 */
	u_int8_t proposal_number;
	
	/**
	 * Protocol ID.
	 */
	u_int8_t protocol_id;

	/**
	 * SPI size of the following SPI.
	 */
 	u_int8_t  spi_size;

	/**
	 * Number of transforms.
	 */
 	u_int8_t  transforms_count;
 	
 	/**
 	 * SPI is stored as chunk.
 	 */
 	chunk_t spi;
 	
 	/**
 	 * Transforms are stored in a linked_list_t.
 	 */
	linked_list_t * transforms;
	
	/**
	 * assigned logger
	 */
	logger_t *logger;
	
	/**
	 * @brief Computes the length of this substructure.
	 *
	 * @param this 	calling private_proposal_substructure_t object
	 */
	void (*compute_length) (private_proposal_substructure_t *this);
};

/**
 * Encoding rules to parse or generate a Proposal substructure.
 *
 * The defined offsets are the positions in a object of type 
 * private_proposal_substructure_t.
 */
encoding_rule_t proposal_substructure_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_proposal_substructure_t, next_payload) 		},
	/* Reserved Byte is skipped */
	{ RESERVED_BYTE,		0															},
	/* Length of the whole proposal substructure payload*/
	{ PAYLOAD_LENGTH,		offsetof(private_proposal_substructure_t, proposal_length) 	},
	/* proposal number is a number of 8 bit */
	{ U_INT_8,				offsetof(private_proposal_substructure_t, proposal_number) 	},
	/* protocol ID is a number of 8 bit */
	{ U_INT_8,				offsetof(private_proposal_substructure_t, protocol_id)		},
	/* SPI Size has its own type */
	{ SPI_SIZE,				offsetof(private_proposal_substructure_t, spi_size)			},
	/* Number of transforms is a number of 8 bit */
	{ U_INT_8,				offsetof(private_proposal_substructure_t, transforms_count)	},
	/* SPI is a chunk of variable size*/
	{ SPI,					offsetof(private_proposal_substructure_t, spi)				},
	/* Transforms are stored in a transform substructure, 
	   offset points to a linked_list_t pointer */
	{ TRANSFORMS,			offsetof(private_proposal_substructure_t, transforms) 		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 2 !   RESERVED    !         Proposal Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Proposal #    !  Protocol ID  !    SPI Size   !# of Transforms!
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ~                        SPI (variable)                         ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                        <Transforms>                           ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_proposal_substructure_t *this)
{
	status_t status = SUCCESS;
	iterator_t *iterator;
	
	if ((this->next_payload != NO_PAYLOAD) && (this->next_payload != 2))
	{
		/* must be 0 or 2 */
		this->logger->log(this->logger, ERROR, "inconsistent next payload");
		return FAILED;
	}
	if (this->transforms_count != this->transforms->get_count(this->transforms))
	{
		/* must be the same! */
		this->logger->log(this->logger, ERROR, "transform count invalid");
		return FAILED;
	}

	switch (this->protocol_id)
	{
		case PROTO_AH:
		case PROTO_ESP:
			if (this->spi.len != 4)
			{
				this->logger->log(this->logger, ERROR, 
								  "invalid SPI length in %s proposal",
								  mapping_find(protocol_id_m, this->protocol_id));
				return FAILED;
			}
			break;
		case PROTO_IKE:
			if (this->spi.len != 0 && this->spi.len  != 8)
			{
				this->logger->log(this->logger, ERROR, 
								  "invalid SPI length in IKE proposal");
				return FAILED;
			}
			break;
		default:
			this->logger->log(this->logger, ERROR, 
							  "invalid proposal protocol (%d)", this->protocol_id);
			return FAILED;
	}
	if ((this->protocol_id == 0) || (this->protocol_id >= 4))
	{
		/* reserved are not supported */
		this->logger->log(this->logger, ERROR, "invalid protocol");
		return FAILED;
	}
	
	iterator = this->transforms->create_iterator(this->transforms,TRUE);
	while(iterator->has_next(iterator))
	{
		payload_t *current_transform;
		iterator->current(iterator,(void **)&current_transform);
		
		status = current_transform->verify(current_transform);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "TRANSFORM_SUBSTRUCTURE verification failed");
			break;
		}
	}
	iterator->destroy(iterator);
	
	/* proposal number is checked in SA payload */	
	return status;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_proposal_substructure_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = proposal_substructure_encodings;
	*rule_count = sizeof(proposal_substructure_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_proposal_substructure_t *this)
{
	return PROPOSAL_SUBSTRUCTURE;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_proposal_substructure_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_proposal_substructure_t *this,payload_type_t type)
{
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_proposal_substructure_t *this)
{
	this->compute_length(this);
	return this->proposal_length;
}

/**
 * Implementation of proposal_substructure_t.create_transform_substructure_iterator.
 */
static iterator_t *create_transform_substructure_iterator (private_proposal_substructure_t *this,bool forward)
{
	return (this->transforms->create_iterator(this->transforms,forward));
}

/**
 * Implementation of proposal_substructure_t.add_transform_substructure.
 */
static void add_transform_substructure (private_proposal_substructure_t *this,transform_substructure_t *transform)
{
	status_t status;
	if (this->transforms->get_count(this->transforms) > 0)
	{
		transform_substructure_t *last_transform;
		status = this->transforms->get_last(this->transforms,(void **) &last_transform);
		/* last transform is now not anymore last one */
		last_transform->set_is_last_transform(last_transform,FALSE);

	}
	transform->set_is_last_transform(transform,TRUE);
	
	this->transforms->insert_last(this->transforms,(void *) transform);
	this->compute_length(this);
}

/**
 * Implementation of proposal_substructure_t.proposal_substructure_t.
 */
static void set_is_last_proposal (private_proposal_substructure_t *this, bool is_last)
{
	this->next_payload = (is_last) ? 0: PROPOSAL_TYPE_VALUE;
}

/**
 * Implementation of proposal_substructure_t.set_proposal_number.
 */
static void set_proposal_number(private_proposal_substructure_t *this,u_int8_t proposal_number)
{
	this->proposal_number = proposal_number;
}

/**
 * Implementation of proposal_substructure_t.get_proposal_number.
 */
static u_int8_t get_proposal_number (private_proposal_substructure_t *this)
{
	return (this->proposal_number);
}

/**
 * Implementation of proposal_substructure_t.set_protocol_id.
 */
static void set_protocol_id(private_proposal_substructure_t *this,u_int8_t protocol_id)
{
	this->protocol_id = protocol_id;
}

/**
 * Implementation of proposal_substructure_t.get_protocol_id.
 */
static u_int8_t get_protocol_id(private_proposal_substructure_t *this)
{
	return (this->protocol_id);
}

/**
 * Implementation of proposal_substructure_t.set_spi.
 */
static void set_spi(private_proposal_substructure_t *this, chunk_t spi)
{
	/* first delete already set spi value */
	if (this->spi.ptr != NULL)
	{
		free(this->spi.ptr);
		this->spi.ptr = NULL;
		this->spi.len = 0;
		this->compute_length(this);
	}
	
	this->spi.ptr = clalloc(spi.ptr,spi.len);
	this->spi.len = spi.len;
	this->spi_size = spi.len;
	this->compute_length(this);
}

/**
 * Implementation of proposal_substructure_t.get_spi.
 */
static chunk_t get_spi(private_proposal_substructure_t *this)
{
	chunk_t spi;
	spi.ptr = this->spi.ptr;
	spi.len = this->spi.len;
	
	return spi;
}

/**
 * Implementation of private_proposal_substructure_t.compute_length.
 */
static void compute_length(private_proposal_substructure_t *this)
{
	iterator_t *iterator;
	size_t transforms_count = 0;
	size_t length = PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH;
	iterator = this->transforms->create_iterator(this->transforms,TRUE);
	while (iterator->has_next(iterator))
	{
		payload_t * current_transform;
		iterator->current(iterator,(void **) &current_transform);
		length += current_transform->get_length(current_transform);
		transforms_count++;
	}
	iterator->destroy(iterator);
	
	length += this->spi.len;
	this->transforms_count = transforms_count;
	this->proposal_length = length;
}

/**
 * Implementation of proposal_substructure_t.get_transform_count.
 */
static size_t get_transform_count (private_proposal_substructure_t *this)
{
	return this->transforms->get_count(this->transforms);
}

/**
 * Implementation of proposal_substructure_t.get_spi_size.
 */
static size_t get_spi_size (private_proposal_substructure_t *this)
{
	return this->spi.len;
}

/**
 * Implementation of proposal_substructure_t.get_proposal.
 */
proposal_t* get_proposal(private_proposal_substructure_t *this)
{
	iterator_t *iterator;
	proposal_t *proposal;
	u_int64_t spi;
	
	proposal = proposal_create(this->protocol_id);
	
	iterator = this->transforms->create_iterator(this->transforms, TRUE);
	while (iterator->has_next(iterator))
	{
		transform_substructure_t *transform;
		transform_type_t transform_type;
		u_int16_t transform_id;
		u_int16_t key_length = 0;
		
		iterator->current(iterator, (void**)&transform);
		
		transform_type = transform->get_transform_type(transform);
		transform_id = transform->get_transform_id(transform);
		transform->get_key_length(transform, &key_length);
		
		proposal->add_algorithm(proposal, transform_type, transform_id, key_length);
	}
	iterator->destroy(iterator);
	
	switch (this->spi.len)
	{
		case 4:
			spi = *((u_int32_t*)this->spi.ptr);
			break;
		case 8:
			spi = *((u_int64_t*)this->spi.ptr);
			break;
		default:
			spi = 0;
	}
	proposal->set_spi(proposal, spi);
	
	return proposal;
}

/**
 * Implementation of proposal_substructure_t.clone.
 */
static private_proposal_substructure_t* clone_(private_proposal_substructure_t *this)
{
	private_proposal_substructure_t * new_clone;
	iterator_t *transforms;
	
	new_clone = (private_proposal_substructure_t *) proposal_substructure_create();
	
	new_clone->next_payload = this->next_payload;
	new_clone->proposal_number = this->proposal_number;
	new_clone->protocol_id = this->protocol_id;
	new_clone->spi_size = this->spi_size;
	if (this->spi.ptr != NULL)
	{
		new_clone->spi.ptr = clalloc(this->spi.ptr,this->spi.len);
		new_clone->spi.len = this->spi.len;
	}

	transforms = this->transforms->create_iterator(this->transforms,FALSE);

	while (transforms->has_next(transforms))
	{
		transform_substructure_t *current_transform;
		transform_substructure_t *current_transform_clone;

		transforms->current(transforms,(void **) &current_transform);

		current_transform_clone = current_transform->clone(current_transform);
		
		new_clone->public.add_transform_substructure(&(new_clone->public),current_transform_clone);
	}
	
	transforms->destroy(transforms);	
	
	return new_clone;	
}

/**
 * Implements payload_t's and proposal_substructure_t's destroy function.
 * See #payload_s.destroy or proposal_substructure_s.destroy for description.
 */
static status_t destroy(private_proposal_substructure_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->transforms->get_count(this->transforms) > 0)
	{
		transform_substructure_t *current_transform;
		if (this->transforms->remove_last(this->transforms,(void **)&current_transform) != SUCCESS)
		{
			break;
		}
		current_transform->destroy(current_transform);
	}
	this->transforms->destroy(this->transforms);
	
	if (this->spi.ptr != NULL)
	{
		free(this->spi.ptr);
	}
	
	free(this);
	
	return SUCCESS;
}

/*
 * Described in header.
 */
proposal_substructure_t *proposal_substructure_create()
{
	private_proposal_substructure_t *this = malloc_thing(private_proposal_substructure_t);

	/* interface functions */	
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;	
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	
	/* public functions */
	this->public.create_transform_substructure_iterator = (iterator_t* (*) (proposal_substructure_t *,bool)) create_transform_substructure_iterator;
	this->public.add_transform_substructure = (void (*) (proposal_substructure_t *,transform_substructure_t *)) add_transform_substructure;
	this->public.set_proposal_number = (void (*) (proposal_substructure_t *,u_int8_t))set_proposal_number;
	this->public.get_proposal_number = (u_int8_t (*) (proposal_substructure_t *)) get_proposal_number;
	this->public.set_protocol_id = (void (*) (proposal_substructure_t *,u_int8_t))set_protocol_id;
	this->public.get_protocol_id = (u_int8_t (*) (proposal_substructure_t *)) get_protocol_id;
	this->public.set_is_last_proposal = (void (*) (proposal_substructure_t *,bool)) set_is_last_proposal;
	this->public.get_proposal = (proposal_t* (*) (proposal_substructure_t*))get_proposal;
	this->public.set_spi = (void (*) (proposal_substructure_t *,chunk_t))set_spi;
	this->public.get_spi = (chunk_t (*) (proposal_substructure_t *)) get_spi;
	this->public.get_transform_count = (size_t (*) (proposal_substructure_t *)) get_transform_count;
	this->public.get_spi_size = (size_t (*) (proposal_substructure_t *)) get_spi_size;	
	this->public.clone = (proposal_substructure_t * (*) (proposal_substructure_t *)) clone_;
	this->public.destroy = (void (*) (proposal_substructure_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->next_payload = NO_PAYLOAD;
	this->proposal_length = 0;
	this->proposal_number = 0;
	this->protocol_id = 0;
	this->transforms_count = 0;
	this->spi_size = 0;
	this->spi.ptr = NULL;
	this->spi.len = 0;
	this->logger = logger_manager->get_logger(logger_manager, PAYLOAD);
	
	this->transforms = linked_list_create();
	
	return (&(this->public));
}

/*
 * Described in header.
 */
proposal_substructure_t *proposal_substructure_create_from_proposal(proposal_t *proposal)
{
	private_proposal_substructure_t *this = (private_proposal_substructure_t*)proposal_substructure_create();
	iterator_t *iterator;
	algorithm_t *algo;
	transform_substructure_t *transform;
	
	/* encryption algorithm is only availble in ESP */
	iterator = proposal->create_algorithm_iterator(proposal, ENCRYPTION_ALGORITHM);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&algo);
		transform = transform_substructure_create_type(ENCRYPTION_ALGORITHM, algo->algorithm, algo->key_size);
		this->public.add_transform_substructure(&(this->public), transform);
	}
	iterator->destroy(iterator);
	
	/* integrity algorithms */
	iterator = proposal->create_algorithm_iterator(proposal, INTEGRITY_ALGORITHM);
	while (iterator->has_next(iterator))
	{
		algorithm_t *algo;
		iterator->current(iterator, (void**)&algo);
		transform = transform_substructure_create_type(INTEGRITY_ALGORITHM, algo->algorithm, algo->key_size);
		this->public.add_transform_substructure(&(this->public), transform);
	}
	iterator->destroy(iterator);
	
	/* prf algorithms */
	iterator = proposal->create_algorithm_iterator(proposal, PSEUDO_RANDOM_FUNCTION);
	while (iterator->has_next(iterator))
	{
		algorithm_t *algo;
		iterator->current(iterator, (void**)&algo);
		transform = transform_substructure_create_type(PSEUDO_RANDOM_FUNCTION, algo->algorithm, algo->key_size);
		this->public.add_transform_substructure(&(this->public), transform);
	}
	iterator->destroy(iterator);
	
	/* dh groups */
	iterator = proposal->create_algorithm_iterator(proposal, DIFFIE_HELLMAN_GROUP);
	while (iterator->has_next(iterator))
	{
		algorithm_t *algo;
		iterator->current(iterator, (void**)&algo);
		transform = transform_substructure_create_type(DIFFIE_HELLMAN_GROUP, algo->algorithm, 0);
		this->public.add_transform_substructure(&(this->public), transform);
	}
	iterator->destroy(iterator);
	
	/* extended sequence numbers */
	iterator = proposal->create_algorithm_iterator(proposal, EXTENDED_SEQUENCE_NUMBERS);
	while (iterator->has_next(iterator))
	{
		algorithm_t *algo;
		iterator->current(iterator, (void**)&algo);
		transform = transform_substructure_create_type(EXTENDED_SEQUENCE_NUMBERS, algo->algorithm, 0);
		this->public.add_transform_substructure(&(this->public), transform);
	}
	iterator->destroy(iterator);
	
	/* add SPI, if necessary */
	switch (proposal->get_protocol(proposal))
	{
		case PROTO_AH:
		case PROTO_ESP:
			this->spi_size = this->spi.len = 4;
			this->spi.ptr = malloc(this->spi_size);
			*((u_int32_t*)this->spi.ptr) = proposal->get_spi(proposal);
			break;
		case PROTO_IKE:
			if (proposal->get_spi(proposal))
			{	/* IKE only uses SPIS when rekeying, but on initial setup */
				this->spi_size = this->spi.len = 8;
				this->spi.ptr = malloc(this->spi_size);
				*((u_int64_t*)this->spi.ptr) = proposal->get_spi(proposal);
			}
			break;
		default:
			break;
	}
	this->proposal_number = 0;
	this->protocol_id = proposal->get_protocol(proposal);
	
	return &this->public;
}
