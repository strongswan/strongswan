/*
 * Copyright (C) 2005-2010 Martin Willi
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
#include <library.h>
#include <utils/linked_list.h>
#include <daemon.h>

/**
 * IKEv1 Value for a proposal payload.
 */
#define PROPOSAL_TYPE_VALUE 2

typedef struct private_proposal_substructure_t private_proposal_substructure_t;

/**
 * Private data of an proposal_substructure_t object.
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
	 * reserved byte
	 */
	u_int8_t reserved;

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
};

/**
 * Encoding rules to parse or generate a Proposal substructure.
 *
 * The defined offsets are the positions in a object of type
 * private_proposal_substructure_t.
 */
encoding_rule_t proposal_substructure_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_proposal_substructure_t, next_payload)		},
	/* 1 Reserved Byte */
	{ RESERVED_BYTE,	offsetof(private_proposal_substructure_t, reserved)			},
	/* Length of the whole proposal substructure payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_proposal_substructure_t, proposal_length)	},
	/* proposal number is a number of 8 bit */
	{ U_INT_8,			offsetof(private_proposal_substructure_t, proposal_number)	},
	/* protocol ID is a number of 8 bit */
	{ U_INT_8,			offsetof(private_proposal_substructure_t, protocol_id)		},
	/* SPI Size has its own type */
	{ SPI_SIZE,			offsetof(private_proposal_substructure_t, spi_size)			},
	/* Number of transforms is a number of 8 bit */
	{ U_INT_8,			offsetof(private_proposal_substructure_t, transforms_count)	},
	/* SPI is a chunk of variable size*/
	{ SPI,				offsetof(private_proposal_substructure_t, spi)				},
	/* Transforms are stored in a transform substructure,
	   offset points to a linked_list_t pointer */
	{ TRANSFORMS,		offsetof(private_proposal_substructure_t, transforms)		}
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

METHOD(payload_t, verify, status_t,
	private_proposal_substructure_t *this)
{
	status_t status = SUCCESS;
	enumerator_t *enumerator;
	payload_t *current;

	if (this->next_payload != NO_PAYLOAD && this->next_payload != 2)
	{
		/* must be 0 or 2 */
		DBG1(DBG_ENC, "inconsistent next payload");
		return FAILED;
	}
	if (this->transforms_count != this->transforms->get_count(this->transforms))
	{
		/* must be the same! */
		DBG1(DBG_ENC, "transform count invalid");
		return FAILED;
	}

	switch (this->protocol_id)
	{
		case PROTO_AH:
		case PROTO_ESP:
			if (this->spi.len != 4)
			{
				DBG1(DBG_ENC, "invalid SPI length in %N proposal",
								  protocol_id_names, this->protocol_id);
				return FAILED;
			}
			break;
		case PROTO_IKE:
			if (this->spi.len != 0 && this->spi.len  != 8)
			{
				DBG1(DBG_ENC, "invalid SPI length in IKE proposal");
				return FAILED;
			}
			break;
		default:
			break;
	}
	enumerator = this->transforms->create_enumerator(this->transforms);
	while (enumerator->enumerate(enumerator, &current))
	{
		status = current->verify(current);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "TRANSFORM_SUBSTRUCTURE verification failed");
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* proposal number is checked in SA payload */
	return status;
}

METHOD(payload_t, get_encoding_rules, void,
	private_proposal_substructure_t *this, encoding_rule_t **rules,
	size_t *rule_count)
{
	*rules = proposal_substructure_encodings;
	*rule_count = countof(proposal_substructure_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_proposal_substructure_t *this)
{
	return PROPOSAL_SUBSTRUCTURE;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_proposal_substructure_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_proposal_substructure_t *this, payload_type_t type)
{
}

/**
 * (re-)compute the length of the payload.
 */
static void compute_length(private_proposal_substructure_t *this)
{
	enumerator_t *enumerator;
	payload_t *transform;

	this->transforms_count = 0;
	this->proposal_length = PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH + this->spi.len;
	enumerator = this->transforms->create_enumerator(this->transforms);
	while (enumerator->enumerate(enumerator, &transform))
	{
		this->proposal_length += transform->get_length(transform);
		this->transforms_count++;
	}
	enumerator->destroy(enumerator);
}

METHOD(payload_t, get_length, size_t,
	private_proposal_substructure_t *this)
{
	return this->proposal_length;
}

/**
 * Add a transform substructure to the proposal
 */
static void add_transform_substructure(private_proposal_substructure_t *this,
									   transform_substructure_t *transform)
{
	if (this->transforms->get_count(this->transforms) > 0)
	{
		transform_substructure_t *last;

		this->transforms->get_last(this->transforms, (void **)&last);
		last->set_is_last_transform(last, FALSE);
	}
	transform->set_is_last_transform(transform,TRUE);
	this->transforms->insert_last(this->transforms, transform);
	compute_length(this);
}

METHOD(proposal_substructure_t, set_is_last_proposal, void,
	private_proposal_substructure_t *this, bool is_last)
{
	this->next_payload = is_last ? 0 : PROPOSAL_TYPE_VALUE;
}

METHOD(proposal_substructure_t, set_proposal_number, void,
	private_proposal_substructure_t *this,u_int8_t proposal_number)
{
	this->proposal_number = proposal_number;
}

METHOD(proposal_substructure_t, get_proposal_number, u_int8_t,
	private_proposal_substructure_t *this)
{
	return this->proposal_number;
}

METHOD(proposal_substructure_t, set_protocol_id, void,
	private_proposal_substructure_t *this,u_int8_t protocol_id)
{
	this->protocol_id = protocol_id;
}

METHOD(proposal_substructure_t, get_protocol_id, u_int8_t,
	private_proposal_substructure_t *this)
{
	return this->protocol_id;
}

METHOD(proposal_substructure_t, set_spi, void,
	private_proposal_substructure_t *this, chunk_t spi)
{
	free(this->spi.ptr);
	this->spi = chunk_clone(spi);
	this->spi_size = spi.len;
	compute_length(this);
}

METHOD(proposal_substructure_t, get_spi, chunk_t,
	private_proposal_substructure_t *this)
{
	return this->spi;
}

METHOD(proposal_substructure_t, get_proposal, proposal_t*,
	private_proposal_substructure_t *this)
{
	enumerator_t *enumerator;
	transform_substructure_t *transform;
	proposal_t *proposal;
	u_int64_t spi;

	proposal = proposal_create(this->protocol_id, this->proposal_number);

	enumerator = this->transforms->create_enumerator(this->transforms);
	while (enumerator->enumerate(enumerator, &transform))
	{
		transform_type_t transform_type;
		u_int16_t transform_id;
		u_int16_t key_length = 0;

		transform_type = transform->get_transform_type(transform);
		transform_id = transform->get_transform_id(transform);
		transform->get_key_length(transform, &key_length);

		proposal->add_algorithm(proposal, transform_type, transform_id, key_length);
	}
	enumerator->destroy(enumerator);

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

METHOD(proposal_substructure_t, create_substructure_enumerator, enumerator_t*,
	private_proposal_substructure_t *this)
{
	return this->transforms->create_enumerator(this->transforms);
}

METHOD2(payload_t, proposal_substructure_t, destroy, void,
	private_proposal_substructure_t *this)
{
	this->transforms->destroy_offset(this->transforms,
									 offsetof(transform_substructure_t, destroy));
	chunk_free(&this->spi);
	free(this);
}

/*
 * Described in header.
 */
proposal_substructure_t *proposal_substructure_create()
{
	private_proposal_substructure_t *this;

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
			.set_proposal_number = _set_proposal_number,
			.get_proposal_number = _get_proposal_number,
			.set_protocol_id = _set_protocol_id,
			.get_protocol_id = _get_protocol_id,
			.set_is_last_proposal = _set_is_last_proposal,
			.get_proposal = _get_proposal,
			.create_substructure_enumerator = _create_substructure_enumerator,
			.set_spi = _set_spi,
			.get_spi = _get_spi,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.proposal_length = PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH,
		.transforms = linked_list_create(),
	);

	return &this->public;
}

/*
 * Described in header.
 */
proposal_substructure_t *proposal_substructure_create_from_proposal(
														proposal_t *proposal)
{
	transform_substructure_t *transform;
	private_proposal_substructure_t *this;
	u_int16_t alg, key_size;
	enumerator_t *enumerator;

	this = (private_proposal_substructure_t*)proposal_substructure_create();

	/* encryption algorithm is only available in ESP */
	enumerator = proposal->create_enumerator(proposal, ENCRYPTION_ALGORITHM);
	while (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(ENCRYPTION_ALGORITHM,
													   alg, key_size);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* integrity algorithms */
	enumerator = proposal->create_enumerator(proposal, INTEGRITY_ALGORITHM);
	while (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(INTEGRITY_ALGORITHM,
													   alg, key_size);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* prf algorithms */
	enumerator = proposal->create_enumerator(proposal, PSEUDO_RANDOM_FUNCTION);
	while (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(PSEUDO_RANDOM_FUNCTION,
													   alg, key_size);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* dh groups */
	enumerator = proposal->create_enumerator(proposal, DIFFIE_HELLMAN_GROUP);
	while (enumerator->enumerate(enumerator, &alg, NULL))
	{
		transform = transform_substructure_create_type(DIFFIE_HELLMAN_GROUP,
													   alg, 0);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* extended sequence numbers */
	enumerator = proposal->create_enumerator(proposal, EXTENDED_SEQUENCE_NUMBERS);
	while (enumerator->enumerate(enumerator, &alg, NULL))
	{
		transform = transform_substructure_create_type(EXTENDED_SEQUENCE_NUMBERS,
													   alg, 0);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

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
	this->proposal_number = proposal->get_number(proposal);
	this->protocol_id = proposal->get_protocol(proposal);
	compute_length(this);

	return &this->public;
}
