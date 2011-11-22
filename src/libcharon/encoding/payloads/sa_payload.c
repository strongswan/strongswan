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

#include "sa_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>
#include <daemon.h>

/* IKEv1 situation */
#define SIT_IDENTITY_ONLY 1

typedef struct private_sa_payload_t private_sa_payload_t;

/**
 * Private data of an sa_payload_t object.
 */
struct private_sa_payload_t {

	/**
	 * Public sa_payload_t interface.
	 */
	sa_payload_t public;

	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;

	/**
	 * Reserved bits
	 */
	bool reserved[8];

	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;

	/**
	 * Proposals in this payload are stored in a linked_list_t.
	 */
	linked_list_t *proposals;

	/**
	 * Type of this payload, V1 or V2
	 */
	payload_type_t type;

	/**
	 * IKEv1 DOI
	 */
	u_int32_t doi;

	/**
	 * IKEv1 situation
	 */
	u_int32_t situation;
};

/**
 * Encoding rules for IKEv1 SA payload
 */
static encoding_rule_t encodings_v1[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_sa_payload_t, next_payload)	},
	/* 8 reserved bits */
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[0])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[1])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[2])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[3])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[4])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[5])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[6])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[7])			},
	/* Length of the whole SA payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_sa_payload_t, payload_length)	},
	/* DOI*/
	{ U_INT_32,			offsetof(private_sa_payload_t, doi)				},
	/* Situation*/
	{ U_INT_32,			offsetof(private_sa_payload_t, situation)		},
	/* Proposals are stored in a proposal substructure list */
	{ PAYLOAD_LIST + PROPOSAL_SUBSTRUCTURE_V1,
						offsetof(private_sa_payload_t, proposals)		},
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !    RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                           DOI                                 !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                           Situation                           !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                          <Proposals>                          ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Encoding rules for IKEv2 SA payload
 */
static encoding_rule_t encodings_v2[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_sa_payload_t, next_payload)		},
	/* the critical bit */
	{ FLAG,				offsetof(private_sa_payload_t, critical)			},
	/* 7 Bit reserved bits */
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[0])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[1])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[2])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[3])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[4])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[5])			},
	{ RESERVED_BIT,		offsetof(private_sa_payload_t, reserved[6])			},
	/* Length of the whole SA payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_sa_payload_t, payload_length)		},
	/* Proposals are stored in a proposal substructure list */
	{ PAYLOAD_LIST + PROPOSAL_SUBSTRUCTURE,
						offsetof(private_sa_payload_t, proposals)			},
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                          <Proposals>                          ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_sa_payload_t *this)
{
	int expected_number = 0, current_number;
	status_t status = SUCCESS;
	enumerator_t *enumerator;
	proposal_substructure_t *substruct;

	if (this->type == SECURITY_ASSOCIATION)
	{
		expected_number = 1;
	}

	/* check proposal numbering */
	enumerator = this->proposals->create_enumerator(this->proposals);
	while (enumerator->enumerate(enumerator, (void**)&substruct))
	{
		current_number = substruct->get_proposal_number(substruct);
		if (current_number < expected_number)
		{
			DBG1(DBG_ENC, "proposal number smaller than previous");
			status = FAILED;
			break;
		}

		status = substruct->payload_interface.verify(&substruct->payload_interface);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "PROPOSAL_SUBSTRUCTURE verification failed");
			break;
		}
		expected_number = current_number;
	}
	enumerator->destroy(enumerator);
	return status;
}

METHOD(payload_t, get_encoding_rules, int,
	private_sa_payload_t *this, encoding_rule_t **rules)
{
	if (this->type == SECURITY_ASSOCIATION_V1)
	{
		*rules = encodings_v1;
		return countof(encodings_v1);
	}
	*rules = encodings_v2;
	return countof(encodings_v2);
}

METHOD(payload_t, get_header_length, int,
	private_sa_payload_t *this)
{
	if (this->type == SECURITY_ASSOCIATION_V1)
	{
		return 12;
	}
	return 4;
}

METHOD(payload_t, get_type, payload_type_t,
	private_sa_payload_t *this)
{
	return this->type;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_sa_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_sa_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * recompute length of the payload.
 */
static void compute_length(private_sa_payload_t *this)
{
	enumerator_t *enumerator;
	payload_t *current;

	this->payload_length = get_header_length(this);

	enumerator = this->proposals->create_enumerator(this->proposals);
	while (enumerator->enumerate(enumerator, (void **)&current))
	{
		this->payload_length += current->get_length(current);
	}
	enumerator->destroy(enumerator);
}

METHOD(payload_t, get_length, size_t,
	private_sa_payload_t *this)
{
	return this->payload_length;
}

/**
 * Create a transform substructure from a proposal, add to payload
 */
static void add_proposal(private_sa_payload_t *this, proposal_t *proposal)
{
	proposal_substructure_t *substruct, *last;
	payload_type_t subtype = PROPOSAL_SUBSTRUCTURE;
	u_int count;

	if (this->type == SECURITY_ASSOCIATION_V1)
	{
		subtype = PROPOSAL_SUBSTRUCTURE_V1;
	}
	substruct = proposal_substructure_create_from_proposal(subtype, proposal);
	count = this->proposals->get_count(this->proposals);
	if (count > 0)
	{
		this->proposals->get_last(this->proposals, (void**)&last);
		/* last transform is now not anymore last one */
		last->set_is_last_proposal(last, FALSE);
	}
	substruct->set_is_last_proposal(substruct, TRUE);
	if (proposal->get_number(proposal))
	{	/* use the selected proposals number, if any */
		substruct->set_proposal_number(substruct, proposal->get_number(proposal));
	}
	else
	{
		substruct->set_proposal_number(substruct, count + 1);
	}
	this->proposals->insert_last(this->proposals, substruct);
	compute_length(this);
}

METHOD(sa_payload_t, get_proposals, linked_list_t*,
	private_sa_payload_t *this)
{
	int struct_number = 0;
	int ignore_struct_number = 0;
	enumerator_t *enumerator;
	proposal_substructure_t *substruct;
	linked_list_t *list;
	proposal_t *proposal;

	if (this->type == SECURITY_ASSOCIATION_V1)
	{	/* IKEv1 proposals start with 0 */
		struct_number = ignore_struct_number = -1;
	}

	list = linked_list_create();
	/* we do not support proposals split up to two proposal substructures, as
	 * AH+ESP bundles are not supported in RFC4301 anymore.
	 * To handle such structures safely, we just skip proposals with multiple
	 * protocols.
	 */
	enumerator = this->proposals->create_enumerator(this->proposals);
	while (enumerator->enumerate(enumerator, &substruct))
	{
		/* check if a proposal has a single protocol */
		if (substruct->get_proposal_number(substruct) == struct_number)
		{
			if (ignore_struct_number < struct_number)
			{
				/* remove an already added, if first of series */
				list->remove_last(list, (void**)&proposal);
				proposal->destroy(proposal);
				ignore_struct_number = struct_number;
			}
			continue;
		}
		struct_number++;
		proposal = substruct->get_proposal(substruct);
		if (proposal)
		{
			list->insert_last(list, proposal);
		}
	}
	enumerator->destroy(enumerator);
	return list;
}

METHOD(sa_payload_t, create_substructure_enumerator, enumerator_t*,
	private_sa_payload_t *this)
{
	return this->proposals->create_enumerator(this->proposals);
}

METHOD2(payload_t, sa_payload_t, destroy, void,
	private_sa_payload_t *this)
{
	this->proposals->destroy_offset(this->proposals,
									offsetof(payload_t, destroy));
	free(this);
}

/*
 * Described in header.
 */
sa_payload_t *sa_payload_create(payload_type_t type)
{
	private_sa_payload_t *this;

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
			.get_proposals = _get_proposals,
			.create_substructure_enumerator = _create_substructure_enumerator,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.proposals = linked_list_create(),
		.type = type,
		/* for IKEv1 only */
		.doi = IKEV1_DOI_IPSEC,
		.situation = SIT_IDENTITY_ONLY,
	);

	compute_length(this);

	return &this->public;
}

/*
 * Described in header.
 */
sa_payload_t *sa_payload_create_from_proposal_list(payload_type_t type,
												   linked_list_t *proposals)
{
	private_sa_payload_t *this;
	enumerator_t *enumerator;
	proposal_t *proposal;

	this = (private_sa_payload_t*)sa_payload_create(type);
	if (type == SECURITY_ASSOCIATION)
	{
		enumerator = proposals->create_enumerator(proposals);
		while (enumerator->enumerate(enumerator, &proposal))
		{
			add_proposal(this, proposal);
		}
		enumerator->destroy(enumerator);
	}
	else
	{	/* IKEv1 encodes multiple proposals in a single substructure
		 * TODO-IKEv1: Encode ESP+AH proposals in two different substructs */
		proposal_substructure_t *substruct;

		substruct = proposal_substructure_create_from_proposals(proposals);
		substruct->set_is_last_proposal(substruct, TRUE);
		this->proposals->insert_last(this->proposals, substruct);
		compute_length(this);
	}
	return &this->public;
}

/*
 * Described in header.
 */
sa_payload_t *sa_payload_create_from_proposal(payload_type_t type,
											  proposal_t *proposal)
{
	private_sa_payload_t *this;

	this = (private_sa_payload_t*)sa_payload_create(type);
	add_proposal(this, proposal);

	return &this->public;
}
