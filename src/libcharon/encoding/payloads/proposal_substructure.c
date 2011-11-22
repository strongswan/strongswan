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
 * IKEv2 Value for a proposal payload.
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
	linked_list_t *transforms;

	/**
	 * Type of this payload, PROPOSAL_SUBSTRUCTURE or PROPOSAL_SUBSTRUCTURE_V1
	 */
	payload_type_t type;
};

/**
 * Encoding rules for a IKEv1 Proposal substructure.
 */
static encoding_rule_t encodings_v1[] = {
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
	/* Transforms are stored in a transform substructure list */
	{ PAYLOAD_LIST + TRANSFORM_SUBSTRUCTURE_V1,
						offsetof(private_proposal_substructure_t, transforms)		},
};

/**
 * Encoding rules for a IKEv2 Proposal substructure.
 */
static encoding_rule_t encodings_v2[] = {
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
	/* Transforms are stored in a transform substructure list */
	{ PAYLOAD_LIST + TRANSFORM_SUBSTRUCTURE,
						offsetof(private_proposal_substructure_t, transforms)		},
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
 * Encryption.
 */
typedef enum {
	IKEV1_ENCR_DES_CBC = 1,
	IKEV1_ENCR_IDEA_CBC = 2,
	IKEV1_ENCR_BLOWFISH_CBC = 3,
	IKEV1_ENCR_RC5_R16_B64_CBC = 4,
	IKEV1_ENCR_3DES_CBC = 5,
	IKEV1_ENCR_CAST_CBC = 6,
	IKEV1_ENCR_AES_CBC = 7,
	IKEV1_ENCR_CAMELLIA_CBC = 8,
	IKEV1_ENCR_LAST = 9,
} ikev1_encryption_t;

/**
 * IKEv1 hash.
 */
typedef enum {
	IKEV1_HASH_MD5 = 1,
	IKEV1_HASH_SHA1 = 2,
	IKEV1_HASH_TIGER = 3,
	IKEV1_HASH_SHA2_256 = 4,
	IKEV1_HASH_SHA2_384 = 5,
	IKEV1_HASH_SHA2_512 = 6,
} ikev1_hash_t;

/**
 * IKEv1 Transform ID IKE.
 */
typedef enum {
	IKEV1_TRANSID_KEY_IKE = 1,
} ikev1_ike_transid_t;

/**
 * IKEv1 Transform ID ESP.
 */
typedef enum {
	IKEV1_TRANSID_ESP_DES_IV64 = 1,
	IKEV1_TRANSID_ESP_DES = 2,
	IKEV1_TRANSID_ESP_3DES = 3,
	IKEV1_TRANSID_ESP_RC5 = 4,
	IKEV1_TRANSID_ESP_IDEA = 5,
	IKEV1_TRANSID_ESP_CAST = 6,
	IKEV1_TRANSID_ESP_BLOWFISH = 7,
	IKEV1_TRANSID_ESP_3IDEA = 8,
	IKEV1_TRANSID_ESP_DES_IV32 = 9,
	IKEV1_TRANSID_ESP_RC4 = 10,
	IKEV1_TRANSID_ESP_NULL = 11,
	IKEV1_TRANSID_ESP_AES_CBC = 12,
} ikev1_esp_transid_t;

/**
 * IKEv1 ESP Encapsulation mode.
 */
typedef enum {
  IKEV1_ENCAP_TUNNEL = 1,
  IKEV1_ENCAP_TRANSPORT = 2,
  IKEV1_ENCAP_UDP_TUNNEL = 3,
  IKEV1_ENCAP_UDP_TRANSPORT = 4,
} ikev1_esp_encap_t;

/**
 * IKEv1 Life duration types.
 */
typedef enum {
	IKEV1_LIFE_TYPE_SECONDS = 1,
	IKEV1_LIFE_TYPE_KILOBYTES = 2,
} ikev1_life_type_t;

/**
 * IKEv1 authenticaiton methods
 */
typedef enum {
	IKEV1_AUTH_PSK = 1,
	IKEV1_AUTH_DSS_SIG = 2,
	IKEV1_AUTH_RSA_SIG = 3,
	IKEV1_AUTH_RSA_ENC = 4,
	IKEV1_AUTH_RSA_ENC_REV = 5,
} ikev1_auth_method_t;

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

METHOD(payload_t, get_encoding_rules, int,
	private_proposal_substructure_t *this, encoding_rule_t **rules)
{
	if (this->type == PROPOSAL_SUBSTRUCTURE)
	{
		*rules = encodings_v2;
		return countof(encodings_v2);
	}
	*rules = encodings_v1;
	return countof(encodings_v1);
}

METHOD(payload_t, get_header_length, int,
	private_proposal_substructure_t *this)
{
	return 8 + this->spi_size;
}

METHOD(payload_t, get_type, payload_type_t,
	private_proposal_substructure_t *this)
{
	return this->type;
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
	this->proposal_length = get_header_length(this);
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

/**
 * Add a transform to a proposal for IKEv2
 */
static void add_to_proposal_v2(proposal_t *proposal,
							   transform_substructure_t *transform)
{
	transform_attribute_t *tattr;
	enumerator_t *enumerator;
	u_int16_t key_length = 0;

	enumerator = transform->create_attribute_enumerator(transform);
	while (enumerator->enumerate(enumerator, &tattr))
	{
		if (tattr->get_attribute_type(tattr) == TATTR_IKEV2_KEY_LENGTH)
		{
			key_length = tattr->get_value(tattr);
			break;
		}
	}
	enumerator->destroy(enumerator);

	proposal->add_algorithm(proposal,
						transform->get_transform_type_or_number(transform),
						transform->get_transform_id(transform), key_length);
}

/**
 * Map IKEv1 to IKEv2 algorithms
 */
typedef struct {
	u_int16_t ikev1;
	u_int16_t ikev2;
} algo_map_t;

/**
 * Encryption algorithm mapping
 */
static algo_map_t map_encr[] = {
	{ IKEV1_ENCR_DES_CBC,		ENCR_DES },
	{ IKEV1_ENCR_IDEA_CBC,		ENCR_IDEA },
	{ IKEV1_ENCR_BLOWFISH_CBC,	ENCR_BLOWFISH },
	{ IKEV1_ENCR_3DES_CBC,		ENCR_3DES },
	{ IKEV1_ENCR_CAST_CBC,		ENCR_CAST },
	{ IKEV1_ENCR_AES_CBC,		ENCR_AES_CBC },
	{ IKEV1_ENCR_CAMELLIA_CBC,	ENCR_CAMELLIA_CBC },
};

/**
 * Integrity algorithm mapping
 */
static algo_map_t map_integ[] = {
	{ IKEV1_HASH_MD5,			AUTH_HMAC_MD5_96 },
	{ IKEV1_HASH_SHA1,			AUTH_HMAC_SHA1_96 },
	{ IKEV1_HASH_SHA2_256,		AUTH_HMAC_SHA2_256_128 },
	{ IKEV1_HASH_SHA2_384,		AUTH_HMAC_SHA2_384_192 },
	{ IKEV1_HASH_SHA2_512,		AUTH_HMAC_SHA2_512_256 },
};

/**
 * PRF algorithm mapping
 */
static algo_map_t map_prf[] = {
	{ IKEV1_HASH_MD5,			PRF_HMAC_MD5 },
	{ IKEV1_HASH_SHA1,			PRF_HMAC_SHA1 },
	{ IKEV1_HASH_SHA2_256,		PRF_HMAC_SHA2_256 },
	{ IKEV1_HASH_SHA2_384,		PRF_HMAC_SHA2_384 },
	{ IKEV1_HASH_SHA2_512,		PRF_HMAC_SHA2_512 },
};

/**
 * Get IKEv2 algorithm from IKEv1 identifier
 */
static u_int16_t get_alg_from_ikev1(transform_type_t type, u_int16_t value)
{
	algo_map_t *map;
	u_int16_t def;
	int i, count;

	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			map = map_encr;
			count = countof(map_encr);
			def = ENCR_UNDEFINED;
			break;
		case INTEGRITY_ALGORITHM:
			map = map_integ;
			count = countof(map_integ);
			def = AUTH_UNDEFINED;
			break;
		case PSEUDO_RANDOM_FUNCTION:
			map = map_prf;
			count = countof(map_prf);
			def = PRF_UNDEFINED;
			break;
		default:
			return 0;
	}
	for (i = 0; i < count; i++)
	{
		if (map[i].ikev1 == value)
		{
			return map[i].ikev2;
		}
	}
	return def;
}

/**
 * Get IKEv1 algorithm from IKEv2 identifier
 */
static u_int16_t get_ikev1_from_alg(transform_type_t type, u_int16_t value)
{
	algo_map_t *map;
	int i, count;

	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			map = map_encr;
			count = countof(map_encr);
			break;
		case INTEGRITY_ALGORITHM:
			map = map_integ;
			count = countof(map_integ);
			break;
		case PSEUDO_RANDOM_FUNCTION:
			map = map_prf;
			count = countof(map_prf);
			break;
		default:
			return 0;
	}
	for (i = 0; i < count; i++)
	{
		if (map[i].ikev2 == value)
		{
			return map[i].ikev1;
		}
	}
	return 0;
}

/**
 * Add an IKE transform to a proposal for IKEv1
 */
static void add_to_proposal_v1_ike(proposal_t *proposal,
								   transform_substructure_t *transform)
{
	transform_attribute_type_t type;
	transform_attribute_t *tattr;
	enumerator_t *enumerator;
	u_int16_t value, key_length = 0;
	u_int16_t encr = ENCR_UNDEFINED;

	enumerator = transform->create_attribute_enumerator(transform);
	while (enumerator->enumerate(enumerator, &tattr))
	{
		type = tattr->get_attribute_type(tattr);
		value = tattr->get_value(tattr);
		switch (type)
		{
			case TATTR_PH1_ENCRYPTION_ALGORITHM:
				encr = get_alg_from_ikev1(ENCRYPTION_ALGORITHM, value);
				break;
			case TATTR_PH1_KEY_LENGTH:
				key_length = value;
				break;
			case TATTR_PH1_HASH_ALGORITHM:
				proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM,
						get_alg_from_ikev1(INTEGRITY_ALGORITHM, value), 0);
				proposal->add_algorithm(proposal, PSEUDO_RANDOM_FUNCTION,
						get_alg_from_ikev1(PSEUDO_RANDOM_FUNCTION, value), 0);
				break;
			case TATTR_PH1_GROUP:
				proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP,
						value, 0);
				break;
			default:
				/* TODO-IKEv1: lifetimes, authentication and other attributes */
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (encr != ENCR_UNDEFINED)
	{
		proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, encr, key_length);
	}
}

/**
 * Add an ESP transform to a proposal for IKEv1
 */
static void add_to_proposal_v1_esp(proposal_t *proposal,
								   transform_substructure_t *transform)
{
	transform_attribute_type_t type;
	transform_attribute_t *tattr;
	enumerator_t *enumerator;
	u_int16_t value, key_length = 0;

	enumerator = transform->create_attribute_enumerator(transform);
	while (enumerator->enumerate(enumerator, &tattr))
	{
		type = tattr->get_attribute_type(tattr);
		value = tattr->get_value(tattr);
		switch (type)
		{
			case TATTR_PH2_KEY_LENGTH:
				key_length = value;
				break;
			case TATTR_PH2_AUTH_ALGORITHM:
				proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM,
						get_alg_from_ikev1(INTEGRITY_ALGORITHM, value), 0);
				break;
			default:
				/* TODO-IKEv1: lifetimes other attributes */
				break;
		}
	}
	enumerator->destroy(enumerator);

	/* TODO-IKEv1: handle ESN attribute */
	proposal->add_algorithm(proposal, EXTENDED_SEQUENCE_NUMBERS,
							NO_EXT_SEQ_NUMBERS, 0);

	proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM,
							transform->get_transform_id(transform), key_length);
}

METHOD(proposal_substructure_t, get_proposal, proposal_t*,
	private_proposal_substructure_t *this)
{
	transform_substructure_t *transform;
	enumerator_t *enumerator;
	proposal_t *proposal;

	proposal = proposal_create(this->protocol_id, this->proposal_number);

	enumerator = this->transforms->create_enumerator(this->transforms);
	while (enumerator->enumerate(enumerator, &transform))
	{
		if (this->type == PROPOSAL_SUBSTRUCTURE)
		{
			add_to_proposal_v2(proposal, transform);
		}
		else
		{
			switch (this->protocol_id)
			{
				case PROTO_IKE:
					add_to_proposal_v1_ike(proposal, transform);
					break;
				case PROTO_ESP:
					add_to_proposal_v1_esp(proposal, transform);
					break;
				default:
					break;
			}
			/* TODO-IKEv1: We currently accept the first set of transforms
			 * in a substructure only. We need to return multiple proposals,
			 * but this messes up proposal numbering, as we don't support
			 * transform numbering. */
			break;
		}
	}
	enumerator->destroy(enumerator);

	switch (this->spi.len)
	{
		case 4:
			proposal->set_spi(proposal, *((u_int32_t*)this->spi.ptr));
			break;
		case 8:
			proposal->set_spi(proposal, *((u_int64_t*)this->spi.ptr));
			break;
		default:
			break;
	}
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
									 offsetof(payload_t, destroy));
	chunk_free(&this->spi);
	free(this);
}

/*
 * Described in header.
 */
proposal_substructure_t *proposal_substructure_create(payload_type_t type)
{
	private_proposal_substructure_t *this;

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
		.transforms = linked_list_create(),
		.type = type,
	);
	compute_length(this);

	return &this->public;
}

/**
 * Add an IKEv1 IKE proposal to the substructure
 */
static void set_from_proposal_v1_ike(private_proposal_substructure_t *this,
									 proposal_t *proposal, int number)
{
	transform_substructure_t *transform;
	u_int16_t alg, key_size;
	enumerator_t *enumerator;

	transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE_V1,
												number, IKEV1_TRANSID_KEY_IKE);

	enumerator = proposal->create_enumerator(proposal, ENCRYPTION_ALGORITHM);
	if (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		alg = get_ikev1_from_alg(ENCRYPTION_ALGORITHM, alg);
		if (alg)
		{
			transform->add_transform_attribute(transform,
				transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
									TATTR_PH1_ENCRYPTION_ALGORITHM, alg));
			if (key_size)
			{
				transform->add_transform_attribute(transform,
					transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
										TATTR_PH1_KEY_LENGTH, key_size));
			}
		}
	}
	enumerator->destroy(enumerator);

	/* encode the integrity algorithm as hash and assume use the same PRF */
	enumerator = proposal->create_enumerator(proposal, INTEGRITY_ALGORITHM);
	if (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		alg = get_ikev1_from_alg(INTEGRITY_ALGORITHM, alg);
		if (alg)
		{
			transform->add_transform_attribute(transform,
				transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
									TATTR_PH1_HASH_ALGORITHM, alg));
		}
	}
	enumerator->destroy(enumerator);

	enumerator = proposal->create_enumerator(proposal, DIFFIE_HELLMAN_GROUP);
	if (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform->add_transform_attribute(transform,
			transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
								TATTR_PH1_GROUP, alg));
	}
	enumerator->destroy(enumerator);

	/* TODO-IKEv1: Add lifetime, non-fixed auth-method and other attributes */
	transform->add_transform_attribute(transform,
		transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
							TATTR_PH1_AUTH_METHOD, IKEV1_AUTH_PSK));
	transform->add_transform_attribute(transform,
		transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
							TATTR_PH1_LIFE_TYPE, IKEV1_LIFE_TYPE_SECONDS));
	transform->add_transform_attribute(transform,
		transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
							TATTR_PH1_LIFE_DURATION, 10800));

	add_transform_substructure(this, transform);
}

/**
 * Add an IKEv1 ESP proposal to the substructure
 */
static void set_from_proposal_v1_esp(private_proposal_substructure_t *this,
									 proposal_t *proposal, int number)
{
	transform_substructure_t *transform = NULL;
	u_int16_t alg, key_size;
	enumerator_t *enumerator;

	enumerator = proposal->create_enumerator(proposal, ENCRYPTION_ALGORITHM);
	if (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE_V1,
												   number, alg);
		if (key_size)
		{
			transform->add_transform_attribute(transform,
				transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
									TATTR_PH2_KEY_LENGTH, key_size));
		}
	}
	enumerator->destroy(enumerator);
	if (!transform)
	{
		return;
	}

	enumerator = proposal->create_enumerator(proposal, INTEGRITY_ALGORITHM);
	if (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		alg = get_ikev1_from_alg(INTEGRITY_ALGORITHM, alg);
		if (alg)
		{
			transform->add_transform_attribute(transform,
				transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
									TATTR_PH2_AUTH_ALGORITHM, alg));
		}
	}
	enumerator->destroy(enumerator);

	/* TODO-IKEv1: Add lifetime and other attributes, non-fixes ESN */
	transform->add_transform_attribute(transform,
		transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
							TATTR_PH2_EXT_SEQ_NUMBER, NO_EXT_SEQ_NUMBERS));
	transform->add_transform_attribute(transform,
		transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
							TATTR_PH2_SA_LIFE_TYPE, IKEV1_LIFE_TYPE_SECONDS));
	transform->add_transform_attribute(transform,
		transform_attribute_create_value(TRANSFORM_ATTRIBUTE_V1,
							TATTR_PH2_SA_LIFE_DURATION, 3600));

	add_transform_substructure(this, transform);
}

/**
 * Add an IKEv2 proposal to the substructure
 */
static void set_from_proposal_v2(private_proposal_substructure_t *this,
								 proposal_t *proposal)
{
	transform_substructure_t *transform;
	u_int16_t alg, key_size;
	enumerator_t *enumerator;

	/* encryption algorithm is only available in ESP */
	enumerator = proposal->create_enumerator(proposal, ENCRYPTION_ALGORITHM);
	while (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE,
												ENCRYPTION_ALGORITHM, alg);
		if (key_size)
		{
			transform->add_transform_attribute(transform,
				transform_attribute_create_value(TRANSFORM_ATTRIBUTE,
											TATTR_IKEV2_KEY_LENGTH, key_size));
		}
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* integrity algorithms */
	enumerator = proposal->create_enumerator(proposal, INTEGRITY_ALGORITHM);
	while (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE,
												INTEGRITY_ALGORITHM, alg);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* prf algorithms */
	enumerator = proposal->create_enumerator(proposal, PSEUDO_RANDOM_FUNCTION);
	while (enumerator->enumerate(enumerator, &alg, &key_size))
	{
		transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE,
												PSEUDO_RANDOM_FUNCTION, alg);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* dh groups */
	enumerator = proposal->create_enumerator(proposal, DIFFIE_HELLMAN_GROUP);
	while (enumerator->enumerate(enumerator, &alg, NULL))
	{
		transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE,
												DIFFIE_HELLMAN_GROUP, alg);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);

	/* extended sequence numbers */
	enumerator = proposal->create_enumerator(proposal, EXTENDED_SEQUENCE_NUMBERS);
	while (enumerator->enumerate(enumerator, &alg, NULL))
	{
		transform = transform_substructure_create_type(TRANSFORM_SUBSTRUCTURE,
												EXTENDED_SEQUENCE_NUMBERS, alg);
		add_transform_substructure(this, transform);
	}
	enumerator->destroy(enumerator);
}

/*
 * Described in header.
 */
proposal_substructure_t *proposal_substructure_create_from_proposal(
									payload_type_t type, proposal_t *proposal)
{
	private_proposal_substructure_t *this;
	u_int64_t spi64;
	u_int32_t spi32;

	this = (private_proposal_substructure_t*)proposal_substructure_create(type);

	if (type == PROPOSAL_SUBSTRUCTURE)
	{
		set_from_proposal_v2(this, proposal);
	}
	else
	{
		switch (proposal->get_protocol(proposal))
		{
			case PROTO_IKE:
				set_from_proposal_v1_ike(this, proposal, 0);
				break;
			case PROTO_ESP:
				set_from_proposal_v1_esp(this, proposal, 0);
				break;
			default:
				break;
		}
	}
	/* add SPI, if necessary */
	switch (proposal->get_protocol(proposal))
	{
		case PROTO_AH:
		case PROTO_ESP:
			spi32 = proposal->get_spi(proposal);
			this->spi = chunk_clone(chunk_from_thing(spi32));
			this->spi_size = this->spi.len;
			break;
		case PROTO_IKE:
			spi64 = proposal->get_spi(proposal);
			if (spi64)
			{	/* IKE only uses SPIS when rekeying, but on initial setup */
				this->spi = chunk_clone(chunk_from_thing(spi64));
				this->spi_size = this->spi.len;
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

/**
 * See header.
 */
proposal_substructure_t *proposal_substructure_create_from_proposals(
													linked_list_t *proposals)
{
	private_proposal_substructure_t *this = NULL;
	enumerator_t *enumerator;
	proposal_t *proposal;
	int number = 0;

	enumerator = proposals->create_enumerator(proposals);
	while (enumerator->enumerate(enumerator, &proposal))
	{
		if (!this)
		{
			this = (private_proposal_substructure_t*)
						proposal_substructure_create_from_proposal(
										PROPOSAL_SUBSTRUCTURE_V1, proposal);
		}
		else
		{
			switch (proposal->get_protocol(proposal))
			{
				case PROTO_IKE:
					set_from_proposal_v1_ike(this, proposal, ++number);
					break;
				case PROTO_ESP:
					set_from_proposal_v1_esp(this, proposal, ++number);
					break;
				default:
					break;
			}
		}
	}
	enumerator->destroy(enumerator);

	return &this->public;
}
