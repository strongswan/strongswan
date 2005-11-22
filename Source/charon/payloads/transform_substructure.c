/**
 * @file transform_substructure.h
 * 
 * @brief Declaration of the class transform_substructure_t. 
 * 
 * An object of this type represents an IKEv2 TRANSFORM Substructure and contains Attributes.
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

#include "transform_substructure.h"

#include "transform_attribute.h"
#include "encodings.h"
#include "../types.h"
#include "../utils/allocator.h"
#include "../utils/linked_list.h"

/**
 * Private data of an transform_substructure_t' Object
 * 
 */
typedef struct private_transform_substructure_s private_transform_substructure_t;

struct private_transform_substructure_s {
	/**
	 * public transform_substructure_t interface
	 */
	transform_substructure_t public;
	
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;

	
	/**
	 * Length of this payload
	 */
	u_int16_t transform_length;
	
	
	/**
	 * Type of the transform
	 */
	u_int8_t	 transform_type;
	
	/**
	 * Transform ID
	 */
	u_int16_t transform_id;
	
 	/**
 	 * Transforms Attributes are stored in a linked_list_t
 	 */
	linked_list_t *attributes;
	
	/**
	 * @brief Computes the length of this substructure.
	 *
	 * @param this 	calling private_transform_substructure_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*compute_length) (private_transform_substructure_t *this);
};


/** 
 * string mappings for transform_type_t
 */
mapping_t transform_type_m[] = {
	{UNDEFINED_TRANSFORM_TYPE, "UNDEFINED_TRANSFORM_TYPE"},
	{ENCRYPTION_ALGORITHM, "ENCRYPTION_ALGORITHM"},
	{PSEUDO_RANDOM_FUNCTION, "PSEUDO_RANDOM_FUNCTION"},
	{INTEGRITIY_ALGORITHM, "INTEGRITIY_ALGORITHM"},
	{DIFFIE_HELLMAN_GROUP, "DIFFIE_HELLMAN_GROUP"},
	{EXTENDED_SEQUENCE_NUNBERS, "EXTENDED_SEQUENCE_NUNBERS"},
	{MAPPING_END, NULL}
};


/** 
 * string mappings for encryption_algorithm_t
 */
mapping_t encryption_algorithm_m[] = {
	{ENCR_UNDEFINED, "ENCR_UNDEFINED"},
	{ENCR_DES_IV64, "ENCR_DES_IV64"},
	{ENCR_DES, "ENCR_DES"},
	{ENCR_3DES, "ENCR_3DES"},
	{ENCR_RC5, "ENCR_RC5"},
	{ENCR_IDEA, "ENCR_IDEA"},
	{ENCR_CAST, "ENCR_CAST"},
	{ENCR_BLOWFISH, "ENCR_BLOWFISH"},
	{ENCR_3IDEA, "ENCR_3IDEA"},
	{ENCR_DES_IV32, "ENCR_DES_IV32"},
	{ENCR_NULL, "ENCR_NULL"},
	{ENCR_AES_CBC, "ENCR_AES_CBC"},
	{ENCR_AES_CTR, "ENCR_AES_CTR"},
	{MAPPING_END, NULL}
};

/** 
 * string mappings for encryption_algorithm_t
 */
mapping_t pseudo_random_function_m[] = {
	{PRF_UNDEFINED, "PRF_UNDEFINED"},
	{PRF_HMAC_MD5, "PRF_HMAC_MD5"},
	{PRF_HMAC_SHA1, "PRF_HMAC_SHA1"},
	{PRF_HMAC_TIGER, "PRF_HMAC_TIGER"},
	{PRF_AES128_CBC, "PRF_AES128_CBC"},
	{MAPPING_END, NULL}
};

/** 
 * string mappings for integrity_algorithm_t
 */
mapping_t integrity_algorithm_m[] = {
	{AUTH_UNDEFINED, "AUTH_UNDEFINED"},
	{AUTH_HMAC_MD5_96, "AUTH_HMAC_MD5_96"},
	{AUTH_HMAC_SHA1_96, "AUTH_HMAC_SHA1_96"},
	{AUTH_DES_MAC, "AUTH_DES_MAC"},
	{AUTH_KPDK_MD5, "AUTH_KPDK_MD5"},
	{AUTH_AES_XCBC_96, "AUTH_AES_XCBC_96"},
	{MAPPING_END, NULL}
};

/** 
 * string mappings for diffie_hellman_group_t
 */
mapping_t diffie_hellman_group_m[] = {
	{MODP_UNDEFINED, "MODP_UNDEFINED"},
	{MODP_768_BIT, "MODP_768_BIT"},
	{MODP_1024_BIT, "MODP_1024_BIT"},
	{MODP_1536_BIT, "MODP_1536_BIT"},
	{MODP_2048_BIT, "MODP_2048_BIT"},
	{MODP_3072_BIT, "MODP_3072_BIT"},
	{MODP_4096_BIT, "MODP_4096_BIT"},
	{MODP_6144_BIT, "MODP_6144_BIT"},
	{MODP_8192_BIT, "MODP_8192_BIT"},
	{MAPPING_END, NULL}
};

/** 
 * string mappings for extended_sequence_numbers_t
 */
mapping_t extended_sequence_numbers_m[] = {
	{NO_EXT_SEQ_NUMBERS, "NO_EXT_SEQ_NUMBERS"},
	{EXT_SEQ_NUMBERS, "EXT_SEQ_NUMBERS"},
	{MAPPING_END, NULL}
};

/**
 * Encoding rules to parse or generate a Transform substructure
 * 
 * The defined offsets are the positions in a object of type 
 * private_transform_substructure_t.
 * 
 */
encoding_rule_t transform_substructure_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_transform_substructure_t, next_payload) 		},
	/* Reserved Byte is skipped */
	{ RESERVED_BYTE,		0																},	
	/* Length of the whole transform substructure*/
	{ PAYLOAD_LENGTH,		offsetof(private_transform_substructure_t, transform_length)	},	
	/* transform type is a number of 8 bit */
	{ U_INT_8,				offsetof(private_transform_substructure_t, transform_type) 	},	
	/* Reserved Byte is skipped */
	{ RESERVED_BYTE,		0																},	
	/* tranform ID is a number of 8 bit */
	{ U_INT_16,				offsetof(private_transform_substructure_t, transform_id)		},	
	/* Attributes are stored in a transform attribute, 
	   offset points to a linked_list_t pointer */
	{ TRANSFORM_ATTRIBUTES,	offsetof(private_transform_substructure_t, attributes) 		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 3 !   RESERVED    !        Transform Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !Transform Type !   RESERVED    !          Transform ID         !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Transform Attributes                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/**
 * Implements payload_t's verify function.
 * See #payload_s.verify for description.
 */
static status_t verify(private_transform_substructure_t *this)
{
	if ((this->next_payload != NO_PAYLOAD) && (this->next_payload != TRANSFORM_SUBSTRUCTURE))
	{
		/* must be 0 or 3 */
		return FAILED;
	}

	switch (this->transform_type)
	{
		case ENCRYPTION_ALGORITHM:
		{
			if ((this->transform_id < ENCR_DES_IV64) || (this->transform_id > ENCR_AES_CTR))
			{
				return FAILED;
			}
			break;
		}
		case	 PSEUDO_RANDOM_FUNCTION:
		{
			if ((this->transform_id < PRF_HMAC_MD5) || (this->transform_id > PRF_AES128_CBC))
			{
				return FAILED;
			}
			break;
		}
		case INTEGRITIY_ALGORITHM:
		{
			if ((this->transform_id < AUTH_HMAC_MD5_96) || (this->transform_id > AUTH_AES_XCBC_96))
			{
				return FAILED;
			}
			break;
		}
		case DIFFIE_HELLMAN_GROUP:
		{
			switch (this->transform_id)
			{
				case MODP_768_BIT:
				case MODP_1024_BIT:
				case MODP_1536_BIT:
				case MODP_2048_BIT:
				case MODP_3072_BIT:
				case MODP_4096_BIT:
				case MODP_6144_BIT:
				case MODP_8192_BIT:
				{
					break;
				}
				default:
				{
					return FAILED;
				}
			}
			
			
			break;
		}
		case EXTENDED_SEQUENCE_NUNBERS:
		{
			if ((this->transform_id != NO_EXT_SEQ_NUMBERS) && (this->transform_id != EXT_SEQ_NUMBERS))
			{
				return FAILED;
			}
			break;
		}
		default:
		{
			/* not a supported transform type! */
			return FAILED;
		}
	}

	/* proposal number is checked in SA payload */	
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_transform_substructure_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = transform_substructure_encodings;
	*rule_count = sizeof(transform_substructure_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_transform_substructure_t *this)
{
	return TRANSFORM_SUBSTRUCTURE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_transform_substructure_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_transform_substructure_t *this)
{
	this->compute_length(this);
		
	return this->transform_length;
}

/**
 * Implements transform_substructure_t's create_transform_attribute_iterator function.
 * See #transform_substructure_s.create_transform_attribute_iterator for description.
 */
static status_t create_transform_attribute_iterator (private_transform_substructure_t *this,linked_list_iterator_t **iterator,bool forward)
{
	return (this->attributes->create_iterator(this->attributes,iterator,forward));
}

/**
 * Implements transform_substructure_t's add_transform_attribute function.
 * See #transform_substructure_s.add_transform_attribute for description.
 */
static status_t add_transform_attribute (private_transform_substructure_t *this,transform_attribute_t *attribute)
{
	status_t status;
	status = this->attributes->insert_last(this->attributes,(void *) attribute);
	this->compute_length(this);
	return status;
}

/**
 * Implements transform_substructure_t's set_is_last_transform function.
 * See #transform_substructure_s.set_is_last_transform for description.
 */
static status_t set_is_last_transform (private_transform_substructure_t *this, bool is_last)
{
	this->next_payload = (is_last) ? 0: TRANSFORM_TYPE_VALUE;
	return SUCCESS;
}

/**
 * Implements transform_substructure_t's get_is_last_transform function.
 * See #transform_substructure_s.get_is_last_transform for description.
 */
static bool get_is_last_transform (private_transform_substructure_t *this)
{
	return ((this->next_payload == TRANSFORM_TYPE_VALUE) ? FALSE : TRUE);
}

/**
 * Implements payload_t's set_next_type function.
 * See #payload_s.set_next_type for description.
 */
static status_t set_next_type(private_transform_substructure_t *this,payload_type_t type)
{
	return SUCCESS;
}

/**
 * Implements transform_substructure_t's set_transform_type function.
 * See #transform_substructure_s.set_transform_type for description.
 */
static status_t set_transform_type (private_transform_substructure_t *this,u_int8_t type)
{
	this->transform_type = type;
	return SUCCESS;
}
	
/**
 * Implements transform_substructure_t's get_transform_type function.
 * See #transform_substructure_s.get_transform_type for description.
 */
static u_int8_t get_transform_type (private_transform_substructure_t *this)
{
	return this->transform_type;
}

/**
 * Implements transform_substructure_t's set_transform_id function.
 * See #transform_substructure_s.set_transform_id for description.
 */
static status_t set_transform_id (private_transform_substructure_t *this,u_int16_t id)
{
	this->transform_id = id;
	return SUCCESS;
}
	
/**
 * Implements transform_substructure_t's get_transform_id function.
 * See #transform_substructure_s.get_transform_id for description.
 */
static u_int16_t get_transform_id (private_transform_substructure_t *this)
{
	return this->transform_id;
}

/**
 * Implements private_transform_substructure_t's compute_length function.
 * See #private_transform_substructure_s.compute_length for description.
 */
static status_t compute_length (private_transform_substructure_t *this)
{
	linked_list_iterator_t *iterator;
	status_t status;
	size_t length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	status = this->attributes->create_iterator(this->attributes,&iterator,TRUE);
	if (status != SUCCESS)
	{
		return length;
	}
	while (iterator->has_next(iterator))
	{
		payload_t * current_attribute;
		iterator->current(iterator,(void **) &current_attribute);
		length += current_attribute->get_length(current_attribute);
	}
	iterator->destroy(iterator);
	
	this->transform_length = length;
		
	return SUCCESS;
}

/**
 * Implements transform_substructure_t's clone function.
 * See transform_substructure_s.clone for description.
 */
static status_t clone(private_transform_substructure_t *this,transform_substructure_t **clone)
{
	private_transform_substructure_t *new_clone;
	linked_list_iterator_t *attributes;
	status_t status;
	
	new_clone = (private_transform_substructure_t *) transform_substructure_create();
	
	new_clone->next_payload = this->next_payload;
	new_clone->transform_type = this->transform_type;
	new_clone->transform_id = this->transform_id;

	status = this->attributes->create_iterator(this->attributes,&attributes,FALSE);
	if (status != SUCCESS)
	{
		new_clone->public.destroy(&(new_clone->public));
		return status;
	}

	while (attributes->has_next(attributes))
	{
		transform_attribute_t *current_attribute;
		transform_attribute_t *current_attribute_clone;
		status = attributes->current(attributes,(void **) &current_attribute);
		if (status != SUCCESS)
		{
			attributes->destroy(attributes);
			new_clone->public.destroy(&(new_clone->public));
			return status;
		}
		status = current_attribute->clone(current_attribute,&current_attribute_clone);
		if (status != SUCCESS)
		{
			attributes->destroy(attributes);
			new_clone->public.destroy(&(new_clone->public));
			return status;
		}
		
		status = new_clone->public.add_transform_attribute(&(new_clone->public),current_attribute_clone);
		if (status != SUCCESS)
		{
			attributes->destroy(attributes);
			current_attribute_clone->destroy(current_attribute_clone);
			new_clone->public.destroy(&(new_clone->public));
			return status;
		}				
	}
	
	attributes->destroy(attributes);	
	
	*clone = &(new_clone->public);
	return SUCCESS;
}


/**
 * Implements payload_t's and transform_substructure_t's destroy function.
 * See #payload_s.destroy or transform_substructure_s.destroy for description.
 */
static status_t destroy(private_transform_substructure_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->attributes->get_count(this->attributes) > 0)
	{
		transform_attribute_t *current_attribute;
		if (this->attributes->remove_last(this->attributes,(void **)&current_attribute) != SUCCESS)
		{
			break;
		}
		current_attribute->destroy(current_attribute);
	}
	this->attributes->destroy(this->attributes);
	
	allocator_free(this);
	
	return SUCCESS;
}

/*
 * Described in header
 */
transform_substructure_t *transform_substructure_create()
{
	private_transform_substructure_t *this = allocator_alloc_thing(private_transform_substructure_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	/* payload interface */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (status_t (*) (payload_t *,payload_type_t)) set_next_type;	
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.create_transform_attribute_iterator = (status_t (*) (transform_substructure_t *,linked_list_iterator_t **,bool)) create_transform_attribute_iterator;
	this->public.add_transform_attribute = (status_t (*) (transform_substructure_t *,transform_attribute_t *)) add_transform_attribute;
	this->public.set_is_last_transform = (status_t (*) (transform_substructure_t *,bool)) set_is_last_transform;
	this->public.get_is_last_transform = (bool (*) (transform_substructure_t *)) get_is_last_transform;
	this->public.set_transform_type = (status_t (*) (transform_substructure_t *,u_int8_t)) set_transform_type;
	this->public.get_transform_type = (u_int8_t (*) (transform_substructure_t *)) get_transform_type;
	this->public.set_transform_id = (status_t (*) (transform_substructure_t *,u_int16_t)) set_transform_id;
	this->public.get_transform_id = (u_int16_t (*) (transform_substructure_t *)) get_transform_id;
	this->public.clone = (status_t (*) (transform_substructure_t *,transform_substructure_t **)) clone;
	this->public.destroy = (status_t (*) (transform_substructure_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->next_payload = NO_PAYLOAD;
	this->transform_length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	this->transform_id = 0;
	this->transform_type = 0;

	this->attributes = linked_list_create();
	
	if (this->attributes == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	return (&(this->public));
}
