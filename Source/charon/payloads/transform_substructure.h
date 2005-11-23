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

#ifndef TRANSFORM_SUBSTRUCTURE_H_
#define TRANSFORM_SUBSTRUCTURE_H_

#include <types.h>
#include <definitions.h>
#include <payloads/payload.h>
#include <payloads/transform_attribute.h>
#include <utils/linked_list.h>


/**
 * IKEv1 Value for a transform payload
 */
#define TRANSFORM_TYPE_VALUE 3

/**
 * Length of the transform substructure header in bytes
 */
#define TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH 8


/**
 * Type of a transform, as in IKEv2 draft 3.3.2
 */
typedef enum transform_type_e transform_type_t;

enum transform_type_e {
	UNDEFINED_TRANSFORM_TYPE = 241,
	ENCRYPTION_ALGORITHM = 1,
	PSEUDO_RANDOM_FUNCTION = 2,
	INTEGRITIY_ALGORITHM = 3,
	DIFFIE_HELLMAN_GROUP = 4,
	EXTENDED_SEQUENCE_NUNBERS = 5
};

/** 
 * string mappings for transform_type_t
 */
extern mapping_t transform_type_m[];

/**
 * Encryption algorithm, as in IKEv2 draft 3.3.2
 */
typedef enum encryption_algorithm_e encryption_algorithm_t;

enum encryption_algorithm_e {
	ENCR_UNDEFINED = 1024,
	ENCR_DES_IV64 = 1,
	ENCR_DES = 2,
	ENCR_3DES = 3,
	ENCR_RC5 = 4,
	ENCR_IDEA = 5,
	ENCR_CAST = 6,
	ENCR_BLOWFISH = 7,
	ENCR_3IDEA = 8,
	ENCR_DES_IV32 = 9,
	RESERVED = 10,
	ENCR_NULL = 11,
	ENCR_AES_CBC = 12,
	ENCR_AES_CTR = 13
};

/** 
 * string mappings for encryption_algorithm_t
 */
extern mapping_t encryption_algorithm_m[];

/**
 * Pseudo random function, as in IKEv2 draft 3.3.2
 */
typedef enum pseudo_random_function_e pseudo_random_function_t;

enum pseudo_random_function_e {
	PRF_UNDEFINED = 1024,
	PRF_HMAC_MD5 = 1,
	PRF_HMAC_SHA1 = 2,
	PRF_HMAC_TIGER = 3,
	PRF_AES128_CBC = 4
};

/** 
 * string mappings for encryption_algorithm_t
 */
extern mapping_t pseudo_random_function_m[];

/**
 * Integrity algorithm, as in IKEv2 draft 3.3.2
 */
typedef enum integrity_algorithm_e integrity_algorithm_t;

enum integrity_algorithm_e {
	AUTH_UNDEFINED = 1024,
	AUTH_HMAC_MD5_96 = 1,
	AUTH_HMAC_SHA1_96 = 2,
	AUTH_DES_MAC = 3,
	AUTH_KPDK_MD5 = 4,
	AUTH_AES_XCBC_96 = 5
};

/** 
 * string mappings for integrity_algorithm_t
 */
extern mapping_t integrity_algorithm_m[];


/** 
 * Diffie-Hellman group, as in IKEv2 draft 3.3.2 and RFC 3526
 */
typedef enum diffie_hellman_group_e diffie_hellman_group_t;

enum diffie_hellman_group_e {
	MODP_UNDEFINED = 1024,
	MODP_768_BIT = 1,
	MODP_1024_BIT = 2,
	MODP_1536_BIT = 5,
	MODP_2048_BIT = 14,
	MODP_3072_BIT = 15,
	MODP_4096_BIT = 16,
	MODP_6144_BIT = 17,
	MODP_8192_BIT = 18
};

/** 
 * string mappings for diffie_hellman_group_t
 */
extern mapping_t diffie_hellman_group_m[];

/** 
 * Extended sequence numbers, as in IKEv2 draft 3.3.2
 */
typedef enum extended_sequence_numbers_e extended_sequence_numbers_t;

enum extended_sequence_numbers_e {
	NO_EXT_SEQ_NUMBERS = 0,
	EXT_SEQ_NUMBERS = 1
};

/** 
 * string mappings for extended_sequence_numbers_t
 */
extern mapping_t extended_sequence_numbers_m[];

/**
 * Object representing an IKEv2- TRANSFORM SUBSTRUCTURE
 * 
 * The TRANSFORM SUBSTRUCTURE format is described in RFC section 3.3.2.
 * 
 */
typedef struct transform_substructure_s transform_substructure_t;

struct transform_substructure_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator of stored transform_attribute_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 * 
	 * @warning When deleting an transform attribute using this iterator, 
	 * 			the length of this transform substructure has to be refreshed 
	 * 			by calling get_length()!
	 *
	 * @param this 			calling transform_substructure_t object
	 * @param iterator  		the created iterator is stored at the pointed pointer
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return 		
	 * 						- SUCCESS or
	 * 						- OUT_OF_RES if iterator could not be created
	 */
	status_t (*create_transform_attribute_iterator) (transform_substructure_t *this,linked_list_iterator_t **iterator, bool forward);
	
	/**
	 * @brief Adds a transform_attribute_t object to this object.
	 * 
	 * @warning The added proposal_substructure_t object  is 
	 * 			getting destroyed in destroy function of transform_substructure_t.
	 *
	 * @param this 		calling transform_substructure_t object
	 * @param proposal  transform_attribute_t object to add
	 * @return 			- SUCCESS if succeeded
	 * 					- FAILED otherwise
	 */
	status_t (*add_transform_attribute) (transform_substructure_t *this,transform_attribute_t *attribute);
	
	/**
	 * @brief Sets the next_payload field of this substructure
	 * 
	 * If this is the last transform, next payload field is set to 0,
	 * otherwise to 3 (payload type of transform in IKEv1)
	 *
	 * @param this 		calling transform_substructure_t object
	 * @param is_last	When TRUE, next payload field is set to 0, otherwise to 3
	 * @return 			- SUCCESS
	 */
	status_t (*set_is_last_transform) (transform_substructure_t *this, bool is_last);
	
	/**
	 * @brief Checks if this is the last transform.
	 * 
	 * @param this 		calling transform_substructure_t object
	 * @return 			TRUE if this is the last Transform, FALSE otherwise
	 */
	bool (*get_is_last_transform) (transform_substructure_t *this);
	
	/**
	 * @brief Sets transform type of the current transform substructure.
	 *
	 * @param this 		calling transform_substructure_t object
	 * @param type		type value to set
	 * @return 			- SUCCESS
	 */
	status_t (*set_transform_type) (transform_substructure_t *this,u_int8_t type);
	
	/**
	 * @brief get transform type of the current transform.
	 * 
	 * @param this 		calling transform_substructure_t object
	 * @return 			Transform type of current transform substructure.
	 */
	u_int8_t (*get_transform_type) (transform_substructure_t *this);
	
	/**
	 * @brief Sets transform id of the current transform substructure.
	 *
	 * @param this 		calling transform_substructure_t object
	 * @param id			transform id to set
	 * @return 			- SUCCESS
	 */
	status_t (*set_transform_id) (transform_substructure_t *this,u_int16_t id);
	
	/**
	 * @brief get transform id of the current transform.
	 * 
	 * @param this 		calling transform_substructure_t object
	 * @return 			Transform id of current transform substructure.
	 */
	u_int16_t (*get_transform_id) (transform_substructure_t *this);

	/**
	 * @brief Clones an transform_substructure_t object.
	 *
	 * @param this 	transform_substructure_t object to clone
	 * @param clone	pointer to a transform_substructure_t object pointer 
	 * 				where the new object is stored to.
	 * @return 		
	 * 				- OUT_OF_RES
	 * 				- SUCCESS in any case
	 */
	status_t (*clone) (transform_substructure_t *this,transform_substructure_t **clone);

	/**
	 * @brief Destroys an transform_substructure_t object.
	 *
	 * @param this 	transform_substructure_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (transform_substructure_t *this);
};

/**
 * @brief Creates an empty transform_substructure_t object
 * 
 * @return			
 * 					- created transform_substructure_t object, or
 * 					- NULL if failed
 */
 
transform_substructure_t *transform_substructure_create();

#endif /*TRANSFORM_SUBSTRUCTURE_H_*/
