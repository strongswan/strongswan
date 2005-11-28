/**
 * @file encryption_payload.h
 * 
 * @brief Interface of encryption_payload_t.
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

#ifndef ENCRYPTION_PAYLOAD_H_
#define ENCRYPTION_PAYLOAD_H_

#include <types.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>
#include <encoding/payloads/payload.h>
#include <utils/linked_list.h>

/**
 * encrpytion payload length in bytes without IV and following data
 */
#define ENCRYPTION_PAYLOAD_HEADER_LENGTH 4


typedef struct encryption_payload_t encryption_payload_t;

/** 
 * @brief The encryption payload as described in RFC section 3.14.
 * 
 */
struct encryption_payload_t {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator for all contained payloads.
	 *
	 * @param this 			calling encryption_payload_t object
	 * @param iterator  	the created iterator is stored at the pointed pointer
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return	
	 * 						- SUCCESS or
	 * 						- OUT_OF_RES if iterator could not be created
	 */
	status_t (*create_payload_iterator) (encryption_payload_t *this, iterator_t **iterator, bool forward);
	
	/**
	 * @brief Adds a payload to this encryption payload.
	 *
	 * @param this 			calling encryption_payload_t object
	 * @param payload		payload_t object to add
	 * @return 				- SUCCESS if succeeded
	 * 						- FAILED otherwise
	 */
	status_t (*add_payload) (encryption_payload_t *this, payload_t *payload);
	
	/**
	 * @brief Decrypt and return contained data.
	 * 
	 * Decrypt the contained data (encoded payloads) using supplied crypter.
	 *
	 * @param this			calling encryption_payload_t
	 * @param crypter		crypter_t to use for data decryption
	 * @param[out]data		resulting data in decrypted and unpadded form
	 * @return 				
	 *						- SUCCESS, or
	 *						- FAILED if crypter does not match data
	 */
	
	status_t (*set_signer) (encryption_payload_t *this, signer_t *signer); 
	
	status_t (*encrypt) (encryption_payload_t *this, crypter_t *crypter);
	status_t (*decrypt) (encryption_payload_t *this, crypter_t *crypter);
	
	status_t (*build_signature) (encryption_payload_t *this, chunk_t data);
	status_t (*verify_signature) (encryption_payload_t *this, chunk_t data);

	/**
	 * @brief Destroys an encryption_payload_t object.
	 *
	 * @param this 	encryption_payload_t object to destroy
	 * @return 		
	 * 						- SUCCESS in any case
	 */
	status_t (*destroy) (encryption_payload_t *this);
};

/**
 * @brief Creates an empty encryption_payload_t object.
 * 
 * @return			
 * 					- created encryption_payload_t object, or
 * 					- NULL if failed
 */
 
encryption_payload_t *encryption_payload_create();


#endif /*ENCRYPTION_PAYLOAD_H_*/
