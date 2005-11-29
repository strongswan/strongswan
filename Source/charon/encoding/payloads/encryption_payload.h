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
 * Encrpytion payload length in bytes without IV and following data.
 */
#define ENCRYPTION_PAYLOAD_HEADER_LENGTH 4


typedef struct encryption_payload_t encryption_payload_t;

/** 
 * @brief The encryption payload as described in RFC section 3.14.
 * 
 * @ingroup payloads
 */
struct encryption_payload_t {
	/**
	 * Implements payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator for all contained payloads.
	 * 
	 * @warning iterator_t object has to get destroyed by the caller.
	 *
	 * @param this 			calling encryption_payload_t object
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * return				created iterator_t object
	 */
	 iterator_t *(*create_payload_iterator) (encryption_payload_t *this, bool forward);
	
	/**
	 * @brief Adds a payload to this encryption payload.
	 *
	 * @param this 			calling encryption_payload_t object
	 * @param payload		payload_t object to add
	 */
	void (*add_payload) (encryption_payload_t *this, payload_t *payload);
	
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
	
	void (*set_signer) (encryption_payload_t *this, signer_t *signer); 
	
	status_t (*encrypt) (encryption_payload_t *this, crypter_t *crypter);
	status_t (*decrypt) (encryption_payload_t *this, crypter_t *crypter);
	
	status_t (*build_signature) (encryption_payload_t *this, chunk_t data);
	status_t (*verify_signature) (encryption_payload_t *this, chunk_t data);

	/**
	 * @brief Destroys an encryption_payload_t object.
	 *
	 * @param this 	encryption_payload_t object to destroy
	 */
	void (*destroy) (encryption_payload_t *this);
};

/**
 * @brief Creates an empty encryption_payload_t object.
 * 
 * @return	created encryption_payload_t object
 * 
 * @ingroup payloads
 */
 
encryption_payload_t *encryption_payload_create();

#endif /*ENCRYPTION_PAYLOAD_H_*/
