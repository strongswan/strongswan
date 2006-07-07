/**
 * @file encryption_payload.h
 * 
 * @brief Interface of encryption_payload_t.
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

#ifndef ENCRYPTION_PAYLOAD_H_
#define ENCRYPTION_PAYLOAD_H_

#include <types.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <encoding/payloads/payload.h>
#include <utils/linked_list.h>

/**
 * Encrpytion payload length in bytes without IV and following data.
 * 
 * @ingroup payloads
 */
#define ENCRYPTION_PAYLOAD_HEADER_LENGTH 4


typedef struct encryption_payload_t encryption_payload_t;

/** 
 * @brief The encryption payload as described in RFC section 3.14.
 * 
 * Before any crypt/decrypt/sign/verify operation can occur, 
 * the transforms must be set. After that, a parsed encryption payload
 * can be decrypted, which also will parse the contained payloads.
 * Encryption is done the same way, added payloads will get generated
 * and then encrypted.
 * For signature building, there is the FULL packet needed. Meaning it
 * must be builded after generation of all payloads and the encryption
 * of the encryption payload.
 * Signature verificatin is done before decryption.
 * 
 * @b Constructors:
 * - encryption_payload_create()
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
	 * @brief Reove the last payload in the contained payload list.
	 *
	 * @param this 			calling encryption_payload_t object
	 * @param[out] payload	removed payload
	 * @return
	 * 						- SUCCESS, or
	 * 						- NOT_FOUND if list empty
	 */
	status_t (*remove_first_payload) (encryption_payload_t *this, payload_t **payload);
	
	/**
	 * @brief Get the number of payloads.
	 *
	 * @param this 			calling encryption_payload_t object
	 * @return				number of contained payloads
	 */
	size_t (*get_payload_count) (encryption_payload_t *this);
	
	/**
	 * @brief Set transforms to use.
	 * 
	 * To decryption, encryption, signature building and verifying,
	 * the payload needs a crypter and a signer object.
	 * 
	 * @warning Do NOT call this function again after encryption, since
	 * the signer must be the same while encrypting and signature building!
	 *
	 * @param this			calling encryption_payload_t
	 * @param crypter		crypter_t to use for data de-/encryption
	 * @param signer		signer_t to use for data signing/verifying
	 */
	void (*set_transforms) (encryption_payload_t *this, crypter_t *crypter, signer_t *signer);
	
	/**
	 * @brief Generate and encrypt contained payloads.
	 * 
	 * This function generates the content for added payloads
	 * and encrypts them. Signature is not built, since we need
	 * additional data (the full message).
	 *
	 * @param this			calling encryption_payload_t
	 * @return
	 * 						- SUCCESS, or
	 * 						- INVALID_STATE if transforms not set
	 */
	status_t (*encrypt) (encryption_payload_t *this);
	
	/**
	 * @brief Decrypt and parse contained payloads.
	 * 
	 * This function decrypts the contained data. After, 
	 * the payloads are parsed internally and are accessible
	 * via the iterator.
	 *
	 * @param this			calling encryption_payload_t
	 * @return
	 * 						- SUCCESS, or
	 * 						- INVALID_STATE if transforms not set, or
	 * 						- FAILED if data is invalid
	 */
	status_t (*decrypt) (encryption_payload_t *this);
	
	/**
	 * @brief Build the signature.
	 * 
	 * The signature is built over the FULL message, so the header
	 * and every payload (inclusive this one) must already be generated.
	 * The generated message is supplied via the data paramater.
	 * 
	 * @param this			calling encryption_payload_t
	 * @param data			chunk contains the already generated message
	 * @return
	 * 						- SUCCESS, or
	 * 						- INVALID_STATE if transforms not set
	 */
	status_t (*build_signature) (encryption_payload_t *this, chunk_t data);
		
	/**
	 * @brief Verify the signature.
	 * 
	 * Since the signature is built over the full message, we need
	 * this data to do the verification. The message data
	 * is supplied via the data argument.
	 * 
	 * @param this			calling encryption_payload_t
	 * @param data			chunk contains the message 
	 * @return
	 * 						- SUCCESS, or
	 * 						- FAILED if signature invalid, or
	 * 						- INVALID_STATE if transforms not set
	 */
	status_t (*verify_signature) (encryption_payload_t *this, chunk_t data);

	/**
	 * @brief Destroys an encryption_payload_t object.
	 *
	 * @param this 			encryption_payload_t object to destroy
	 */
	void (*destroy) (encryption_payload_t *this);
};

/**
 * @brief Creates an empty encryption_payload_t object.
 * 
 * @return encryption_payload_t object
 * 
 * @ingroup payloads
 */
encryption_payload_t *encryption_payload_create(void);


#endif /*ENCRYPTION_PAYLOAD_H_*/
