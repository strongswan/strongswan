/**
 * @file authenticator.c
 *
 * @brief Implementation of authenticator_t.
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

#include <string.h>

#include "authenticator.h"

#include <config/policies/policy.h>
#include <daemon.h>

/**
 * Key pad for the AUTH method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
 */
#define IKEV2_KEY_PAD "Key Pad for IKEv2"


typedef struct private_authenticator_t private_authenticator_t;

/**
 * Private data of an authenticator_t object.
 */
struct private_authenticator_t {

	/**
	 * Public authenticator_t interface.
	 */
	authenticator_t public;

	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * auth_method to create own signature/mac/whatever..
	 */
	auth_method_t auth_method;
	
	/**
	 * PRF taken from the IKE_SA.
	 */
	prf_t *prf;
};

/**
 * Builds the octets to be signed (RSA or PSK) as described in section 2.15 of RFC 4306
 */
static chunk_t build_tbs_octets(private_authenticator_t *this,
								chunk_t last_message, 
								chunk_t other_nonce,
								identification_t *id,
								bool initiator)
{
	prf_t *prf;

	chunk_t  id_encoding = id->get_encoding(id);
	u_int8_t id_with_header[4 + id_encoding.len];
	chunk_t id_with_header_chunk = {ptr:id_with_header, len: sizeof(id_with_header)};

	u_int8_t *current_pos;
	chunk_t octets;
	
	id_with_header[0] = id->get_type(id);
	id_with_header[1] = 0x00;
	id_with_header[2] = 0x00;
	id_with_header[3] = 0x00;
	memcpy(id_with_header + 4, id_encoding.ptr, id_encoding.len);
	
	if (initiator)
	{
		prf = this->ike_sa->get_prf_auth_i(this->ike_sa);
	}
	else
	{
		prf = this->ike_sa->get_prf_auth_r(this->ike_sa);
	}
	
	/* 4 bytes are id type and reserved fields of id payload */
	octets.len = last_message.len + other_nonce.len + prf->get_block_size(prf);
	octets.ptr = malloc(octets.len);
	current_pos = octets.ptr;
	memcpy(current_pos, last_message.ptr, last_message.len);
	current_pos += last_message.len;
	memcpy(current_pos, other_nonce.ptr, other_nonce.len);
	current_pos += other_nonce.len;
	prf->get_bytes(prf, id_with_header_chunk, current_pos);
	
	return octets;
}

/**
 * Creates the AUTH data using auth method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
 */
static chunk_t build_shared_key_signature(private_authenticator_t *this,
										  chunk_t last_message,
										  chunk_t nonce,
										  identification_t *id,
										  bool initiator,
										  chunk_t secret)
{
	chunk_t key_pad = {ptr: IKEV2_KEY_PAD, len:strlen(IKEV2_KEY_PAD)};
	u_int8_t key_buffer[this->prf->get_block_size(this->prf)];
	chunk_t key = {ptr: key_buffer, len: sizeof(key_buffer)};
	chunk_t auth_data;
	
	chunk_t octets = build_tbs_octets(this, last_message, nonce, id, initiator);
	
	/* AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>) */
	this->prf->set_key(this->prf, secret);
	this->prf->get_bytes(this->prf, key_pad, key_buffer);
	this->prf->set_key(this->prf, key);
	this->prf->allocate_bytes(this->prf, octets, &auth_data);
	DBG3(DBG_IKE, "octets = message + nonce + prf(Sk_px, IDx') %B", &octets);
	DBG3(DBG_IKE, "secret %B", &secret);
	DBG3(DBG_IKE, "keypad %B", &key_pad);
	DBG3(DBG_IKE, "prf(secret, keypad) %B", &key);
	DBG3(DBG_IKE, "AUTH = prf(prf(secret, keypad), octets) %B", &auth_data);
	chunk_free(&octets);

	return auth_data;
}

/**
 * Implementation of authenticator_t.verify_auth_data.
 */
static status_t verify_auth_data (private_authenticator_t *this,
									auth_payload_t *auth_payload,
									chunk_t last_received_packet,
									chunk_t my_nonce,
									identification_t *my_id,
									identification_t *other_id,
									bool initiator)
{
	status_t status;
	chunk_t       auth_data   = auth_payload->get_data(auth_payload);
	auth_method_t auth_method = auth_payload->get_auth_method(auth_payload);

	switch (auth_method)
	{
		case SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		{
			chunk_t shared_key;
			chunk_t my_auth_data;
						
			status = charon->credentials->get_shared_key(charon->credentials,
														 my_id,
														 other_id,
														 &shared_key);
			if (status != SUCCESS)
			{
				DBG1(DBG_IKE, "no shared key found for '%D' - '%D'",
					 my_id, other_id);
				chunk_free(&shared_key);
				break;
			}
			
			my_auth_data = build_shared_key_signature(this, last_received_packet,
													  my_nonce, other_id,
													  initiator, shared_key);
			chunk_free(&shared_key);


			status = (auth_data.len == my_auth_data.len &&
					  memeq(auth_data.ptr, my_auth_data.ptr, my_auth_data.len))
					 ? SUCCESS : FAILED;
			chunk_free(&my_auth_data);
		    break;
		}
		case RSA_DIGITAL_SIGNATURE:
		{
			chunk_t octets;

			rsa_public_key_t *public_key =
				charon->credentials->get_trusted_public_key(charon->credentials, other_id);

			if (public_key == NULL)
			{
				DBG1(DBG_IKE, "no RSA public key found for '%D'", other_id);
				status = NOT_FOUND;
				break;
			}
			
			octets = build_tbs_octets(this, last_received_packet, my_nonce,
									  other_id, initiator);
			status = public_key->verify_emsa_pkcs1_signature(public_key, octets, 
															 auth_data);
			chunk_free(&octets);
			break;
		}
		default:
		{
			return NOT_SUPPORTED;
		}
	}
	
	if (status == SUCCESS)
	{
		DBG1(DBG_IKE, "authentication of '%D' with %N successful",
			 other_id, auth_method_names, auth_method);
	}
	
	return status;
}

/**
 * Implementation of authenticator_t.compute_auth_data.
 */
static status_t compute_auth_data (private_authenticator_t *this,
								   auth_payload_t **auth_payload,
								   chunk_t last_sent_packet,
								   chunk_t other_nonce,
								   identification_t *my_id,
								   identification_t *other_id,
								   bool initiator)
{
	DBG1(DBG_IKE, "authentication of '%D' with %N (myself)",
		 my_id, auth_method_names, this->auth_method);

	switch (this->auth_method)
	{
		case SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		{
			chunk_t shared_key;
			chunk_t auth_data;

			status_t status = charon->credentials->get_shared_key(charon->credentials,
																  my_id,
																  other_id,
																  &shared_key);

			if (status != SUCCESS)
			{
				DBG1(DBG_IKE, "no shared key found for '%D' - '%D'",
					 my_id, other_id);
				return status;	
			}
			
			auth_data = build_shared_key_signature(this, last_sent_packet,
												   other_nonce,  my_id,
												   initiator, shared_key);
			chunk_free(&shared_key);
			*auth_payload = auth_payload_create();
			(*auth_payload)->set_auth_method(*auth_payload,
											 SHARED_KEY_MESSAGE_INTEGRITY_CODE);
			(*auth_payload)->set_data(*auth_payload, auth_data);

			chunk_free(&auth_data);
			return SUCCESS;
		}
		case RSA_DIGITAL_SIGNATURE:
		{
			chunk_t chunk;
			chunk_t octets;
			chunk_t auth_data;
			status_t status;
			rsa_public_key_t  *my_pubkey;
			rsa_private_key_t *my_key;

			DBG2(DBG_IKE, "looking for RSA public key belonging to '%D'",
							  my_id);

			my_pubkey = charon->credentials->get_rsa_public_key(charon->credentials, my_id);
			if (my_pubkey == NULL)
			{
				DBG1(DBG_IKE, "no RSA public key found for '%D'", my_id);
				return NOT_FOUND;
			}
			DBG2(DBG_IKE, "matching RSA public key found");
			
			chunk = my_pubkey->get_keyid(my_pubkey);
			DBG2(DBG_IKE, "looking for RSA private key with keyid %#B", &chunk);

			my_key = charon->credentials->get_rsa_private_key(charon->credentials, my_pubkey);
			if (my_key == NULL)
			{
				DBG1(DBG_IKE, "no RSA private key found with for %D with keyid %#B",
					 my_id, &chunk);
				return NOT_FOUND;
			}
			DBG2(DBG_IKE, "matching RSA private key found");

			octets = build_tbs_octets(this, last_sent_packet, other_nonce,
									  my_id, initiator);
			status = my_key->build_emsa_pkcs1_signature(my_key, HASH_SHA1,
														octets, &auth_data);
			chunk_free(&octets);

			if (status != SUCCESS)
			{
				my_key->destroy(my_key);
				return status;
			}
			DBG2(DBG_IKE, "successfully signed with RSA private key");
			
			*auth_payload = auth_payload_create();
			(*auth_payload)->set_auth_method(*auth_payload, RSA_DIGITAL_SIGNATURE);
			(*auth_payload)->set_data(*auth_payload, auth_data);

			my_key->destroy(my_key);
			chunk_free(&auth_data);
			return SUCCESS;
		}
		default:
		{
			return NOT_SUPPORTED;
		}
	}
}

/**
 * Implementation of authenticator_t.destroy.
 */
static void destroy (private_authenticator_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
authenticator_t *authenticator_create(ike_sa_t *ike_sa, auth_method_t auth_method)
{
	private_authenticator_t *this = malloc_thing(private_authenticator_t);

	/* Public functions */
	this->public.destroy = (void(*)(authenticator_t*))destroy;
	this->public.verify_auth_data = (status_t (*) (authenticator_t*,auth_payload_t*,chunk_t,chunk_t,identification_t*,identification_t*,bool)) verify_auth_data;
	this->public.compute_auth_data = (status_t (*) (authenticator_t*,auth_payload_t**,chunk_t,chunk_t,identification_t*,identification_t*,bool)) compute_auth_data;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->auth_method = auth_method;
	this->prf = this->ike_sa->get_prf(this->ike_sa);
	
	return &(this->public);
}
