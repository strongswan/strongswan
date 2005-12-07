/**
 * @file authenticator.c
 *
 * @brief Implementation of authenticator_t.
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

#include "authenticator.h"

#include <utils/allocator.h>
#include <daemon.h>

/**
 * Key pad for the AUTH method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
 */
#define IKE_V2_KEY_PAD "Key Pad for IKEv2"

/**
 * Length of key pad in bytes.
 */
#define IKE_V2_KEY_PAD_LEN strlen(IKE_V2_KEY_PAD)


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
	 * Assigned IKE_SA. Needed to get objects of type prf_t, sa_config_t and logger_t.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * PRF taken from the IKE_SA.
	 */
	prf_t *prf;

	/**
	 * A logger for.
	 * 
	 * Using logger of IKE_SA.
	 */
	logger_t *logger;
	
	/**
	 * @brief Creates the octets which are signed (RSA) or MACed (shared secret) as described in section 
	 * 2.15 of draft.
	 * 
	 * @param this				calling object
	 * @param last_message		the last message to include in created octets 
	 * 							(either binary form of IKE_SA_INIT request or IKE_SA_INIT response)
	 * @param other_nonce		Nonce data received from other peer
	 * @param my_id				id_payload_t object representing an ID payload
	 * @param initiator			Type of peer. TRUE, if it is original initiator, FALSE otherwise
	 * @return					octets as described in section 2.15. Memory gets allocated and has to get 
	 * 							destroyed by caller.
	 */
	chunk_t (*allocate_octets) (private_authenticator_t *this,
								chunk_t last_message,
								chunk_t other_nonce,
								id_payload_t *my_id,
								bool initiator);
	
	/**
	 * @brief Creates the AUTH data using auth method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
	 * 
	 * @param this				calling object
	 * @param last_message		the last message
	 * 							(either binary form of IKE_SA_INIT request or IKE_SA_INIT response)
	 * @param nonce				Nonce data to include in auth data compution
	 * @param id_payload		id_payload_t object representing an ID payload
	 * @param initiator			Type of peer. TRUE, if it is original initiator, FALSE otherwise
	 * @param shared_secret		shared secret as chunk_t. If shared secret is a string,
	 * 							the NULL termination is not included.
	 * @return					AUTH data as dscribed in section 2.15 for 
	 * 							AUTH method SHARED_KEY_MESSAGE_INTEGRITY_CODE.
	 * 							Memory gets allocated and has to get destroyed by caller.
	 */
	chunk_t (*allocate_auth_data_with_preshared_secret) (private_authenticator_t *this,
															chunk_t last_message,
															chunk_t nonce,
															id_payload_t *id_payload,
															bool initiator,
															chunk_t preshared_secret);
};

/**
 * Implementation of private_authenticator_t.allocate_octets.
 */
static chunk_t allocate_octets(private_authenticator_t *this,
								chunk_t last_message, 
								chunk_t other_nonce,
								id_payload_t *my_id,
								bool initiator)
{
	chunk_t id_chunk = my_id->get_data(my_id);
	u_int8_t id_with_header[4 + id_chunk.len];
	/*
	 * IKEv2 for linux (http://sf.net/projects/ikev2/) 
	 * is not compatible with IKEv2 Draft and so not compatible with this
	 * implementation, cause AUTH data are computed without
	 * ID type and the three reserved bytes.
	 */
	chunk_t id_with_header_chunk = {ptr:id_with_header, len: sizeof(id_with_header)};
	u_int8_t *current_pos;
	chunk_t octets;
	
	id_with_header[0] = my_id->get_id_type(my_id);
	/* TODO:
	 * Reserved bytes are not in any case zero.
	 */
	id_with_header[1] = 0x00;
	id_with_header[2] = 0x00;
	id_with_header[3] = 0x00;
	memcpy(id_with_header + 4,id_chunk.ptr,id_chunk.len);
	
	if (initiator)
	{
		this->prf->set_key(this->prf,this->ike_sa->get_key_pi(this->ike_sa));
	}
	else
	{
		this->prf->set_key(this->prf,this->ike_sa->get_key_pr(this->ike_sa));
	}

	
	/* 4 bytes are id type and reserved fields of id payload */
	octets.len = last_message.len + other_nonce.len + this->prf->get_block_size(this->prf);
	octets.ptr = allocator_alloc(octets.len);
	current_pos = octets.ptr;
	memcpy(current_pos,last_message.ptr,last_message.len);
	current_pos += last_message.len;
	memcpy(current_pos,other_nonce.ptr,other_nonce.len);
	current_pos += other_nonce.len;
	this->prf->get_bytes(this->prf,id_with_header_chunk,current_pos);
	
	this->logger->log_chunk(this->logger,RAW | LEVEL2, "Octets (Mesage + Nonce + prf(Sk_px,Idx)",&octets);
	return octets;
}

/**
 * Implementation of private_authenticator_t.allocate_auth_data_with_preshared_secret.
 */
static chunk_t allocate_auth_data_with_preshared_secret (private_authenticator_t *this,
															chunk_t last_message,
															chunk_t nonce,
															id_payload_t *id_payload,
															bool initiator,
															chunk_t preshared_secret)
{
	chunk_t key_pad = {ptr: IKE_V2_KEY_PAD, len:IKE_V2_KEY_PAD_LEN};
	u_int8_t key_buffer[this->prf->get_block_size(this->prf)];
	chunk_t key = {ptr: key_buffer, len: sizeof(key_buffer)};
	chunk_t auth_data;

	chunk_t octets = this->allocate_octets(this,last_message,nonce,id_payload,initiator);
	
	/*
	 * AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>) 
	 */

	this->prf->set_key(this->prf,preshared_secret);
	this->prf->get_bytes(this->prf,key_pad,key_buffer);
	this->prf->set_key(this->prf,key);
	this->prf->allocate_bytes(this->prf,octets,&auth_data);
	allocator_free_chunk(&octets);
	this->logger->log_chunk(this->logger,RAW | LEVEL2, "Authenticated data",&auth_data);

	return auth_data;
}

/**
 * Implementation of authenticator_t.verify_auth_data.
 */
static status_t verify_auth_data (private_authenticator_t *this,
									auth_payload_t *auth_payload,
									chunk_t last_received_packet,
									chunk_t my_nonce,
									id_payload_t *other_id_payload,
									bool initiator)
{
	switch(auth_payload->get_auth_method(auth_payload))
	{
		case SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		{
			identification_t *other_id = other_id_payload->get_identification(other_id_payload);
			chunk_t auth_data = auth_payload->get_data(auth_payload);
			chunk_t preshared_secret;
			status_t status;
						
			status = charon->configuration_manager->get_shared_secret(charon->configuration_manager,
																		other_id,
																		&preshared_secret);
			other_id->destroy(other_id);
			if (status != SUCCESS)
			{
				return status;	
			}
			
			chunk_t my_auth_data = this->allocate_auth_data_with_preshared_secret(this,
																					last_received_packet,
																					my_nonce,
																					other_id_payload,
																					initiator,
																					preshared_secret);
			
			if (auth_data.len != my_auth_data.len)
			{
				allocator_free_chunk(&my_auth_data);
				return FAILED;
			}
			if (memcmp(auth_data.ptr,my_auth_data.ptr,my_auth_data.len) == 0)
			{
				status = SUCCESS;
			}
			else
			{
				status = FAILED;
			}
			allocator_free_chunk(&my_auth_data);
			return status;
		}
		case RSA_DIGITAL_SIGNATURE:
		{
			identification_t *other_id = other_id_payload->get_identification(other_id_payload);
			rsa_public_key_t *public_key;
			status_t status;
			chunk_t octets, auth_data;
			
			auth_data = auth_payload->get_data(auth_payload);
			
			status = charon->configuration_manager->get_rsa_public_key(charon->configuration_manager,
																		other_id,
																		&public_key);
			other_id->destroy(other_id);
			if (status != SUCCESS)
			{
				return status;	
			}
			
			octets = this->allocate_octets(this,last_received_packet,my_nonce,other_id_payload,initiator);
			
			status = public_key->verify_emsa_pkcs1_signature(public_key, octets, auth_data);
			
			allocator_free_chunk(&octets);
			return status;
		}
		default:
		{
			return NOT_SUPPORTED;
		}
	}
}

/**
 * Implementation of authenticator_t.compute_auth_data.
 */
static status_t compute_auth_data (private_authenticator_t *this,
									auth_payload_t **auth_payload,
									chunk_t last_sent_packet,
									chunk_t other_nonce,
									id_payload_t *my_id_payload,
									bool initiator)
{
	sa_config_t *sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	
	switch(sa_config->get_auth_method(sa_config))
	{
		case SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		{
			identification_t *my_id =my_id_payload->get_identification(my_id_payload);
			chunk_t preshared_secret;
			status_t status;		

			status = charon->configuration_manager->get_shared_secret(charon->configuration_manager,
																		my_id,
																		&preshared_secret);

			my_id->destroy(my_id);
			if (status != SUCCESS)
			{
				return status;	
			}
			
			chunk_t auth_data = this->allocate_auth_data_with_preshared_secret(this,
																				last_sent_packet,
																				other_nonce,
																				my_id_payload,
																				initiator,
																				preshared_secret);

			*auth_payload = auth_payload_create();
			(*auth_payload)->set_auth_method((*auth_payload),SHARED_KEY_MESSAGE_INTEGRITY_CODE);
			(*auth_payload)->set_data((*auth_payload),auth_data);

			allocator_free_chunk(&auth_data);
			return SUCCESS;
		}
		case RSA_DIGITAL_SIGNATURE:
		{
			identification_t *my_id = my_id_payload->get_identification(my_id_payload);
			rsa_private_key_t *private_key;
			status_t status;
			chunk_t octets, auth_data;
			
			status = charon->configuration_manager->get_rsa_private_key(charon->configuration_manager,
																		my_id,
																		&private_key);
			my_id->destroy(my_id);
			if (status != SUCCESS)
			{
				return status;	
			}
			
			octets = this->allocate_octets(this,last_sent_packet,other_nonce,my_id_payload,initiator);
			
			status = private_key->build_emsa_pkcs1_signature(private_key, HASH_SHA1, octets, &auth_data);
			allocator_free_chunk(&octets);
			if (status != SUCCESS)
			{
				return status;	
			}
			
			*auth_payload = auth_payload_create();
			(*auth_payload)->set_auth_method((*auth_payload), RSA_DIGITAL_SIGNATURE);
			(*auth_payload)->set_data((*auth_payload),auth_data);

			allocator_free_chunk(&auth_data);
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
	allocator_free(this);
}

/*
 * Described in header.
 */
authenticator_t *authenticator_create(protected_ike_sa_t *ike_sa)
{
	private_authenticator_t *this = allocator_alloc_thing(private_authenticator_t);

	/* Public functions */
	this->public.destroy = (void(*)(authenticator_t*))destroy;
	this->public.verify_auth_data = (status_t (*) (authenticator_t *,auth_payload_t *, chunk_t ,chunk_t ,id_payload_t *,bool)) verify_auth_data;
	this->public.compute_auth_data = (status_t (*) (authenticator_t *,auth_payload_t **, chunk_t ,chunk_t ,id_payload_t *,bool)) compute_auth_data;
	
	/* private functions */
	this->allocate_octets = allocate_octets;
	this->allocate_auth_data_with_preshared_secret = allocate_auth_data_with_preshared_secret;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->prf = this->ike_sa->get_prf(this->ike_sa);
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	
	return 	&(this->public);
}
