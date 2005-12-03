/**
 * @file authenticator.c
 *
 * @brief Implementation of authenticator.
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

typedef struct private_authenticator_t private_authenticator_t;

/**
 * Private data of an authenticator_t object.
 */
struct private_authenticator_t {

	/**
	 * Public interface.
	 */
	authenticator_t public;

	/**
	 * IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;

	/**
	 * A logger for.
	 * 
	 * Using logger of IKE_SA.
	 */
	logger_t *logger;
	
	/**
	 * TODO
	 */
	chunk_t (*allocate_octets) (private_authenticator_t *this,chunk_t last_message, chunk_t other_nonce,identification_t *my_id);
	
	chunk_t (*allocate_auth_data_with_preshared_secret) (private_authenticator_t *this,chunk_t octets,chunk_t preshared_secret);
};

/**
 * Implementation of authenticator_t.private_authenticator_t.
 */
static chunk_t allocate_octets(private_authenticator_t *this,chunk_t last_message, chunk_t other_nonce,identification_t *my_id)
{
	chunk_t id_chunk = my_id->get_encoding(my_id);
	u_int8_t id_with_header[4 + id_chunk.len];
	chunk_t id_with_header_chunk;
	chunk_t octets;
	u_int8_t *current_pos;
	prf_t *prf;
	
	id_with_header[0] = my_id->get_type(my_id);
	id_with_header[1] = 0x00;
	id_with_header[2] = 0x00;
	id_with_header[3] = 0x00;
	memcpy(id_with_header + 4,id_chunk.ptr,id_chunk.len);
	id_with_header_chunk.ptr = id_with_header;
	id_with_header_chunk.len = sizeof(id_with_header);
	
	prf = this->ike_sa->get_prf(this->ike_sa);
	
	prf->set_key(prf,this->ike_sa->get_key_pr(this->ike_sa));
	
	
	/* 4 bytes are id type and reserved fields of id payload */
	octets.len = last_message.len + other_nonce.len + prf->get_block_size(prf);
	octets.ptr = allocator_alloc(octets.len);
	current_pos = octets.ptr;
	memcpy(current_pos,last_message.ptr,last_message.len);
	current_pos += last_message.len;
	memcpy(current_pos,other_nonce.ptr,other_nonce.len);
	current_pos += other_nonce.len;
	prf->get_bytes(prf,id_with_header_chunk,current_pos);
	
	this->logger->log_chunk(this->logger,RAW | MORE, "Octets (Mesage + Nonce + prf(Sk_px,Idx)",&octets);
	return octets;
}

/**
 * Implementation of authenticator_t.allocate_auth_data_with_preshared_secret.
 */
static chunk_t allocate_auth_data_with_preshared_secret (private_authenticator_t *this,chunk_t octets,chunk_t preshared_secret)
{
	prf_t *prf = this->ike_sa->get_prf(this->ike_sa);
	chunk_t auth_data;	
	chunk_t key_pad;
	chunk_t key;
	
	key_pad.ptr = "Key Pad for IKEv2";
	key_pad.len = strlen(key_pad.ptr);

	prf->set_key(prf,preshared_secret);
	prf->allocate_bytes(prf,key_pad,&key);
	prf->set_key(prf,key);
	allocator_free_chunk(&key);
	prf->allocate_bytes(prf,octets,&auth_data);
	this->logger->log_chunk(this->logger,RAW | MORE, "Authenticated data",&auth_data);
			
	return auth_data;
}


/**
 * Implementation of authenticator_t.verify_authentication.
 */
static status_t verify_authentication (private_authenticator_t *this,auth_method_t auth_method, chunk_t auth_data, chunk_t last_message, chunk_t other_nonce,identification_t *my_id,bool *verified)
{
	switch(auth_method)
	{
		case SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		{
			
			chunk_t preshared_secret;
			
			preshared_secret.ptr = "secret";
			preshared_secret.len = strlen(preshared_secret.ptr);
			
			chunk_t octets = this->allocate_octets(this,last_message, other_nonce,my_id);
			chunk_t my_auth_data = this->allocate_auth_data_with_preshared_secret(this,octets,preshared_secret);

			allocator_free_chunk(&octets);				

			if (auth_data.len != my_auth_data.len)
			{
				*verified = FALSE;
				allocator_free_chunk(&my_auth_data);
				return SUCCESS;
			}
			if (memcmp(auth_data.ptr,my_auth_data.ptr,my_auth_data.len) == 0)
			{
				*verified = TRUE;
			}
			else
			{
				*verified = FALSE;
			}
			allocator_free_chunk(&my_auth_data);		
			return SUCCESS;
		}
		default:
		{
			return NOT_SUPPORTED;
		}
	}
}

/**
 * Implementation of authenticator_t.allocate_auth_data.
 */
static status_t allocate_auth_data (private_authenticator_t *this,auth_method_t auth_method,chunk_t last_message, chunk_t other_nonce,identification_t *my_id,chunk_t *auth_data)
{
	switch(auth_method)
	{
		case SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		{
			chunk_t preshared_secret;
			
			preshared_secret.ptr = "secret";
			preshared_secret.len = strlen(preshared_secret.ptr);
			
			chunk_t octets = this->allocate_octets(this,last_message, other_nonce,my_id);
			chunk_t my_auth_data = allocate_auth_data_with_preshared_secret(this,octets,preshared_secret);
			
			allocator_free_chunk(&octets);
			
			*auth_data = my_auth_data;
			
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
	this->public.verify_authentication = (status_t (*) (authenticator_t *,auth_method_t , chunk_t , chunk_t , chunk_t ,identification_t *,bool *) )verify_authentication;
	this->public.allocate_auth_data = (status_t (*)  (authenticator_t *,auth_method_t ,chunk_t , chunk_t ,identification_t *,chunk_t *)) allocate_auth_data;
	
	/* private functions */
	this->allocate_octets = allocate_octets;
	this->allocate_auth_data_with_preshared_secret = allocate_auth_data_with_preshared_secret;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	
	return 	&(this->public);
}
