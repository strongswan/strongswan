/**
 * @file eap_authenticator.c
 *
 * @brief Implementation of eap_authenticator_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "eap_authenticator.h"

#include <daemon.h>
#include <config/policies/policy.h>
#include <sa/authenticators/eap/eap_method.h>

typedef struct private_eap_authenticator_t private_eap_authenticator_t;

/**
 * Private data of an eap_authenticator_t object.
 */
struct private_eap_authenticator_t {
	
	/**
	 * Public authenticator_t interface.
	 */
	eap_authenticator_t public;
	
	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Role of this authenticator, PEER or SERVER
	 */
	eap_role_t role;
	
	/**
	 * Current EAP method processing
	 */
	eap_method_t *method;
	
	/**
	 * MSK used to build and verify auth payload
	 */
	chunk_t msk;
};

extern chunk_t build_shared_key_signature(chunk_t ike_sa_init, chunk_t nonce,
										  chunk_t secret, identification_t *id,
										  prf_t *prf);

/**
 * Implementation of authenticator_t.verify.
 */
static status_t verify(private_eap_authenticator_t *this, chunk_t ike_sa_init,
					   chunk_t my_nonce, auth_payload_t *auth_payload)
{
	chunk_t auth_data, recv_auth_data;
	identification_t *other_id = this->ike_sa->get_other_id(this->ike_sa);
	prf_t *prf = this->ike_sa->get_auth_verify(this->ike_sa);
	
	auth_data = build_shared_key_signature(ike_sa_init, my_nonce, this->msk,
										   other_id, prf);
	
	recv_auth_data = auth_payload->get_data(auth_payload);
	if (!chunk_equals(auth_data, recv_auth_data))
	{
		DBG1(DBG_IKE, "verification of AUTH payload created from EAP MSK failed");
		chunk_free(&auth_data);
		return FAILED;
	}
	chunk_free(&auth_data);
	
	DBG1(DBG_IKE, "authentication of '%D' with %N successful",
		 other_id, auth_method_names, AUTH_EAP);
	return SUCCESS;
}

/**
 * Implementation of authenticator_t.build.
 */
static status_t build(private_eap_authenticator_t *this, chunk_t ike_sa_init,
					  chunk_t other_nonce, auth_payload_t **auth_payload)
{
	chunk_t auth_data;
	identification_t *my_id = this->ike_sa->get_my_id(this->ike_sa);
	prf_t *prf = this->ike_sa->get_auth_build(this->ike_sa);
	
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N",
		 my_id, auth_method_names, AUTH_EAP);
	
	auth_data = build_shared_key_signature(ike_sa_init, other_nonce,
										   this->msk, my_id, prf);
	
	*auth_payload = auth_payload_create();
	(*auth_payload)->set_auth_method(*auth_payload, AUTH_PSK);
	(*auth_payload)->set_data(*auth_payload, auth_data);
	chunk_free(&auth_data);
	
	return SUCCESS;
}

/**
 * Implementation of eap_authenticator_t.initiate
 */
static status_t initiate(private_eap_authenticator_t *this, eap_type_t type,
						 eap_payload_t **out)
{
	/* if initiate() is called, role is always server */
	this->role = EAP_SERVER;
	
	if (type == 0)
	{
		DBG1(DBG_IKE,
			 "client requested EAP authentication, but configuration forbids it");
		*out = eap_payload_create_code(EAP_FAILURE);
		return FAILED;
	}
	
	DBG1(DBG_IKE, "requesting %N authentication", eap_type_names, type);
	this->method = eap_method_create(type, this->role,
									 this->ike_sa->get_my_id(this->ike_sa),
									 this->ike_sa->get_other_id(this->ike_sa));
	
	if (this->method == NULL)
	{
		DBG1(DBG_IKE, "configured EAP server method %N not supported, sending %N",
			 eap_type_names, type, eap_code_names, EAP_FAILURE);
		*out = eap_payload_create_code(EAP_FAILURE);
		return FAILED;
	}
	if (this->method->initiate(this->method, out) != NEED_MORE)
	{
		DBG1(DBG_IKE, "failed to initiate %N, sending %N",
			 eap_type_names, type, eap_code_names, EAP_FAILURE);
		*out = eap_payload_create_code(EAP_FAILURE);
		return FAILED;	
	}
	return NEED_MORE;
}

/**
 * Processing method for a peer
 */
static status_t process_peer(private_eap_authenticator_t *this,
							 eap_payload_t *in, eap_payload_t **out)
{
	eap_type_t type = in->get_type(in);
	
	if (type == EAP_IDENTITY)
	{
		eap_method_t *method = eap_method_create(type, EAP_PEER,
									   this->ike_sa->get_other_id(this->ike_sa),
									   this->ike_sa->get_my_id(this->ike_sa));
		
		if (method == NULL || method->process(method, in, out) != SUCCESS)
		{
			DBG1(DBG_IKE, "EAP server requested %N, but unable to process",
				 eap_type_names, type);
			DESTROY_IF(method);
			return FAILED;
		}
		
		DBG1(DBG_IKE, "EAP server requested %N, sending IKE identity",
			 eap_type_names, type);
			 
		method->destroy(method);
		return NEED_MORE;
	}
	
	/* create an eap_method for the first call */
	if (this->method == NULL)
	{
		DBG1(DBG_IKE, "EAP server requested %N authentication",
			 eap_type_names, type);
		this->method = eap_method_create(type, EAP_PEER,
							this->ike_sa->get_other_id(this->ike_sa),
							this->ike_sa->get_my_id(this->ike_sa));
		if (this->method == NULL)
		{
			DBG1(DBG_IKE, "EAP server requested unsupported "
				 "EAP method %N, sending EAP_NAK", eap_type_names, type);
			*out = eap_payload_create_nak();
			return NEED_MORE;
		}
	}
	
	switch (this->method->process(this->method, in, out))
	{
		case NEED_MORE:
			return NEED_MORE;
		case SUCCESS:
			DBG1(DBG_IKE, "EAP method %N succeded",
				 eap_type_names, this->method->get_type(this->method));
			return SUCCESS;
		case FAILED:
		default:
			DBG1(DBG_IKE, "EAP method %N failed",
				 eap_type_names, this->method->get_type(this->method));
			return FAILED;
	}
}

/**
 * Processing method for a server
 */
static status_t process_server(private_eap_authenticator_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	switch (this->method->process(this->method, in, out))
	{
		case NEED_MORE:
			return NEED_MORE;
		case SUCCESS:
			if (this->method->get_msk(this->method, &this->msk) == SUCCESS)
			{
				DBG1(DBG_IKE, "EAP method %N succeded, MSK established",
					 eap_type_names, this->method->get_type(this->method));
				this->msk = chunk_clone(this->msk);
				*out = eap_payload_create_code(EAP_SUCCESS);
				return SUCCESS;
			}
			DBG1(DBG_IKE, "EAP method %N succeded, but no MSK established",
				 eap_type_names, this->method->get_type(this->method));
			*out = eap_payload_create_code(EAP_FAILURE);
			return FAILED;
		case FAILED:
		default:
			DBG1(DBG_IKE, "EAP method %N failed for peer %D",
				 eap_type_names, this->method->get_type(this->method),
				 this->ike_sa->get_other_id(this->ike_sa));
			*out = eap_payload_create_code(EAP_FAILURE);
			return FAILED;
	}
}

/**
 * Implementation of eap_authenticator_t.process
 */
static status_t process(private_eap_authenticator_t *this, eap_payload_t *in,
						eap_payload_t **out)
{
	eap_code_t code = in->get_code(in);
	
	switch (this->role)
	{
		case EAP_SERVER:
		{
			switch (code)
			{
				case EAP_RESPONSE:
				{
					return process_server(this, in, out);
				}
				default:
				{
					DBG1(DBG_IKE, "received %N, sending %N",
						 eap_code_names, code, eap_code_names, EAP_FAILURE);
					*out = eap_payload_create_code(EAP_FAILURE);
					return FAILED;
				}
			}
		}
		case EAP_PEER:
		{
			switch (code)
			{
				case EAP_REQUEST:
				{
					return process_peer(this, in, out);
				}
				case EAP_SUCCESS:
				{
					if (this->method->get_msk(this->method, &this->msk) == SUCCESS)
					{
						this->msk = chunk_clone(this->msk);
						return SUCCESS;
					}
					DBG1(DBG_IKE, "EAP method %N has no MSK established",
						 eap_type_names, this->method->get_type(this->method));
					return FAILED;
				}
				case EAP_FAILURE:
				default:
				{
					DBG1(DBG_IKE, "received %N, EAP authentication failed",
						 eap_code_names, code);
					return FAILED;
				}
			}
		}
		default:
		{
			return FAILED;
		}
	}
}

/**
 * Implementation of authenticator_t.is_mutual.
 */
static bool is_mutual(private_eap_authenticator_t *this)
{
	if (this->method)
	{
		return this->method->is_mutual(this->method);
	}
	return FALSE;
}

/**
 * Implementation of authenticator_t.destroy.
 */
static void destroy(private_eap_authenticator_t *this)
{
	DESTROY_IF(this->method);
	chunk_free(&this->msk);
	free(this);
}

/*
 * Described in header.
 */
eap_authenticator_t *eap_authenticator_create(ike_sa_t *ike_sa)
{
	private_eap_authenticator_t *this = malloc_thing(private_eap_authenticator_t);
	
	/* public functions */
	this->public.authenticator_interface.verify = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t*))verify;
	this->public.authenticator_interface.build = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t**))build;
	this->public.authenticator_interface.destroy = (void(*)(authenticator_t*))destroy;
	
	this->public.is_mutual = (bool(*)(eap_authenticator_t*))is_mutual;
	this->public.initiate = (status_t(*)(eap_authenticator_t*,eap_type_t,eap_payload_t**))initiate;
	this->public.process = (status_t(*)(eap_authenticator_t*,eap_payload_t*,eap_payload_t**))process;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->role = EAP_PEER;
	this->method = NULL;
	this->msk = chunk_empty;
	
	return &this->public;
}
