/*
 * Copyright (C) 2006-2008 Martin Willi
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
 *
 * $Id$
 */

#include <string.h>

#include "eap_authenticator.h"

#include <daemon.h>
#include <config/peer_cfg.h>
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
	
	/**
	 * should we do a EAP-Identity exchange as server?
	 */
	bool do_eap_identity;
	
	/**
	 * saved EAP type if we do eap_identity
	 */
	eap_type_t type;
	
	/**
	 * saved vendor id if we do eap_identity
	 */
	u_int32_t vendor;
};
/**
 * Implementation of authenticator_t.verify.
 */
static status_t verify(private_eap_authenticator_t *this, chunk_t ike_sa_init,
					   chunk_t my_nonce, auth_payload_t *auth_payload)
{
	chunk_t auth_data, recv_auth_data;
	identification_t *other_id;
	keymat_t *keymat;
	
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	keymat = this->ike_sa->get_keymat(this->ike_sa);
	
	auth_data = keymat->get_psk_sig(keymat, TRUE, ike_sa_init, my_nonce,
									this->msk, other_id);
	
	recv_auth_data = auth_payload->get_data(auth_payload);
	if (!auth_data.len || !chunk_equals(auth_data, recv_auth_data))
	{
		DBG1(DBG_IKE, "verification of AUTH payload created from EAP MSK failed");
		chunk_free(&auth_data);
		return FAILED;
	}
	chunk_free(&auth_data);
	
	DBG1(DBG_IKE, "authentication of '%D' with %N successful",
		 other_id, auth_class_names, AUTH_CLASS_EAP);
	return SUCCESS;
}

/**
 * Implementation of authenticator_t.build.
 */
static status_t build(private_eap_authenticator_t *this, chunk_t ike_sa_init,
					  chunk_t other_nonce, auth_payload_t **auth_payload)
{
	identification_t *my_id;
	chunk_t auth_data;
	keymat_t *keymat;
	
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	keymat = this->ike_sa->get_keymat(this->ike_sa);
	
	DBG1(DBG_IKE, "authentication of '%D' (myself) with %N",
		 my_id, auth_class_names, AUTH_CLASS_EAP);
	
	auth_data = keymat->get_psk_sig(keymat, FALSE, ike_sa_init, other_nonce,
									this->msk, my_id);
	
	*auth_payload = auth_payload_create();
	(*auth_payload)->set_auth_method(*auth_payload, AUTH_PSK);
	(*auth_payload)->set_data(*auth_payload, auth_data);
	chunk_free(&auth_data);
	
	return SUCCESS;
}

/**
 * get the peers identity to use in the EAP method
 */
static identification_t *get_peer_id(private_eap_authenticator_t *this)
{
	identification_t *id;
	peer_cfg_t *config;
	auth_info_t *auth;
	
	id = this->ike_sa->get_eap_identity(this->ike_sa);
	if (!id)
	{
		config = this->ike_sa->get_peer_cfg(this->ike_sa);
		auth = config->get_auth(config);
		if (!auth->get_item(auth, AUTHN_EAP_IDENTITY, (void**)&id) ||
			id->get_type(id) == ID_ANY)
		{
			if (this->role == EAP_PEER)
			{
				id = this->ike_sa->get_my_id(this->ike_sa);
			}
			else
			{
				id = this->ike_sa->get_other_id(this->ike_sa);
			}
		}
	}
	if (id->get_type(id) == ID_EAP)
	{
		return id->clone(id);
	}
	return identification_create_from_encoding(ID_EAP, id->get_encoding(id));
}

/**
 * get the servers identity to use in the EAP method
 */
static identification_t *get_server_id(private_eap_authenticator_t *this)
{
	identification_t *id;
	
	if (this->role == EAP_SERVER)
	{
		id = this->ike_sa->get_my_id(this->ike_sa);
	}
	else
	{
		id = this->ike_sa->get_other_id(this->ike_sa);
	}
	if (id->get_type(id) == ID_EAP)
	{
		return id->clone(id);
	}
	return identification_create_from_encoding(ID_EAP, id->get_encoding(id));
}

/**
 * load an EAP method using the correct identities
 */
static eap_method_t *load_method(private_eap_authenticator_t *this,
							eap_type_t type, u_int32_t vendor, eap_role_t role)
{
	identification_t *server, *peer;
	eap_method_t *method;
	
	server = get_server_id(this);
	peer = get_peer_id(this);
	method = charon->eap->create_instance(charon->eap, type, vendor, role,
										  server, peer);		 
	server->destroy(server);
	peer->destroy(peer);
	return method;
}

/**
 * Implementation of eap_authenticator_t.initiate
 */
static status_t initiate(private_eap_authenticator_t *this, eap_type_t type,
						 u_int32_t vendor, eap_payload_t **out)
{
	/* if initiate() is called, role is always server */
	this->role = EAP_SERVER;
	
	if (this->do_eap_identity)
	{	/* do an EAP-Identity request first */
		this->type = type;
		this->vendor = vendor;
		vendor = 0;
		type = EAP_IDENTITY;
	}
	
	if (type == 0)
	{
		DBG1(DBG_IKE,
			 "client requested EAP authentication, but configuration forbids it");
		*out = eap_payload_create_code(EAP_FAILURE, 0);
		return FAILED;
	}
	
	if (vendor)
	{
		DBG1(DBG_IKE, "requesting vendor specific EAP method %d-%d",
			 type, vendor);
	}
	else
	{
		DBG1(DBG_IKE, "requesting EAP method %N", eap_type_names, type);
	}
	this->method = load_method(this, type, vendor, this->role);
	if (this->method == NULL)
	{
		if (vendor == 0 && type == EAP_IDENTITY)
		{
			DBG1(DBG_IKE, "skipping %N, no implementation found",
				 eap_type_names, type);
			this->do_eap_identity = FALSE;
			return initiate(this, this->type, this->vendor, out);
		}
		DBG1(DBG_IKE, "configured EAP server method not supported, sending %N",
			 eap_code_names, EAP_FAILURE);
		*out = eap_payload_create_code(EAP_FAILURE, 0);
		return FAILED;
	}
	if (this->method->initiate(this->method, out) != NEED_MORE)
	{
		DBG1(DBG_IKE, "failed to initiate EAP exchange, sending %N",
			 eap_code_names, EAP_FAILURE);
		*out = eap_payload_create_code(EAP_FAILURE, 0);
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
	eap_type_t type;
	u_int32_t vendor;
	
	type = in->get_type(in, &vendor);
	
	if (!vendor && type == EAP_IDENTITY)
	{
		eap_method_t *method;
		
		method = load_method(this, type, 0, EAP_PEER);
		if (method == NULL || method->process(method, in, out) != SUCCESS)
		{
			DBG1(DBG_IKE, "EAP server requested %N, but unable to process",
				 eap_type_names, type);
			DESTROY_IF(method);
			return FAILED;
		}
		DBG1(DBG_IKE, "EAP server requested %N", eap_type_names, type);	 
		method->destroy(method);
		return NEED_MORE;
	}
	
	/* create an eap_method for the first call */
	if (this->method == NULL)
	{
		if (vendor)
		{
			DBG1(DBG_IKE, "EAP server requested vendor specific EAP method %d-%d",
				 type, vendor);
		}
		else
		{
			DBG1(DBG_IKE, "EAP server requested %N authentication",
				 eap_type_names, type);
		}
		this->method = load_method(this, type, vendor, EAP_PEER);
		if (this->method == NULL)
		{
			DBG1(DBG_IKE, "EAP server requested unsupported "
				 "EAP method, sending EAP_NAK");
			*out = eap_payload_create_nak(in->get_identifier(in));
			return NEED_MORE;
		}
	}
	
	type = this->method->get_type(this->method, &vendor);
	
	switch (this->method->process(this->method, in, out))
	{
		case NEED_MORE:
			return NEED_MORE;
		case SUCCESS:
			if (vendor)
			{
				DBG1(DBG_IKE, "EAP vendor specific method %d-%d succeded",
					 type, vendor);
			}
			else
			{
				DBG1(DBG_IKE, "EAP method %N succeeded", eap_type_names, type);
			}
			return SUCCESS;
		case FAILED:
		default:
			if (vendor)
			{
				DBG1(DBG_IKE, "EAP vendor specific method %d-%d failed",
					 type, vendor);
			}
			else
			{
				DBG1(DBG_IKE, "EAP method %N failed",
					 eap_type_names, type);
			}
			return FAILED;
	}
}

/**
 * handle an EAP-Identity response on the server
 */
static status_t process_eap_identity(private_eap_authenticator_t *this,
									 eap_payload_t **out)
{
	chunk_t data;
	identification_t *id;

	if (this->method->get_msk(this->method, &data) == SUCCESS)
	{
		id = identification_create_from_encoding(ID_EAP, data);
		DBG1(DBG_IKE, "using EAP identity '%D'", id);
		this->ike_sa->set_eap_identity(this->ike_sa, id);
	}
	/* restart EAP exchange, but with real method */
	this->method->destroy(this->method);
	this->method = NULL;
	this->do_eap_identity = FALSE;
	return initiate(this, this->type, this->vendor, out);
}

/**
 * Processing method for a server
 */
static status_t process_server(private_eap_authenticator_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	eap_type_t type;
	u_int32_t vendor;
	
	type = this->method->get_type(this->method, &vendor);
	
	switch (this->method->process(this->method, in, out))
	{
		case NEED_MORE:
			return NEED_MORE;
		case SUCCESS:
			if (this->do_eap_identity)
			{
				return process_eap_identity(this, out);
			}
			if (this->method->get_msk(this->method, &this->msk) == SUCCESS)
			{
				this->msk = chunk_clone(this->msk);
			}
			if (vendor)
			{
				DBG1(DBG_IKE, "EAP vendor specific method %d-%d succeded, "
					 "%sMSK established", type, vendor,
					 this->msk.ptr ? "" : "no ");
			}
			else
			{
				DBG1(DBG_IKE, "EAP method %N succeded, %sMSK established",
					 eap_type_names, type, this->msk.ptr ? "" : "no ");
			}
			*out = eap_payload_create_code(EAP_SUCCESS, in->get_identifier(in));
			return SUCCESS;
		case FAILED:
		default:
			if (vendor)
			{
				DBG1(DBG_IKE, "EAP vendor specific method %d-%d failed for "
					 "peer %D", type, vendor, 
					 this->ike_sa->get_other_id(this->ike_sa));
			}
			else
			{
				DBG1(DBG_IKE, "EAP method %N failed for peer '%D'",
					 eap_type_names, type,
					 this->ike_sa->get_other_id(this->ike_sa));
			}
			*out = eap_payload_create_code(EAP_FAILURE, in->get_identifier(in));
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
					*out = eap_payload_create_code(EAP_FAILURE,
												   in->get_identifier(in));
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
					}
					return SUCCESS;
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
	peer_cfg_t *config;
	auth_info_t *auth;
	identification_t *id;
	private_eap_authenticator_t *this = malloc_thing(private_eap_authenticator_t);
	
	/* public functions */
	this->public.authenticator_interface.verify = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t*))verify;
	this->public.authenticator_interface.build = (status_t(*)(authenticator_t*,chunk_t,chunk_t,auth_payload_t**))build;
	this->public.authenticator_interface.destroy = (void(*)(authenticator_t*))destroy;
	
	this->public.is_mutual = (bool(*)(eap_authenticator_t*))is_mutual;
	this->public.initiate = (status_t(*)(eap_authenticator_t*,eap_type_t,u_int32_t,eap_payload_t**))initiate;
	this->public.process = (status_t(*)(eap_authenticator_t*,eap_payload_t*,eap_payload_t**))process;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->role = EAP_PEER;
	this->method = NULL;
	this->msk = chunk_empty;
	this->do_eap_identity = FALSE;
	this->type = 0;
	this->vendor = 0;
	
	config = ike_sa->get_peer_cfg(ike_sa);
	if (config)
	{
		auth = config->get_auth(config);
		if (auth->get_item(auth, AUTHN_EAP_IDENTITY, (void**)&id))
		{
			if (id->get_type(id) == ID_ANY)
			{	/* %any as configured EAP identity runs EAP-Identity first */
				this->do_eap_identity = TRUE;
			}
			else
			{
				ike_sa->set_eap_identity(ike_sa, id->clone(id));
			}
		}
	}
	return &this->public;
}
