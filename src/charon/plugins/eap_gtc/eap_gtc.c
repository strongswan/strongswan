/*
 * Copyright (C) 2007 Martin Willi
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
 * $Id: eap_gtc.c 3806 2008-04-15 05:56:35Z martin $
 */
 
#include "eap_gtc.h"

#include <daemon.h>
#include <library.h>
#include <crypto/hashers/hasher.h>

#include <security/pam_appl.h>

#define GTC_REQUEST_MSG "login"
#define GTC_PAM_SERVICE "login"

typedef struct private_eap_gtc_t private_eap_gtc_t;

/**
 * Private data of an eap_gtc_t object.
 */
struct private_eap_gtc_t {
	
	/**
	 * Public authenticator_t interface.
	 */
	eap_gtc_t public;
	
	/**
	 * ID of the server
	 */
	identification_t *server;
	
	/**
	 * ID of the peer
	 */
	identification_t *peer;
	
	/**
	 * EAP message identififier
	 */
	u_int8_t identifier;
};

typedef struct eap_gtc_header_t eap_gtc_header_t;

/**
 * packed eap GTC header struct
 */
struct eap_gtc_header_t {
	/** EAP code (REQUEST/RESPONSE) */
	u_int8_t code;
	/** unique message identifier */
	u_int8_t identifier;
	/** length of whole message */
	u_int16_t length;
	/** EAP type */
	u_int8_t type;
	/** type data */
	u_int8_t data[];
} __attribute__((__packed__));

/**
 * Implementation of eap_method_t.initiate for the peer
 */
static status_t initiate_peer(private_eap_gtc_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

/**
 * PAM conv callback function
 */
static int auth_conv(int num_msg, const struct pam_message **msg,
                	 struct pam_response **resp, char *password)
{
	struct pam_response *response;
	
	if (num_msg != 1)
	{
		return PAM_CONV_ERR;
	}
	response = malloc(sizeof(struct pam_response));
	response->resp = strdup(password);
	response->resp_retcode = 0;
	*resp = response;
	return PAM_SUCCESS;
}

/**
 * Authenticate a username/password using PAM
 */
static bool authenticate(char *service, char *user, char *password)
{
    pam_handle_t *pamh = NULL;
	static struct pam_conv conv;
    int ret;
	
	conv.conv = (void*)auth_conv;
	conv.appdata_ptr = password;
	
	ret = pam_start(service, user, &conv, &pamh);
	if (ret != PAM_SUCCESS)
	{
		DBG1(DBG_IKE, "EAP-GTC pam_start failed: %s",
			 pam_strerror(pamh, ret));
		return FALSE;
	}
	ret = pam_authenticate(pamh, 0);
	if (ret != PAM_SUCCESS)
	{
		DBG1(DBG_IKE, "EAP-GTC pam_authenticate failed: %s",
			 pam_strerror(pamh, ret));
	}
	pam_end(pamh, ret);
	return ret == PAM_SUCCESS;
}

/**
 * Implementation of eap_method_t.initiate for the server
 */
static status_t initiate_server(private_eap_gtc_t *this, eap_payload_t **out)
{
	eap_gtc_header_t *req;
	size_t len;
	
	len = strlen(GTC_REQUEST_MSG);
	req = alloca(sizeof(eap_gtc_header_t) + len);
	req->length = htons(sizeof(eap_gtc_header_t) + len);
	req->code = EAP_REQUEST;
	req->identifier = this->identifier;
	req->type = EAP_GTC;
	memcpy(req->data, GTC_REQUEST_MSG, len);
	
	*out = eap_payload_create_data(chunk_create((void*)req,
								   sizeof(eap_gtc_header_t) + len));
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process for the peer
 */
static status_t process_peer(private_eap_gtc_t *this,
							 eap_payload_t *in, eap_payload_t **out)
{
	eap_gtc_header_t *res;
	shared_key_t *shared;
	chunk_t key;
	size_t len;

	shared = charon->credentials->get_shared(charon->credentials, SHARED_EAP,
											 this->peer, this->server);
	if (shared == NULL)
	{
		DBG1(DBG_IKE, "no EAP key found for '%D' - '%D'",
			 this->server, this->peer);
		return FAILED;
	}
	key = shared->get_key(shared);
	len = key.len;
	
	/* TODO: According to the draft we should "SASLprep" password, RFC4013. */

	res = alloca(sizeof(eap_gtc_header_t) + len);
	res->length = htons(sizeof(eap_gtc_header_t) + len);
	res->code = EAP_RESPONSE;
	res->identifier = in->get_identifier(in);
	res->type = EAP_GTC;
	memcpy(res->data, key.ptr, len);
	
	shared->destroy(shared);
	
	*out = eap_payload_create_data(chunk_create((void*)res,
								   sizeof(eap_gtc_header_t) + len));
	return NEED_MORE;
}

/**
 * Implementation of eap_method_t.process for the server
 */
static status_t process_server(private_eap_gtc_t *this,
							   eap_payload_t *in, eap_payload_t **out)
{
	chunk_t data, encoding;
	char *user, *password, *service;
	
	data = chunk_skip(in->get_data(in), 5);
	if (this->identifier != in->get_identifier(in) || !data.len)
	{
		DBG1(DBG_IKE, "received invalid EAP-GTC message");
		return FAILED;
	}
	
	encoding = this->peer->get_encoding(this->peer);
	user = alloca(encoding.len + 1);
	memcpy(user, encoding.ptr, encoding.len);
	user[encoding.len] = '\0';
	
	password = alloca(data.len + 1);
	memcpy(password, data.ptr, data.len);
	password[data.len] = '\0';
	
	service = lib->settings->get_str(lib->settings,
						"charon.plugins.eap_gtc.pam_service", GTC_PAM_SERVICE);
	
	if (!authenticate(service, user, password))
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of eap_method_t.get_type.
 */
static eap_type_t get_type(private_eap_gtc_t *this, u_int32_t *vendor)
{
	*vendor = 0;
	return EAP_GTC;
}

/**
 * Implementation of eap_method_t.get_msk.
 */
static status_t get_msk(private_eap_gtc_t *this, chunk_t *msk)
{
	return FAILED;
}

/**
 * Implementation of eap_method_t.is_mutual.
 */
static bool is_mutual(private_eap_gtc_t *this)
{
	return FALSE;
}

/**
 * Implementation of eap_method_t.destroy.
 */
static void destroy(private_eap_gtc_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	free(this);
}

/**
 * Generic constructor
 */
static private_eap_gtc_t *eap_gtc_create_generic(identification_t *server,
												 identification_t *peer)
{
	private_eap_gtc_t *this = malloc_thing(private_eap_gtc_t);
	
	this->public.eap_method_interface.initiate = NULL;
	this->public.eap_method_interface.process = NULL;
	this->public.eap_method_interface.get_type = (eap_type_t(*)(eap_method_t*,u_int32_t*))get_type;
	this->public.eap_method_interface.is_mutual = (bool(*)(eap_method_t*))is_mutual;
	this->public.eap_method_interface.get_msk = (status_t(*)(eap_method_t*,chunk_t*))get_msk;
	this->public.eap_method_interface.destroy = (void(*)(eap_method_t*))destroy;
	
	/* private data */
	this->peer = peer->clone(peer);
	this->server = server->clone(server);
	this->identifier = 0;
	
	return this;
}

/*
 * see header
 */
eap_gtc_t *eap_gtc_create_server(identification_t *server, identification_t *peer)
{
	private_eap_gtc_t *this = eap_gtc_create_generic(server, peer);
	
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate_server;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process_server;

	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

/*
 * see header
 */
eap_gtc_t *eap_gtc_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_gtc_t *this = eap_gtc_create_generic(server, peer);
	
	this->public.eap_method_interface.initiate = (status_t(*)(eap_method_t*,eap_payload_t**))initiate_peer;
	this->public.eap_method_interface.process = (status_t(*)(eap_method_t*,eap_payload_t*,eap_payload_t**))process_peer;

	return &this->public;
}

