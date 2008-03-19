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
 * $Id$
 */

#include "credential_manager.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/mutex.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/ocsp_request.h>
#include <credentials/certificates/ocsp_response.h>

#define MAX_CA_LEVELS 6

typedef struct private_credential_manager_t private_credential_manager_t;

/**
 * private data of credential_manager
 */
struct private_credential_manager_t {

	/**
	 * public functions
	 */
	credential_manager_t public;
	
	/**
	 * list of credential sets
	 */
	linked_list_t *sets;
	
	/**
	 * mutex to gain exclusive access
	 */
	mutex_t *mutex;
};

/** data to pass to create_private_enumerator */
typedef struct {
	private_credential_manager_t *this;
	key_type_t type;
	identification_t* keyid;
} private_data_t;

/** data to pass to create_cert_enumerator */
typedef struct {
	private_credential_manager_t *this;
	certificate_type_t cert;
	key_type_t key;
	identification_t *id;
	bool trusted;
} cert_data_t;

/** data to pass to create_cdp_enumerator */
typedef struct {
	private_credential_manager_t *this;
	certificate_type_t type;
	identification_t *id;
} cdp_data_t;

/** data to pass to create_shared_enumerator */
typedef struct {
	private_credential_manager_t *this;
	shared_key_type_t type;
	identification_t *me;
	identification_t *other;
} shared_data_t;

/**
 * cleanup function for cert data
 */
static void destroy_cert_data(cert_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * enumerator constructor for certificates
 */
static enumerator_t *create_cert(credential_set_t *set, cert_data_t *data)
{
	return set->create_cert_enumerator(set, data->cert, data->key, 
									   data->id, data->trusted);
}

/**
 * Implementation of credential_manager_t.create_cert_enumerator.
 */
static enumerator_t *create_cert_enumerator(private_credential_manager_t *this,
						certificate_type_t certificate, key_type_t key,
						identification_t *id, bool trusted)
{
	cert_data_t *data = malloc_thing(cert_data_t);
	data->this = this;
	data->cert = certificate;
	data->key = key;
	data->id = id;
	data->trusted = trusted;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_nested(this->sets->create_enumerator(this->sets),
									(void*)create_cert, data,
									(void*)destroy_cert_data);
}

/**
 * Implementation of credential_manager_t.get_cert.
 */
static certificate_t *get_cert(private_credential_manager_t *this,
						certificate_type_t cert, key_type_t key,
						identification_t *id, bool trusted)
{
	certificate_t *current, *found = NULL;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = create_cert_enumerator(this, cert, key, id, trusted);
	if (enumerator->enumerate(enumerator, &current))
	{
		/* TODO: best match? order by keyid, subject, sualtname */
		found = current->get_ref(current);
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return found;
}


/**
 * cleanup function for cdp data
 */
static void destroy_cdp_data(cdp_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * enumerator constructor for CDPs
 */
static enumerator_t *create_cdp(credential_set_t *set, cdp_data_t *data)
{
	return set->create_cdp_enumerator(set, data->type, data->id);
}
/**
 * Implementation of credential_manager_t.create_cdp_enumerator.
 */
static enumerator_t * create_cdp_enumerator(private_credential_manager_t *this,
								credential_type_t type, identification_t *id)
{
	cdp_data_t *data = malloc_thing(cdp_data_t);
	data->this = this;
	data->type = type;
	data->id = id;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_nested(this->sets->create_enumerator(this->sets),
									(void*)create_cdp, data,
									(void*)destroy_cdp_data);
}

/**
 * cleanup function for private data
 */
static void destroy_private_data(private_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * enumerator constructor for private keys
 */
static enumerator_t *create_private(credential_set_t *set, private_data_t *data)
{
	return set->create_private_enumerator(set, data->type, data->keyid);
}

/**
 * Implementation of credential_manager_t.get_private_by_keyid.
 */
static enumerator_t* create_private_enumerator(
									private_credential_manager_t *this,
								    key_type_t key, identification_t *keyid)
{
	private_data_t *data;
	
	data = malloc_thing(private_data_t);
	data->this = this;
	data->type = key;
	data->keyid = keyid;
	this->mutex->lock(this->mutex);
	return enumerator_create_nested(this->sets->create_enumerator(this->sets),
						(void*)create_private, data, (void*)destroy_private_data);
}

/**
 * Implementation of credential_manager_t.get_private_by_keyid.
 */   
static private_key_t *get_private_by_keyid(private_credential_manager_t *this,
										   key_type_t key, identification_t *keyid)
{
	private_key_t *found = NULL;
	enumerator_t *enumerator;
	
	enumerator = create_private_enumerator(this, key, keyid);
	if (enumerator->enumerate(enumerator, &found))
	{
		found->get_ref(found);
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * cleanup function for shared data
 */
static void destroy_shared_data(shared_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * enumerator constructor for shared keys
 */
static enumerator_t *create_shared(credential_set_t *set, shared_data_t *data)
{
	return set->create_shared_enumerator(set, data->type, data->me, data->other);
}

/**
 * Implementation of credential_manager_t.create_shared_enumerator.
 */
static enumerator_t *create_shared_enumerator(private_credential_manager_t *this, 
						shared_key_type_t type,
						identification_t *me, identification_t *other)
{
	shared_data_t *data = malloc_thing(shared_data_t);
	data->this = this;
	data->type = type;
	data->me = me;
	data->other = other;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_nested(this->sets->create_enumerator(this->sets),
									(void*)create_shared, data, 
									(void*)destroy_shared_data);
}

/**
 * Implementation of credential_manager_t.get_shared.
 */   
static shared_key_t *get_shared(private_credential_manager_t *this,
								shared_key_type_t type,	identification_t *me,
								identification_t *other)
{
	shared_key_t *current, *found = NULL;
	id_match_t *best_me = ID_MATCH_NONE, *best_other = ID_MATCH_NONE;
	id_match_t *match_me, *match_other;
	enumerator_t *enumerator;
	
	enumerator = create_shared_enumerator(this, type, me, other);
	while (enumerator->enumerate(enumerator, &current, &match_me, &match_other))
	{
		if (match_other > best_other ||
			(match_other == best_other && match_me > best_me))
		{
			DESTROY_IF(found);
			found = current->get_ref(current);
			best_me = match_me;
			best_other = match_other;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * forward declaration 
 */
static certificate_t *get_trusted_cert(private_credential_manager_t *this,
									   key_type_t type, identification_t *id,
									   auth_info_t *auth, bool crl, bool ocsp);

/**
 * credential_set_t implementation around an OCSP response
 */
typedef struct ocsp_wrapper_t {
	credential_set_t set;
	ocsp_response_t *response;
} ocsp_wrapper_t;

/**
 * enumerator for ocsp_wrapper_t.create_cert_enumerator()
 */
typedef struct {
	enumerator_t public;
	enumerator_t *inner;
	certificate_type_t cert;
	key_type_t key;
	identification_t *id;
} ocsp_wrapper_enumerator_t;

/**
 * enumerate function for ocsp_wrapper_enumerator_t
 */
static bool ocsp_wrapper_enum_enumerate(ocsp_wrapper_enumerator_t *this,
									    certificate_t **cert)
{
	certificate_t *current;
	public_key_t *public;

	while (this->inner->enumerate(this->inner, &current))
	{
		if (this->cert != CERT_ANY && this->cert != current->get_type(current))
		{	/* CERT type requested, but does not match */
			continue;
		}
		public = current->get_public_key(current);
		if (this->key != KEY_ANY && !public)
		{	/* key type requested, but no public key */
			DESTROY_IF(public);
			continue;
		}
		if (this->key != KEY_ANY && public && this->key != public->get_type(public))
		{	/* key type requested, but public key has another type */
			DESTROY_IF(public);
			continue;
		}
		DESTROY_IF(public);
		if (this->id && !current->has_subject(current, this->id))
		{	/* subject requested, but does not match */
			continue;
		}
		*cert = current;
		return TRUE;
	}
	return FALSE;
}

/**
 * destroy function for ocsp_wrapper_enumerator_t
 */
static void ocsp_wrapper_enum_destroy(ocsp_wrapper_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * implementation of ocsp_wrapper_t.set.create_cert_enumerator
 */
static enumerator_t *ocsp_wrapper_create_enumerator(ocsp_wrapper_t *this,
										certificate_type_t cert, key_type_t key,
										identification_t *id, bool trusted)
{
	ocsp_wrapper_enumerator_t *enumerator;
	
	if (trusted)
	{
		return NULL;
	}
	
	enumerator = malloc_thing(ocsp_wrapper_enumerator_t);
	enumerator->cert = cert;
	enumerator->key = key;
	enumerator->id = id;
	enumerator->inner = this->response->create_cert_enumerator(this->response);
	enumerator->public.enumerate = (void*)ocsp_wrapper_enum_enumerate;
	enumerator->public.destroy = (void*)ocsp_wrapper_enum_destroy;
	return &enumerator->public;
}

/**
 * create credential_set wrapper around an OCSP response
 */
static ocsp_wrapper_t *ocsp_wrapper_create(ocsp_response_t *response)
{
	ocsp_wrapper_t *this = malloc_thing(ocsp_wrapper_t);
	
	this->response = response;
	this->set.create_private_enumerator = (void*)return_null;
	this->set.create_cert_enumerator = (void*)ocsp_wrapper_create_enumerator;
	this->set.create_shared_enumerator = (void*)return_null;
	this->set.create_cdp_enumerator = (void*)return_null;

	return this;
}

/**
 * Do an OCSP request
 */
static certificate_t *fetch_ocsp(private_credential_manager_t *this, char *url,
								 certificate_t *subject, certificate_t *issuer)
{
	certificate_t *request, *response, *issuer_cert;
	chunk_t send, receive;
	identification_t *responder;
	auth_info_t *auth;
	ocsp_wrapper_t *wrapper;
	
	/* TODO: requestor name, signature */
	request = lib->creds->create(lib->creds,
						CRED_CERTIFICATE, CERT_X509_OCSP_REQUEST,
						BUILD_CA_CERT, issuer->get_ref(issuer),
						BUILD_CERT, subject->get_ref(subject), BUILD_END);
	if (!request)
	{
		DBG1(DBG_CFG, "  generating ocsp request failed");
		return NULL;
	}
	
	send = request->get_encoding(request);
	request->destroy(request);
	if (lib->fetcher->fetch(lib->fetcher, url, &receive, 
							FETCH_REQUEST_DATA, send,
							FETCH_REQUEST_TYPE, "application/ocsp-request",
							FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "  ocsp request to %s failed", url);
		chunk_free(&send);
		return NULL;
	}
	chunk_free(&send);
	
	response = lib->creds->create(lib->creds,
								  CRED_CERTIFICATE, CERT_X509_OCSP_RESPONSE,
								  BUILD_BLOB_ASN1_DER, receive, BUILD_END);
	if (!response)
	{
		DBG1(DBG_CFG, "  parsing ocsp response failed");
		return NULL;
	}
	
	responder = response->get_issuer(response);
	auth = auth_info_create();
	wrapper = ocsp_wrapper_create((ocsp_response_t*)response);
	this->sets->insert_first(this->sets, wrapper);
	issuer_cert = get_trusted_cert(this, KEY_ANY, responder, auth, FALSE, FALSE);
	this->sets->remove(this->sets, wrapper, NULL);
	free(wrapper);
	auth->destroy(auth);
	if (!issuer_cert)
	{
		DBG1(DBG_CFG, "  ocsp response untrusted: no signer certificate found");
		response->destroy(response);
		return NULL;
	}
	if (!response->issued_by(response, issuer_cert, TRUE))
	{
		DBG1(DBG_CFG, "  ocsp response untrusted: bad signature");
		response->destroy(response);
		issuer_cert->destroy(issuer_cert);
		return NULL;
	}
	issuer_cert->destroy(issuer_cert);
	
	/* TODO: cache response? */
	return response;
}

/**
 * validate a x509 certificate using OCSP
 */
static cert_validation_t check_ocsp(private_credential_manager_t *this,
								    x509_t *subject, x509_t *issuer, 
								    auth_info_t *auth)
{
	certificate_t *sub = (certificate_t*)subject;
	certificate_t *best_cert = NULL;
	certificate_t *cert;
	public_key_t *public;
	cert_validation_t valid = VALIDATION_SKIPPED;
	identification_t *keyid = NULL;
	bool stale = TRUE;
	
	/* derive the authorityKeyIdentifier from the issuer's public key */
	cert = &issuer->interface;
	public = cert->get_public_key(cert);
	if (public)
	{
		keyid = public->get_id(public, ID_PUBKEY_SHA1);
	}
	
	/* find a cached ocsp response by authorityKeyIdentifier */	
	if (keyid)
	{
		enumerator_t *enumerator = create_cert_enumerator(this,
										 CERT_X509_OCSP_RESPONSE,
										 KEY_ANY, keyid, TRUE);
		certificate_t *cert;

		while (enumerator->enumerate(enumerator, &cert))
		{
			if (cert->has_subject(cert, sub->get_subject(sub)))
			{
				/* select most recent ocsp response */
				if (best_cert == NULL || cert->is_newer(cert, best_cert))
				{
					DESTROY_IF(best_cert);
					best_cert = cert->get_ref(cert);
				}
			}
		}
		enumerator->destroy(enumerator);
	}

	/* check the validity of the cached ocsp response if one was found */
	if (best_cert)
	{
		stale = !best_cert->get_validity(best_cert, NULL, NULL, NULL);
		DBG1(DBG_CFG, "cached ocsp response is %s", stale? "stale":"valid");
	}

	/* fallback to URL fetching from CDPs */
	if (stale && keyid)
	{
		enumerator_t *enumerator = create_cdp_enumerator(this,
										 CERT_X509_OCSP_RESPONSE, keyid);
		char *uri;

		while (enumerator->enumerate(enumerator, &uri))
		{
			certificate_t* cert = fetch_ocsp(this, uri, &subject->interface,
														&issuer->interface);

			/* redefine default since we have at least one uri */
			valid = VALIDATION_FAILED;

			if (cert)
			{
				/* select most recent ocsp response until valid one is found */
				if (best_cert == NULL || cert->is_newer(cert, best_cert))
				{
					DESTROY_IF(best_cert);
					best_cert = cert;
					stale = !best_cert->get_validity(best_cert, NULL, NULL, NULL);
					DBG1(DBG_CFG, "ocsp response is %s", stale? "stale":"valid");
					if (!stale)
					{
						break;
					}
				}
				else
				{
					cert->destroy(cert);
				}
			}
		}
		enumerator->destroy(enumerator);
	}

	/* fallback to URL fetching from subject certificate's URIs */
	if (stale)
	{
		enumerator_t *enumerator = subject->create_ocsp_uri_enumerator(subject);
		char *uri;

		while (enumerator->enumerate(enumerator, &uri))
		{
			certificate_t* cert = fetch_ocsp(this, uri, &subject->interface,
														&issuer->interface);

			/* redefine default since we have at least one uri */
			valid = VALIDATION_FAILED;

			if (cert)
			{
				/* select most recent ocsp response until valid one is found */
				if (best_cert == NULL || cert->is_newer(cert, best_cert))
				{
					DESTROY_IF(best_cert);
					best_cert = cert;
					stale = !best_cert->get_validity(best_cert, NULL, NULL, NULL);
					DBG1(DBG_CFG, "ocsp response is %s", stale? "stale":"valid");
					if (!stale)
					{
						break;
					}
				}
				else
				{
					cert->destroy(cert);
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	DESTROY_IF(public);

	/* if we have an ocsp response, check the revocation status */
	if (best_cert)
	{
		time_t revocation, this_update, next_update;
		crl_reason_t reason;
		ocsp_response_t *response = (ocsp_response_t*)best_cert;
		
		valid = response->get_status(response, subject, issuer, &revocation,
									 &reason, &this_update, &next_update);
		switch (valid)
		{
			case VALIDATION_FAILED:
				DBG1(DBG_CFG, "subject not found in ocsp response");
				break;
			case VALIDATION_REVOKED:
				DBG1(DBG_CFG, "certificate was revoked on %T, reason: %N",
					 		  &revocation, crl_reason_names, reason);
				break;
			case VALIDATION_GOOD:
			case VALIDATION_UNKNOWN:
			default:
				break;
		}
		best_cert->destroy(best_cert);
	}
	
	if (auth)
	{
		auth->add_item(auth, AUTHZ_OCSP_VALIDATION, &valid);
	}
	return valid;
}

/**
 * fetch a CRL from an URL
 */
static certificate_t* fetch_crl(private_credential_manager_t *this, char *url)
{
	certificate_t *crl_cert;
	chunk_t chunk;
	
	/* TODO: unlock the manager while fetching? */
	DBG1(DBG_CFG, "fetching crl from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &chunk, FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "  crl fetching failed");
		return NULL;
	}
	crl_cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL,
								  BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
	if (!crl_cert)
	{
		DBG1(DBG_CFG, "  crl fetched successfully but parsing failed");
		return NULL;
	}
	
	/* verify the signature of the fetched crl */
	{
		bool ok;
		identification_t *issuer = crl_cert->get_issuer(crl_cert);
		auth_info_t *auth = auth_info_create();
		certificate_t *issuer_cert = get_trusted_cert(this, KEY_ANY, issuer,
													  auth, FALSE, FALSE);
		auth->destroy(auth);

		if (!issuer_cert)
		{
			DBG1(DBG_CFG, "  crl is untrusted: issuer certificate not found");
			crl_cert->destroy(crl_cert);
			return NULL;
		}
		ok = crl_cert->issued_by(crl_cert, issuer_cert, TRUE);
		issuer_cert->destroy(issuer_cert);

		DBG1(DBG_CFG, "  crl is %strusted: %s signature",
					   ok ? "":"un", ok ? "good" : "bad");
		if (!ok)
		{
			crl_cert->destroy(crl_cert);
			return NULL;
		}
	}
	return crl_cert;
}

/**
 * validate a x509 certificate using CRL
 */
static cert_validation_t check_crl(private_credential_manager_t *this,
								   x509_t *subject, x509_t *issuer, 
								   auth_info_t *auth)
{
	identification_t *keyid = NULL;
	certificate_t *best_cert = NULL;
	certificate_t *cert;
	public_key_t *public;
	cert_validation_t valid = VALIDATION_SKIPPED;
	bool stale = TRUE;
	
	/* derive the authorityKeyIdentifier from the issuer's public key */
	cert = &issuer->interface;
	public = cert->get_public_key(cert);
	if (public)
	{
		keyid = public->get_id(public, ID_PUBKEY_SHA1);
	}
	
	/* find a cached crl by authorityKeyIdentifier */
	if (keyid)
	{
		enumerator_t *enumerator = create_cert_enumerator(this, CERT_X509_CRL,
														KEY_ANY, keyid, TRUE);
		certificate_t *cert;

		while (enumerator->enumerate(enumerator, &cert))
		{
			/* select most recent crl */
			if (best_cert == NULL || cert->is_newer(cert, best_cert))
			{
				DESTROY_IF(best_cert);
				best_cert = cert->get_ref(cert);
			}
		}
		enumerator->destroy(enumerator);
	}

	/* check the validity of the cached crl if one was found */
	if (best_cert)
	{
		stale = !best_cert->get_validity(best_cert, NULL, NULL, NULL);
		DBG1(DBG_CFG, "cached crl is %s", stale? "stale":"valid");
	}

	/* fallback to fetching crls from cdps defined in ca info sections */
	if (stale && keyid)
	{
		enumerator_t *enumerator = create_cdp_enumerator(this, CERT_X509_CRL,
														 keyid);
		char *uri;

		while (enumerator->enumerate(enumerator, &uri))
		{
			certificate_t *cert = fetch_crl(this, uri);

			/* redefine default since we have at least one uri */
			valid = VALIDATION_FAILED;

			if (cert)
			{
				/* select most recent crl until valid one is found */
				if (best_cert == NULL || cert->is_newer(cert, best_cert))
				{
					DESTROY_IF(best_cert);
					best_cert = cert;
					stale = !best_cert->get_validity(best_cert, NULL, NULL, NULL);
					DBG1(DBG_CFG, "fetched crl is %s", stale? "stale":"valid");
					if (!stale)
					{
						break;
					}
				}
				else
				{
					cert->destroy(cert);
				}
			}
		}
		enumerator->destroy(enumerator);
	}

	/* fallback to fetching crls from cdps defined in the subject's certificate */
	if (stale)
	{
		enumerator_t *enumerator = subject->create_crl_uri_enumerator(subject);
		char *uri;

		while (enumerator->enumerate(enumerator, &uri))
		{
			certificate_t *cert = fetch_crl(this, uri);

			/* redefine default since we have at least one uri */
			valid = VALIDATION_FAILED;

			if (cert)
			{
				/* select most recent crl until valid one is found */
				if (best_cert == NULL || cert->is_newer(cert, best_cert))
				{
					DESTROY_IF(best_cert);
					best_cert = cert;
					stale = !best_cert->get_validity(best_cert, NULL, NULL, NULL);
					DBG1(DBG_CFG, "fetched crl is %s", stale? "stale":"valid");
					if (!stale)
					{
						break;
					}
				}
				else
				{
					cert->destroy(cert);
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	DESTROY_IF(public);

	/* if we have a crl, check the revocation status */
	if (best_cert)
	{
		chunk_t subject_serial = subject->get_serial(subject);
		chunk_t serial;
		time_t revocation;
		crl_reason_t reason;
		crl_t *crl = (crl_t*)best_cert;
		enumerator_t *enumerator = crl->create_enumerator(crl);

		/* redefine default */
		valid = stale ? VALIDATION_UNKNOWN : VALIDATION_GOOD;

		while (enumerator->enumerate(enumerator, &serial, &revocation, &reason))
		{
			if (chunk_equals(serial, subject_serial))
			{
				DBG1(DBG_CFG, "certificate was revoked on %T, reason: %N",
					 &revocation, crl_reason_names, reason);
				valid = VALIDATION_REVOKED;
				break;
			}
		}
		enumerator->destroy(enumerator);
		best_cert->destroy(best_cert);
	}

	if (auth)
	{
		auth->add_item(auth, AUTHZ_CRL_VALIDATION, &valid);
	}
	return valid;
}

/**
 * check a certificate for its lifetime
 */
static bool check_certificate(private_credential_manager_t *this,
							  certificate_t *subject, certificate_t *issuer,
							  bool crl, bool ocsp, auth_info_t *auth)
{
	time_t not_before, not_after;

	if (!subject->get_validity(subject, NULL, &not_before, &not_after))
	{
		DBG1(DBG_CFG, "certificate invalid (valid from %T to %T)",
			 &not_before, &not_after);
		return FALSE;
	}
	if (issuer && !subject->issued_by(subject, issuer, TRUE))
	{
		DBG1(DBG_CFG, "certificate %D not issued by %D",
			 subject->get_subject(subject), issuer->get_subject(issuer));
		return FALSE;
	}
	if (issuer && issuer->get_type(issuer) == CERT_X509 &&
		subject->get_type(subject) == CERT_X509)
	{
		if (ocsp)
		{
			switch (check_ocsp(this, (x509_t*)subject, (x509_t*)issuer, auth))
			{
				case VALIDATION_GOOD:
					DBG1(DBG_CFG, "certificate status is good");
					return TRUE;
				case VALIDATION_REVOKED:
					/* has already been logged */			
					return FALSE;
				case VALIDATION_SKIPPED:
					DBG2(DBG_CFG, "OCSP check skipped, no OCSP URI found");
					break;
				case VALIDATION_FAILED:
				case VALIDATION_UNKNOWN:
					DBG1(DBG_CFG, "OCSP check failed, fallback to CRL");
					break;
			}
		}
		if (crl)
		{
			switch (check_crl(this, (x509_t*)subject, (x509_t*)issuer, auth))
			{
				case VALIDATION_GOOD:
					DBG1(DBG_CFG, "certificate status is good");
					return TRUE;
				case VALIDATION_REVOKED:		
					/* has already been logged */			
					return FALSE;
				case VALIDATION_UNKNOWN:
					DBG1(DBG_CFG, "certificate status is unknown");
					break;
				case VALIDATION_FAILED:
				case VALIDATION_SKIPPED:
					DBG1(DBG_CFG, "certificate status is not available");
					break;		
				default:
					break;
			}
		}
	}
	return TRUE;
}

/**
 * credential_set_t implementation around a auth_info_t
 */
typedef struct auth_wrapper_t {
	credential_set_t set;
	auth_info_t *auth;
} auth_wrapper_t;

/**
 * enumerator for auth_wrapper_t.create_cert_enumerator()
 */
typedef struct {
	enumerator_t public;
	enumerator_t *inner;
	certificate_type_t cert;
	key_type_t key;
	identification_t *id;
} auth_wrapper_enumerator_t;

/**
 * enumerate function for auth_wrapper_enumerator_t
 */
static bool auth_wrapper_enum_enumerate(auth_wrapper_enumerator_t *this,
									    certificate_t **cert)
{
	auth_item_t type;
	certificate_t *current;
	public_key_t *public;

	while (this->inner->enumerate(this->inner, &type, &current))
	{
		if (type != AUTHN_SUBJECT_CERT && 
			type != AUTHN_IM_CERT)
		{
			continue;
		}

		if (this->cert != CERT_ANY && this->cert != current->get_type(current))
		{	/* CERT type requested, but does not match */
			continue;
		}
		public = current->get_public_key(current);
		if (this->key != KEY_ANY && !public)
		{	/* key type requested, but no public key */
			DESTROY_IF(public);
			continue;
		}
		if (this->key != KEY_ANY && public && this->key != public->get_type(public))
		{	/* key type requested, but public key has another type */
			DESTROY_IF(public);
			continue;
		}
		DESTROY_IF(public);
		if (this->id && !current->has_subject(current, this->id))
		{	/* subject requested, but does not match */
			continue;
		}
		*cert = current;
		return TRUE;
	}
	return FALSE;
}

/**
 * destroy function for auth_wrapper_enumerator_t
 */
static void auth_wrapper_enum_destroy(auth_wrapper_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * implementation of auth_wrapper_t.set.create_cert_enumerator
 */
static enumerator_t *auth_wrapper_create_enumerator(auth_wrapper_t *this,
										certificate_type_t cert, key_type_t key,
										identification_t *id, bool trusted)
{
	auth_wrapper_enumerator_t *enumerator;
	
	if (trusted)
	{
		return NULL;
	}
	
	enumerator = malloc_thing(auth_wrapper_enumerator_t);
	enumerator->cert = cert;
	enumerator->key = key;
	enumerator->id = id;
	enumerator->inner = this->auth->create_item_enumerator(this->auth);
	enumerator->public.enumerate = (void*)auth_wrapper_enum_enumerate;
	enumerator->public.destroy = (void*)auth_wrapper_enum_destroy;
	return &enumerator->public;
}

/**
 * create credential_set wrapper around auth_info_t
 */
static auth_wrapper_t *auth_wrapper_create(auth_info_t *auth)
{
	auth_wrapper_t *this = malloc_thing(auth_wrapper_t);
	
	this->auth = auth;
	this->set.create_private_enumerator = (void*)return_null;
	this->set.create_cert_enumerator = (void*)auth_wrapper_create_enumerator;
	this->set.create_shared_enumerator = (void*)return_null;
	this->set.create_cdp_enumerator = (void*)return_null;

	return this;
}

/**
 * Get a trusted certificate
 */
static certificate_t *get_trusted_cert(private_credential_manager_t *this,
									   key_type_t type, identification_t *id,
									   auth_info_t *auth, bool crl, bool ocsp)
{
	enumerator_t *enumerator;
	auth_wrapper_t *wrapper;
	certificate_t *subject, *issuer, *candidate;
	public_key_t *public;
	bool trusted = FALSE;
	auth_info_t *auth1, *auth2;
	u_int level = 0;
	
	this->mutex->lock(this->mutex);
	wrapper = auth_wrapper_create(auth);
	this->sets->insert_first(this->sets, wrapper);
	
	/* check if we have a trusted certificate for that peer */
	auth1 = auth_info_create();
	subject = get_cert(this, CERT_ANY, type, id, TRUE);
	if (subject)
	{
		if (check_certificate(this, subject, NULL, crl, ocsp, auth1))
		{
			public = subject->get_public_key(subject);
			if (public)
			{
				DBG2(DBG_CFG, "using trusted certificate %D",
					 subject->get_subject(subject));
				this->sets->remove(this->sets, wrapper, NULL);
				free(wrapper);
				this->mutex->unlock(this->mutex);
				auth->add_item(auth1, AUTHZ_SUBJECT_CERT, subject);
				public->destroy(public);
				auth->merge(auth, auth1);
				auth1->destroy(auth1);
				return subject;
			}
		}
		subject->destroy(subject);
	}
	auth1->destroy(auth1);
	
	/* check for an untrusted certificate */
	auth1 = auth_info_create();
	subject = get_cert(this, CERT_ANY, type, id, FALSE);
	if (!subject)
	{
		DBG1(DBG_CFG, "no end entity certificate found for %D", id);
	}
	else
	{
		issuer = subject;
		do
		{
			/* look for a trusted certificate */
			auth2 = auth_info_create();
			enumerator = create_cert_enumerator(this, issuer->get_type(issuer), 
									KEY_ANY, issuer->get_issuer(issuer), TRUE);
			while (enumerator->enumerate(enumerator, &candidate))
			{
				if (check_certificate(this, issuer, candidate, crl, ocsp,
									  issuer == subject ? auth2 : NULL) &&
					check_certificate(this, candidate, NULL, crl, ocsp, NULL))
				{
					DBG2(DBG_CFG, "using trusted root CA certificate %D",
						 candidate->get_subject(candidate));
					issuer = candidate;
					trusted = TRUE;
					auth1->merge(auth1, auth2);
					auth1->add_item(auth1, AUTHZ_CA_CERT, candidate);
					break;
				}
			}
			enumerator->destroy(enumerator);
			auth2->destroy(auth2);
			if (trusted)
			{
				break;
			}
			
			/* no trusted certificate found, look for an untrusted */
			enumerator = create_cert_enumerator(this, issuer->get_type(issuer), 
									KEY_ANY, issuer->get_issuer(issuer), FALSE);
			while (enumerator->enumerate(enumerator, &candidate))
			{
				auth2 = auth_info_create();
				if (check_certificate(this, issuer, candidate, crl, ocsp,
									  issuer == subject ? auth2 : NULL))
				{
					if (issuer != subject)
					{
						DBG2(DBG_CFG, "using intermediate CA certificate %D",
							 candidate->get_subject(candidate));
						auth1->add_item(auth1, AUTHZ_IM_CERT, candidate);
					}
					else
					{
						DBG2(DBG_CFG, "using end entity certificate %D",
							 candidate->get_subject(candidate));
					}
					issuer = candidate;
					auth1->merge(auth1, auth2);
					auth2->destroy(auth2);
					/* check next level */
					break;
				}
				auth2->destroy(auth2);
			}
			enumerator->destroy(enumerator);
		}
		while (++level < MAX_CA_LEVELS);
		
		if (!trusted)
		{
			subject->destroy(subject);
			subject = NULL;
		}
	}
	this->sets->remove(this->sets, wrapper, NULL);
	free(wrapper);
	this->mutex->unlock(this->mutex);
	if (subject)
	{
		auth->add_item(auth, AUTHZ_SUBJECT_CERT, subject);
		auth->merge(auth, auth1);
		auth1->destroy(auth1);
		return subject;
	}
	auth1->destroy(auth1);
	return NULL;
}

/**
 * Implementation of credential_manager_t.get_public.
 */
static public_key_t *get_public(private_credential_manager_t *this,
								key_type_t type, identification_t *id,
								auth_info_t *auth)
{
	public_key_t *public;
	certificate_t *cert;
	
	cert = get_trusted_cert(this, type, id, auth, TRUE, TRUE);
	if (cert)
	{
		public = cert->get_public_key(cert);
		cert->destroy(cert);
		return public;
	}
	return NULL;
}

/**
 * Get the issuing certificate of a subject certificate
 */
static certificate_t *get_issuer_cert(private_credential_manager_t *this,
									  certificate_t *subject)
{
	enumerator_t *enumerator;
	certificate_t *issuer = NULL, *candidate;
	
	enumerator = create_cert_enumerator(this, subject->get_type(subject), KEY_ANY, 
										subject->get_issuer(subject), FALSE);
	while (enumerator->enumerate(enumerator, &candidate))
	{
		if (subject->issued_by(subject, candidate, FALSE))
		{
			issuer = candidate->get_ref(candidate);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return issuer;
}

/**
 * Check if a certificate's keyid is contained in the auth helper
 */
static bool auth_contains_cacert(auth_info_t *auth, certificate_t *cert)
{
	enumerator_t *enumerator;
	identification_t *value;
	auth_item_t type;
	bool found = FALSE;

	enumerator = auth->create_item_enumerator(auth);
	while (enumerator->enumerate(enumerator, &type, &value))
	{
		if (type == AUTHN_CA_CERT && cert->equals(cert, (certificate_t*)value))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * build a trustchain from subject up to a trust anchor in trusted
 */
static auth_info_t *build_trustchain(private_credential_manager_t *this,
									 certificate_t *subject, auth_info_t *auth)
{	
	certificate_t *issuer, *current;
	auth_info_t *trustchain;
	u_int level = 0;
	
	trustchain = auth_info_create();
	
	if (!auth->get_item(auth, AUTHN_CA_CERT, (void**)&current))
	{
		/* no trust anchor specified, return this cert only */
		trustchain->add_item(trustchain, AUTHZ_SUBJECT_CERT, subject);
		return trustchain;
	}
	
	current = subject->get_ref(subject);
	while (TRUE)
	{
		if (auth_contains_cacert(auth, current))
		{
			trustchain->add_item(trustchain, AUTHZ_CA_CERT, current);
			current->destroy(current);
			return trustchain;
		}
		if (subject == current)
		{
			trustchain->add_item(trustchain, AUTHZ_SUBJECT_CERT, current);
		}
		else
		{
			trustchain->add_item(trustchain, AUTHZ_IM_CERT, current);
		}
		issuer = get_issuer_cert(this, current);
		if (!issuer || issuer->equals(issuer, current) || level > MAX_CA_LEVELS)
		{
			DESTROY_IF(issuer);
			current->destroy(current);
			break;
		}
		current->destroy(current);
		current = issuer;
		level++;
	}
	trustchain->destroy(trustchain);
	return NULL;
}

/**
 * find a private key of a give certificate
 */
static private_key_t *get_private_by_cert(private_credential_manager_t *this,
										  certificate_t *cert, key_type_t type)
{
	private_key_t *private = NULL;
	identification_t* keyid;
	public_key_t *public;

	public = cert->get_public_key(cert);
	if (public)
	{
		keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
		if (keyid)
		{
			private = get_private_by_keyid(this, type, keyid);
		}
		public->destroy(public);
	}
	return private;
}

/**
 * Implementation of credential_manager_t.get_private.
 */
static private_key_t *get_private(private_credential_manager_t *this,
								  key_type_t type, identification_t *id,
								  auth_info_t *auth)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	private_key_t *private = NULL;
	auth_info_t *trustchain;
	
	/* check if this is a lookup by key ID, and do it if so */
	if (id)
	{
		switch (id->get_type(id))
		{
			case ID_PUBKEY_SHA1:
			case ID_PUBKEY_INFO_SHA1:
				return get_private_by_keyid(this, type, id);
			default:
				break;
		}
	}
	
	this->mutex->lock(this->mutex);
	/* get all available end entity certificates for ourself */
	enumerator = create_cert_enumerator(this, CERT_ANY, type, id, FALSE);
	while (enumerator->enumerate(enumerator, &cert))
	{	
		private = get_private_by_cert(this, cert, type);
		if (private)
		{
			trustchain = build_trustchain(this, cert, auth);
			if (trustchain)
			{
				auth->merge(auth, trustchain);
				trustchain->destroy(trustchain);
				break;
			}
			private->destroy(private);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return private;
}

/**
 * Implementation of credential_manager_t.add_set.
 */
static void add_set(private_credential_manager_t *this,
							   credential_set_t *set)
{
	this->mutex->lock(this->mutex);
	this->sets->insert_last(this->sets, set);
	this->mutex->unlock(this->mutex);
}
/**
 * Implementation of credential_manager_t.remove_set.
 */
static void remove_set(private_credential_manager_t *this, credential_set_t *set)
{
	this->mutex->lock(this->mutex);
	this->sets->remove(this->sets, set, NULL);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of credential_manager_t.destroy
 */
static void destroy(private_credential_manager_t *this)
{
	this->sets->destroy(this->sets);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
credential_manager_t *credential_manager_create()
{
	private_credential_manager_t *this = malloc_thing(private_credential_manager_t);
	
	this->public.create_cert_enumerator = (enumerator_t *(*)(credential_manager_t *this,certificate_type_t cert, key_type_t key,identification_t *id,bool))create_cert_enumerator;
	this->public.create_shared_enumerator = (enumerator_t *(*)(credential_manager_t *this, shared_key_type_t type,identification_t *me, identification_t *other))create_shared_enumerator;
	this->public.create_cdp_enumerator = (enumerator_t *(*)(credential_manager_t*, credential_type_t type, identification_t *id))create_cdp_enumerator;
	this->public.get_cert = (certificate_t *(*)(credential_manager_t *this,certificate_type_t cert, key_type_t key,identification_t *, bool))get_cert;
	this->public.get_shared = (shared_key_t *(*)(credential_manager_t *this,shared_key_type_t type,identification_t *me, identification_t *other))get_shared;
	this->public.get_private = (private_key_t*(*)(credential_manager_t*, key_type_t type, identification_t *, auth_info_t*))get_private;
	this->public.get_public = (public_key_t*(*)(credential_manager_t*, key_type_t type, identification_t *, auth_info_t*))get_public;
	this->public.add_set = (void(*)(credential_manager_t*, credential_set_t *set))add_set;
	this->public.remove_set = (void(*)(credential_manager_t*, credential_set_t *set))remove_set;
	this->public.destroy = (void(*)(credential_manager_t*))destroy;
	
	this->sets = linked_list_create();
	this->mutex = mutex_create(MUTEX_RECURSIVE);
	
	return &this->public;
}

