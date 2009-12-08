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
 */

#include <pthread.h>

#include "credential_manager.h"

#include <daemon.h>
#include <threading/rwlock.h>
#include <utils/linked_list.h>
#include <credentials/sets/cert_cache.h>
#include <credentials/sets/auth_cfg_wrapper.h>
#include <credentials/sets/ocsp_response_wrapper.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/ocsp_request.h>
#include <credentials/certificates/ocsp_response.h>

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
	 * thread local set of credentials, linked_list_t with credential_set_t's
	 */
	pthread_key_t local_sets;

	/**
	 * trust relationship and certificate cache
	 */
	cert_cache_t *cache;

	/**
	 * certificates queued for persistent caching
	 */
	linked_list_t *cache_queue;

	/**
	 * read-write lock to sets list
	 */
	rwlock_t *lock;
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

/** enumerator over local and global sets */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** enumerator over global sets */
	enumerator_t *global;
	/** enumerator over local sets */
	enumerator_t *local;
} sets_enumerator_t;

/**
 * destroy a sets_enumerator_t
 */
static void sets_enumerator_destroy(sets_enumerator_t *this)
{
	DESTROY_IF(this->global);
	DESTROY_IF(this->local);
	free(this);
}

/**
 * sets_enumerator_t.enumerate
 */
static bool sets_enumerator_enumerate(sets_enumerator_t *this,
									  credential_set_t **set)
{
	if (this->global)
	{
		if (this->global->enumerate(this->global, set))
		{
			return TRUE;
		}
		/* end of global sets, look for local */
		this->global->destroy(this->global);
		this->global = NULL;
	}
	if (this->local)
	{
		return this->local->enumerate(this->local, set);
	}
	return FALSE;
}

/**
 * create an enumerator over both, global and local sets
 */
static enumerator_t *create_sets_enumerator(private_credential_manager_t *this)
{
	linked_list_t *local;
	sets_enumerator_t *enumerator = malloc_thing(sets_enumerator_t);

	enumerator->public.enumerate = (void*)sets_enumerator_enumerate;
	enumerator->public.destroy = (void*)sets_enumerator_destroy;
	enumerator->global = this->sets->create_enumerator(this->sets);
	enumerator->local = NULL;
	local = pthread_getspecific(this->local_sets);
	if (local)
	{
		enumerator->local = local->create_enumerator(local);
	}
	return &enumerator->public;
}

/**
 * cleanup function for cert data
 */
static void destroy_cert_data(cert_data_t *data)
{
	data->this->lock->unlock(data->this->lock);
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

	this->lock->read_lock(this->lock);
	return enumerator_create_nested(create_sets_enumerator(this),
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

	enumerator = create_cert_enumerator(this, cert, key, id, trusted);
	if (enumerator->enumerate(enumerator, &current))
	{
		/* TODO: best match? order by keyid, subject, sualtname */
		found = current->get_ref(current);
	}
	enumerator->destroy(enumerator);
	return found;
}


/**
 * cleanup function for cdp data
 */
static void destroy_cdp_data(cdp_data_t *data)
{
	data->this->lock->unlock(data->this->lock);
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
								certificate_type_t type, identification_t *id)
{
	cdp_data_t *data = malloc_thing(cdp_data_t);
	data->this = this;
	data->type = type;
	data->id = id;

	this->lock->read_lock(this->lock);
	return enumerator_create_nested(create_sets_enumerator(this),
									(void*)create_cdp, data,
									(void*)destroy_cdp_data);
}

/**
 * cleanup function for private data
 */
static void destroy_private_data(private_data_t *data)
{
	data->this->lock->unlock(data->this->lock);
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
 * Implementation of credential_manager_t.create_private_enumerator.
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
	this->lock->read_lock(this->lock);
	return enumerator_create_nested(create_sets_enumerator(this),
									(void*)create_private, data,
									(void*)destroy_private_data);
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
	data->this->lock->unlock(data->this->lock);
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

	this->lock->read_lock(this->lock);
	return enumerator_create_nested(create_sets_enumerator(this),
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
 * add a credential set to the thread local list
 */
static void add_local_set(private_credential_manager_t *this,
						  credential_set_t *set)
{
	linked_list_t *sets;

	sets = pthread_getspecific(this->local_sets);
	if (!sets)
	{	/* first invocation */
		sets = linked_list_create();
		pthread_setspecific(this->local_sets, sets);
	}
	sets->insert_last(sets, set);
}

/**
 * remove a credential set from the thread local list
 */
static void remove_local_set(private_credential_manager_t *this,
							 credential_set_t *set)
{
	linked_list_t *sets;

	sets = pthread_getspecific(this->local_sets);
	sets->remove(sets, set, NULL);
}

/**
 * Implementation of credential_manager_t.cache_cert.
 */
static void cache_cert(private_credential_manager_t *this, certificate_t *cert)
{
	credential_set_t *set;
	enumerator_t *enumerator;

	if (this->lock->try_write_lock(this->lock))
	{
		enumerator = this->sets->create_enumerator(this->sets);
		while (enumerator->enumerate(enumerator, &set))
		{
			set->cache_cert(set, cert);
		}
		enumerator->destroy(enumerator);
	}
	else
	{	/* we can't cache now as other threads are active, queue for later */
		this->lock->read_lock(this->lock);
		this->cache_queue->insert_last(this->cache_queue, cert->get_ref(cert));
	}
	this->lock->unlock(this->lock);
}

/**
 * Try to cache certificates queued for caching
 */
static void cache_queue(private_credential_manager_t *this)
{
	credential_set_t *set;
	certificate_t *cert;
	enumerator_t *enumerator;

	if (this->cache_queue->get_count(this->cache_queue) > 0 &&
		this->lock->try_write_lock(this->lock))
	{
		while (this->cache_queue->remove_last(this->cache_queue,
											  (void**)&cert) == SUCCESS)
		{
			enumerator = this->sets->create_enumerator(this->sets);
			while (enumerator->enumerate(enumerator, &set))
			{
				set->cache_cert(set, cert);
			}
			enumerator->destroy(enumerator);
			cert->destroy(cert);
		}
		this->lock->unlock(this->lock);
	}
}

/**
 * forward declaration
 */
static enumerator_t *create_trusted_enumerator(private_credential_manager_t *this,
					key_type_t type, identification_t *id, bool crl, bool ocsp);

/**
 * Do an OCSP request
 */
static certificate_t *fetch_ocsp(private_credential_manager_t *this, char *url,
								 certificate_t *subject, certificate_t *issuer)
{
	certificate_t *request, *response;
	chunk_t send, receive;

	/* TODO: requestor name, signature */
	request = lib->creds->create(lib->creds,
						CRED_CERTIFICATE, CERT_X509_OCSP_REQUEST,
						BUILD_CA_CERT, issuer,
						BUILD_CERT, subject, BUILD_END);
	if (!request)
	{
		DBG1(DBG_CFG, "generating ocsp request failed");
		return NULL;
	}

	send = request->get_encoding(request);
	request->destroy(request);

	DBG1(DBG_CFG, "  requesting ocsp status from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &receive,
							FETCH_REQUEST_DATA, send,
							FETCH_REQUEST_TYPE, "application/ocsp-request",
							FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "ocsp request to %s failed", url);
		chunk_free(&send);
		return NULL;
	}
	chunk_free(&send);

	response = lib->creds->create(lib->creds,
								  CRED_CERTIFICATE, CERT_X509_OCSP_RESPONSE,
								  BUILD_BLOB_ASN1_DER, receive, BUILD_END);
	chunk_free(&receive);
	if (!response)
	{
		DBG1(DBG_CFG, "parsing ocsp response failed");
		return NULL;
	}
	return response;
}

/**
 * check the signature of an OCSP response
 */
static bool verify_ocsp(private_credential_manager_t *this,
						ocsp_response_t *response)
{
	certificate_t *issuer, *subject;
	identification_t *responder;
	ocsp_response_wrapper_t *wrapper;
	enumerator_t *enumerator;
	bool verified = FALSE;

	wrapper = ocsp_response_wrapper_create((ocsp_response_t*)response);
	add_local_set(this, &wrapper->set);

	subject = &response->certificate;
	responder = subject->get_issuer(subject);
	enumerator = create_trusted_enumerator(this, KEY_ANY, responder, FALSE, FALSE);
	while (enumerator->enumerate(enumerator, &issuer, NULL))
	{
		if (this->cache->issued_by(this->cache, subject, issuer))
		{
			DBG1(DBG_CFG, "  ocsp response correctly signed by \"%Y\"",
							 issuer->get_subject(issuer));
			verified = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	remove_local_set(this, &wrapper->set);
	wrapper->destroy(wrapper);
	return verified;
}

/**
 * Get the better of two OCSP responses, and check for usable OCSP info
 */
static certificate_t *get_better_ocsp(private_credential_manager_t *this,
									  certificate_t *cand, certificate_t *best,
									  x509_t *subject, x509_t *issuer,
									  cert_validation_t *valid, bool cache)
{
	ocsp_response_t *response;
	time_t revocation, this_update, next_update, valid_until;
	crl_reason_t reason;
	bool revoked = FALSE;

	response = (ocsp_response_t*)cand;

	/* check ocsp signature */
	if (!verify_ocsp(this, response))
	{
		DBG1(DBG_CFG, "ocsp response verification failed");
		cand->destroy(cand);
		return best;
	}
	/* check if response contains our certificate */
	switch (response->get_status(response, subject, issuer, &revocation, &reason,
								 &this_update, &next_update))
	{
		case VALIDATION_REVOKED:
			/* subject has been revoked by a valid OCSP response */
			DBG1(DBG_CFG, "certificate was revoked on %T, reason: %N",
						  &revocation, TRUE, crl_reason_names, reason);
			revoked = TRUE;
			break;
		case VALIDATION_GOOD:
			/* results in either good or stale */
			break;
		default:
		case VALIDATION_FAILED:
			/* candidate unusable, does not contain our cert */
			DBG1(DBG_CFG, "  ocsp response contains no status on our certificate");
			cand->destroy(cand);
			return best;
	}

	/* select the better of the two responses */
	if (best == NULL || cand->is_newer(cand, best))
	{
		DESTROY_IF(best);
		best = cand;
		if (best->get_validity(best, NULL, NULL, &valid_until))
		{
			DBG1(DBG_CFG, "  ocsp response is valid: until %T",
							 &valid_until, FALSE);
			*valid = VALIDATION_GOOD;
			if (cache)
			{	/* cache non-stale only, stale certs get refetched */
				cache_cert(this, best);
			}
		}
		else
		{
			DBG1(DBG_CFG, "  ocsp response is stale: since %T",
							 &valid_until, FALSE);
			*valid = VALIDATION_STALE;
		}
	}
	else
	{
		*valid = VALIDATION_STALE;
		cand->destroy(cand);
	}
	if (revoked)
	{	/* revoked always counts, even if stale */
		*valid = VALIDATION_REVOKED;
	}
	return best;
}

/**
 * validate a x509 certificate using OCSP
 */
static cert_validation_t check_ocsp(private_credential_manager_t *this,
									x509_t *subject, x509_t *issuer,
									auth_cfg_t *auth)
{
	enumerator_t *enumerator;
	cert_validation_t valid = VALIDATION_SKIPPED;
	certificate_t *best = NULL, *current;
	identification_t *keyid = NULL;
	public_key_t *public;
	chunk_t chunk;
	char *uri = NULL;

	/** lookup cache for valid OCSP responses */
	enumerator = create_cert_enumerator(this, CERT_X509_OCSP_RESPONSE,
										KEY_ANY, NULL, FALSE);
	while (enumerator->enumerate(enumerator, &current))
	{
		current->get_ref(current);
		best = get_better_ocsp(this, current, best, subject, issuer,
							   &valid, FALSE);
		if (best && valid != VALIDATION_STALE)
		{
			DBG1(DBG_CFG, "  using cached ocsp response");
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* derive the authorityKeyIdentifier from the issuer's public key */
	current = &issuer->interface;
	public = current->get_public_key(current);
	if (public && public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &chunk))
	{
		keyid = identification_create_from_encoding(ID_KEY_ID, chunk);
	}
	/** fetch from configured OCSP responder URLs */
	if (keyid && valid != VALIDATION_GOOD && valid != VALIDATION_REVOKED)
	{
		enumerator = create_cdp_enumerator(this, CERT_X509_OCSP_RESPONSE, keyid);
		while (enumerator->enumerate(enumerator, &uri))
		{
			current = fetch_ocsp(this, uri, &subject->interface,
								 &issuer->interface);
			if (current)
			{
				best = get_better_ocsp(this, current, best, subject, issuer,
									   &valid, TRUE);
				if (best && valid != VALIDATION_STALE)
				{
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	DESTROY_IF(public);
	DESTROY_IF(keyid);

	/* fallback to URL fetching from subject certificate's URIs */
	if (valid != VALIDATION_GOOD && valid != VALIDATION_REVOKED)
	{
		enumerator = subject->create_ocsp_uri_enumerator(subject);
		while (enumerator->enumerate(enumerator, &uri))
		{
			current = fetch_ocsp(this, uri, &subject->interface,
								 &issuer->interface);
			if (current)
			{
				best = get_better_ocsp(this, current, best, subject, issuer,
									   &valid, TRUE);
				if (best && valid != VALIDATION_STALE)
				{
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	/* an uri was found, but no result. switch validation state to failed */
	if (valid == VALIDATION_SKIPPED && uri)
	{
		valid = VALIDATION_FAILED;
	}
	if (auth)
	{
		auth->add(auth, AUTH_RULE_OCSP_VALIDATION, valid);
		if (valid == VALIDATION_GOOD)
		{	/* successful OCSP check fulfills also CRL constraint */
			auth->add(auth, AUTH_RULE_CRL_VALIDATION, VALIDATION_GOOD);
		}
	}
	DESTROY_IF(best);
	return valid;
}

/**
 * fetch a CRL from an URL
 */
static certificate_t* fetch_crl(private_credential_manager_t *this, char *url)
{
	certificate_t *crl;
	chunk_t chunk;

	DBG1(DBG_CFG, "  fetching crl from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &chunk, FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "crl fetching failed");
		return NULL;
	}
	crl = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL,
							 BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
	chunk_free(&chunk);
	if (!crl)
	{
		DBG1(DBG_CFG, "crl fetched successfully but parsing failed");
		return NULL;
	}
	return crl;
}

/**
 * check the signature of an CRL
 */
static bool verify_crl(private_credential_manager_t *this, certificate_t *crl)
{
	certificate_t *issuer;
	enumerator_t *enumerator;
	bool verified = FALSE;

	enumerator = create_trusted_enumerator(this, KEY_ANY, crl->get_issuer(crl),
										   FALSE, FALSE);
	while (enumerator->enumerate(enumerator, &issuer, NULL))
	{
		if (this->cache->issued_by(this->cache, crl, issuer))
		{
			DBG1(DBG_CFG, "  crl correctly signed by \"%Y\"",
						   issuer->get_subject(issuer));
			verified = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return verified;
}

/**
 * Get the better of two CRLs, and check for usable CRL info
 */
static certificate_t *get_better_crl(private_credential_manager_t *this,
									 certificate_t *cand, certificate_t *best,
									 x509_t *subject, x509_t *issuer,
									 cert_validation_t *valid, bool cache)
{
	enumerator_t *enumerator;
	time_t revocation, valid_until;
	crl_reason_t reason;
	chunk_t serial;
	crl_t *crl;

	/* check CRL signature */
	if (!verify_crl(this, cand))
	{
		DBG1(DBG_CFG, "crl response verification failed");
		cand->destroy(cand);
		return best;
	}

	crl = (crl_t*)cand;
	enumerator = crl->create_enumerator(crl);
	while (enumerator->enumerate(enumerator, &serial, &revocation, &reason))
	{
		if (chunk_equals(serial, subject->get_serial(subject)))
		{
			DBG1(DBG_CFG, "certificate was revoked on %T, reason: %N",
				 &revocation, TRUE, crl_reason_names, reason);
			*valid = VALIDATION_REVOKED;
			enumerator->destroy(enumerator);
			DESTROY_IF(best);
			return cand;
		}
	}
	enumerator->destroy(enumerator);

	/* select the better of the two CRLs */
	if (best == NULL || cand->is_newer(cand, best))
	{
		DESTROY_IF(best);
		best = cand;
		if (best->get_validity(best, NULL, NULL, &valid_until))
		{
			DBG1(DBG_CFG, "  crl is valid: until %T", &valid_until, FALSE);
			*valid = VALIDATION_GOOD;
			if (cache)
			{	/* we cache non-stale crls only, as a stale crls are refetched */
				cache_cert(this, best);
			}
		}
		else
		{
			DBG1(DBG_CFG, "  crl is stale: since %T", &valid_until, FALSE);
			*valid = VALIDATION_STALE;
		}
	}
	else
	{
		*valid = VALIDATION_STALE;
		cand->destroy(cand);
	}
	return best;
}

/**
 * validate a x509 certificate using CRL
 */
static cert_validation_t check_crl(private_credential_manager_t *this,
								   x509_t *subject, x509_t *issuer,
								   auth_cfg_t *auth)
{
	cert_validation_t valid = VALIDATION_SKIPPED;
	identification_t *keyid = NULL;
	certificate_t *best = NULL;
	certificate_t *current;
	public_key_t *public;
	enumerator_t *enumerator;
	chunk_t chunk;
	char *uri = NULL;

	/* derive the authorityKeyIdentifier from the issuer's public key */
	current = &issuer->interface;
	public = current->get_public_key(current);
	if (public && public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &chunk))
	{
		keyid = identification_create_from_encoding(ID_KEY_ID, chunk);

		/* find a cached crl by authorityKeyIdentifier */
		enumerator = create_cert_enumerator(this, CERT_X509_CRL, KEY_ANY,
											keyid, FALSE);
		while (enumerator->enumerate(enumerator, &current))
		{
			current->get_ref(current);
			best = get_better_crl(this, current, best, subject, issuer,
								  &valid, FALSE);
			if (best && valid != VALIDATION_STALE)
			{
				DBG1(DBG_CFG, "  using cached crl");
				break;
			}
		}
		enumerator->destroy(enumerator);

		/* fallback to fetching crls from credential sets cdps */
		if (valid != VALIDATION_GOOD && valid != VALIDATION_REVOKED)
		{
			enumerator = create_cdp_enumerator(this, CERT_X509_CRL, keyid);

			while (enumerator->enumerate(enumerator, &uri))
			{
				current = fetch_crl(this, uri);
				if (current)
				{
					best = get_better_crl(this, current, best, subject, issuer,
										  &valid, TRUE);
					if (best && valid != VALIDATION_STALE)
					{
						break;
					}
				}
			}
			enumerator->destroy(enumerator);
		}
		keyid->destroy(keyid);
	}
	DESTROY_IF(public);

	/* fallback to fetching crls from cdps from subject's certificate */
	if (valid != VALIDATION_GOOD && valid != VALIDATION_REVOKED)
	{
		enumerator = subject->create_crl_uri_enumerator(subject);

		while (enumerator->enumerate(enumerator, &uri))
		{
			current = fetch_crl(this, uri);
			if (current)
			{
				best = get_better_crl(this, current, best, subject, issuer,
									  &valid, TRUE);
				if (best && valid != VALIDATION_STALE)
				{
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
	}

	/* an uri was found, but no result. switch validation state to failed */
	if (valid == VALIDATION_SKIPPED && uri)
	{
		valid = VALIDATION_FAILED;
	}
	if (auth)
	{
		if (valid == VALIDATION_SKIPPED)
		{	/* if we skipped CRL validation, we use the result of OCSP for
			 * constraint checking */
			auth->add(auth, AUTH_RULE_CRL_VALIDATION,
					  auth->get(auth, AUTH_RULE_OCSP_VALIDATION));
		}
		else
		{
			auth->add(auth, AUTH_RULE_CRL_VALIDATION, valid);
		}
	}
	DESTROY_IF(best);
	return valid;
}

/**
 * check a certificate for optional IP address block constraints
 */
static bool check_ip_addr_block_constraints(x509_t *subject, x509_t *issuer)
{
	bool subject_constraint = subject->get_flags(subject) & X509_IP_ADDR_BLOCKS;
	bool issuer_constraint = issuer->get_flags(issuer) & X509_IP_ADDR_BLOCKS;
	bool contained = TRUE;

	enumerator_t *subject_enumerator, *issuer_enumerator;
	traffic_selector_t *subject_ts, *issuer_ts;

	if (!subject_constraint && !issuer_constraint)
	{
		return TRUE;		
	}
	if (!subject_constraint)
	{
		DBG1(DBG_CFG, "subject certficate lacks ipAddrBlocks extension");
		return FALSE;
	}
	if (!issuer_constraint)
	{
		DBG1(DBG_CFG, "issuer certficate lacks ipAddrBlocks extension");
		return FALSE;		
	}
	subject_enumerator = subject->create_ipAddrBlock_enumerator(subject);
	while (subject_enumerator->enumerate(subject_enumerator, &subject_ts))
	{
		contained = FALSE;

		issuer_enumerator = issuer->create_ipAddrBlock_enumerator(issuer);
		while (issuer_enumerator->enumerate(issuer_enumerator, &issuer_ts))
		{
			if (subject_ts->is_contained_in(subject_ts, issuer_ts))
			{
				DBG2(DBG_CFG, "  subject address block %R is contained in "
							  "issuer address block %R", subject_ts, issuer_ts);
				contained = TRUE;
				break;
			}
		}
		issuer_enumerator->destroy(issuer_enumerator);
		if (!contained)
		{
			DBG1(DBG_CFG, "subject address block %R is not contained in any "
						  "issuer address block", subject_ts);
			break;
		}
	}
	subject_enumerator->destroy(subject_enumerator);
	return contained;	
}

/**
 * check a certificate for its lifetime
 */
static bool check_certificate(private_credential_manager_t *this,
							  certificate_t *subject, certificate_t *issuer,
							  bool crl, bool ocsp, auth_cfg_t *auth)
{
	time_t not_before, not_after;

	if (!subject->get_validity(subject, NULL, &not_before, &not_after))
	{
		DBG1(DBG_CFG, "subject certificate invalid (valid from %T to %T)",
			 &not_before, FALSE, &not_after, FALSE);
		return FALSE;
	}
	if (!issuer->get_validity(issuer, NULL, &not_before, &not_after))
	{
		DBG1(DBG_CFG, "issuer certificate invalid (valid from %T to %T)",
			 &not_before, FALSE, &not_after, FALSE);
		return FALSE;
	}
	if (issuer->get_type(issuer) == CERT_X509 &&
		subject->get_type(subject) == CERT_X509)
	{
		if (!check_ip_addr_block_constraints((x509_t*)subject, (x509_t*)issuer))
		{
			return FALSE;
		}
		if (ocsp || crl)
		{
			DBG1(DBG_CFG, "checking certificate status of \"%Y\"",
						   subject->get_subject(subject));
		}
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
					DBG2(DBG_CFG, "ocsp check skipped, no ocsp found");
					break;
				case VALIDATION_STALE:
					DBG1(DBG_CFG, "ocsp information stale, fallback to crl");
					break;
				case VALIDATION_FAILED:
					DBG1(DBG_CFG, "ocsp check failed, fallback to crl");
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
				case VALIDATION_FAILED:
				case VALIDATION_SKIPPED:
					DBG1(DBG_CFG, "certificate status is not available");
					break;
				case VALIDATION_STALE:
					DBG1(DBG_CFG, "certificate status is unknown, crl is stale");
					break;
			}
		}
	}
	return TRUE;
}

/**
 * Get a trusted certificate from a credential set
 */
static certificate_t *get_pretrusted_cert(private_credential_manager_t *this,
										  key_type_t type, identification_t *id)
{
	certificate_t *subject;
	public_key_t *public;

	subject = get_cert(this, CERT_ANY, type, id, TRUE);
	if (!subject)
	{
		return NULL;
	}
	public = subject->get_public_key(subject);
	if (!public)
	{
		subject->destroy(subject);
		return NULL;
	}
	public->destroy(public);
	return subject;
}

/**
 * Get the issuing certificate of a subject certificate
 */
static certificate_t *get_issuer_cert(private_credential_manager_t *this,
									  certificate_t *subject, bool trusted)
{
	enumerator_t *enumerator;
	certificate_t *issuer = NULL, *candidate;

	enumerator = create_cert_enumerator(this, subject->get_type(subject), KEY_ANY,
										subject->get_issuer(subject), trusted);
	while (enumerator->enumerate(enumerator, &candidate))
	{
		if (this->cache->issued_by(this->cache, subject, candidate))
		{
			issuer = candidate->get_ref(candidate);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return issuer;
}

/**
 * try to verify the trust chain of subject, return TRUE if trusted
 */
static bool verify_trust_chain(private_credential_manager_t *this,
							   certificate_t *subject, auth_cfg_t *result,
							   bool trusted, bool crl, bool ocsp)
{
	certificate_t *current, *issuer;
	x509_t *x509;
	auth_cfg_t *auth;
	int pathlen, pathlen_constraint;

	auth = auth_cfg_create();
	current = subject->get_ref(subject);

	for (pathlen = 0; pathlen <= X509_MAX_PATH_LEN; pathlen++)
	{
		issuer = get_issuer_cert(this, current, TRUE);
		if (issuer)
		{
			/* accept only self-signed CAs as trust anchor */
			if (this->cache->issued_by(this->cache, issuer, issuer))
			{
				auth->add(auth, AUTH_RULE_CA_CERT, issuer->get_ref(issuer));
				DBG1(DBG_CFG, "  using trusted ca certificate \"%Y\"",
							  issuer->get_subject(issuer));
				trusted = TRUE;
			}
			else
			{
				auth->add(auth, AUTH_RULE_IM_CERT, issuer->get_ref(issuer));
				DBG1(DBG_CFG, "  using trusted intermediate ca certificate "
					 "\"%Y\"", issuer->get_subject(issuer));
			}
		}
		else
		{
			issuer = get_issuer_cert(this, current, FALSE);
			if (issuer)
			{
				if (current->equals(current, issuer))
				{
					DBG1(DBG_CFG, "  self-signed certificate \"%Y\" is not trusted",
						 current->get_subject(current));
					issuer->destroy(issuer);
					break;
				}
				auth->add(auth, AUTH_RULE_IM_CERT, issuer->get_ref(issuer));
				DBG1(DBG_CFG, "  using untrusted intermediate certificate "
					 "\"%Y\"", issuer->get_subject(issuer));
			}
			else
			{
				DBG1(DBG_CFG, "no issuer certificate found for \"%Y\"",
					 current->get_subject(current));
				break;
			}
		}
		if (!check_certificate(this, current, issuer, crl, ocsp,
							   current == subject ? auth : NULL))
		{
			trusted = FALSE;
			issuer->destroy(issuer);
			break;
		}

		/* check path length constraint */
		x509 = (x509_t*)issuer;
		pathlen_constraint = x509->get_pathLenConstraint(x509);
		if (pathlen_constraint != X509_NO_PATH_LEN_CONSTRAINT &&
			pathlen > pathlen_constraint)
		{
			DBG1(DBG_CFG, "path length of %d violates constraint of %d",
				 pathlen, pathlen_constraint);
			trusted = FALSE;
			issuer->destroy(issuer);
			break;
		}
		current->destroy(current);
		current = issuer;
		if (trusted)
		{
			DBG1(DBG_CFG, "  reached self-signed root ca with a path length of %d",
						  pathlen);
			break;
		}
	}
	current->destroy(current);
	if (pathlen > X509_MAX_PATH_LEN)
	{
		DBG1(DBG_CFG, "maximum path length of %d exceeded", X509_MAX_PATH_LEN);
	}
	if (trusted)
	{
		result->merge(result, auth, FALSE);
	}
	auth->destroy(auth);
	return trusted;
}

/**
 * enumerator for trusted certificates
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** enumerator over candidate peer certificates */
	enumerator_t *candidates;
	/** reference to the credential_manager */
	private_credential_manager_t *this;
	/** type of the requested key */
	key_type_t type;
	/** identity the requested key belongs to */
	identification_t *id;
	/** TRUE to do CRL checking */
	bool crl;
	/** TRUE to do OCSP checking */
	bool ocsp;
	/** pretrusted certificate we have served at first invocation */
	certificate_t *pretrusted;
	/** currently enumerating auth config */
	auth_cfg_t *auth;
} trusted_enumerator_t;

/**
 * Implements trusted_enumerator_t.enumerate
 */
static bool trusted_enumerate(trusted_enumerator_t *this,
							  certificate_t **cert, auth_cfg_t **auth)
{
	certificate_t *current;

	DESTROY_IF(this->auth);
	this->auth = auth_cfg_create();

	if (!this->candidates)
	{
		/* first invocation, build enumerator for next one */
		this->candidates = create_cert_enumerator(this->this, CERT_ANY,
												  this->type, this->id, FALSE);
		/* check if we have a trusted certificate for that peer */
		this->pretrusted = get_pretrusted_cert(this->this, this->type, this->id);
		if (this->pretrusted)
		{
			/* if we find a trusted self signed certificate, we just accept it.
			 * However, in order to fulfill authorization rules, we try to build
			 * the trust chain if it is not self signed */
			if (this->this->cache->issued_by(this->this->cache,
								   this->pretrusted, this->pretrusted) ||
				verify_trust_chain(this->this, this->pretrusted, this->auth,
								   TRUE, this->crl, this->ocsp))
			{
				this->auth->add(this->auth, AUTH_RULE_SUBJECT_CERT,
								this->pretrusted->get_ref(this->pretrusted));
				DBG1(DBG_CFG, "  using trusted certificate \"%Y\"",
					 this->pretrusted->get_subject(this->pretrusted));
				*cert = this->pretrusted;
				if (auth)
				{
					*auth = this->auth;
				}
				return TRUE;
			}
		}
	}
	/* try to verify the trust chain for each certificate found */
	while (this->candidates->enumerate(this->candidates, &current))
	{
		if (this->pretrusted &&
			this->pretrusted->equals(this->pretrusted, current))
		{	/* skip pretrusted certificate we already served */
			continue;
		}

		DBG1(DBG_CFG, "  using certificate \"%Y\"",
			 current->get_subject(current));
		if (verify_trust_chain(this->this, current, this->auth, FALSE,
							   this->crl, this->ocsp))
		{
			*cert = current;
			if (auth)
			{
				*auth = this->auth;
			}
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Implements trusted_enumerator_t.destroy
 */
static void trusted_destroy(trusted_enumerator_t *this)
{
	DESTROY_IF(this->pretrusted);
	DESTROY_IF(this->auth);
	DESTROY_IF(this->candidates);
	free(this);
}

/**
 * create an enumerator over trusted certificates and their trustchain
 */
static enumerator_t *create_trusted_enumerator(private_credential_manager_t *this,
					key_type_t type, identification_t *id, bool crl, bool ocsp)
{
	trusted_enumerator_t *enumerator = malloc_thing(trusted_enumerator_t);

	enumerator->public.enumerate = (void*)trusted_enumerate;
	enumerator->public.destroy = (void*)trusted_destroy;

	enumerator->candidates = NULL;
	enumerator->this = this;
	enumerator->type = type;
	enumerator->id = id;
	enumerator->crl = crl;
	enumerator->ocsp = ocsp;
	enumerator->pretrusted = NULL;
	enumerator->auth = NULL;

	return &enumerator->public;
}

/**
 * enumerator for public keys
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** enumerator over candidate peer certificates */
	enumerator_t *inner;
	/** reference to the credential_manager */
	private_credential_manager_t *this;
	/** currently enumerating key */
	public_key_t *current;
	/** credset wrapper around auth config */
	auth_cfg_wrapper_t *wrapper;
} public_enumerator_t;

/**
 * Implements public_enumerator_t.enumerate
 */
static bool public_enumerate(public_enumerator_t *this,
							 public_key_t **key, auth_cfg_t **auth)
{
	certificate_t *cert;

	while (this->inner->enumerate(this->inner, &cert, auth))
	{
		DESTROY_IF(this->current);
		this->current = cert->get_public_key(cert);
		if (this->current)
		{
			*key = this->current;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Implements public_enumerator_t.destroy
 */
static void public_destroy(public_enumerator_t *this)
{
	DESTROY_IF(this->current);
	this->inner->destroy(this->inner);
	if (this->wrapper)
	{
		remove_local_set(this->this, &this->wrapper->set);
		this->wrapper->destroy(this->wrapper);
	}
	this->this->lock->unlock(this->this->lock);

	/* check for delayed certificate cache queue */
	cache_queue(this->this);
	free(this);
}

/**
 * Implementation of credential_manager_t.create_public_enumerator.
 */
static enumerator_t* create_public_enumerator(private_credential_manager_t *this,
						key_type_t type, identification_t *id, auth_cfg_t *auth)
{
	public_enumerator_t *enumerator = malloc_thing(public_enumerator_t);

	enumerator->public.enumerate = (void*)public_enumerate;
	enumerator->public.destroy = (void*)public_destroy;
	enumerator->inner = create_trusted_enumerator(this, type, id, TRUE, TRUE);
	enumerator->this = this;
	enumerator->current = NULL;
	enumerator->wrapper = NULL;
	if (auth)
	{
		enumerator->wrapper = auth_cfg_wrapper_create(auth);
		add_local_set(this, &enumerator->wrapper->set);
	}
	this->lock->read_lock(this->lock);
	return &enumerator->public;
}

/**
 * Check if a certificate's keyid is contained in the auth helper
 */
static bool auth_contains_cacert(auth_cfg_t *auth, certificate_t *cert)
{
	enumerator_t *enumerator;
	identification_t *value;
	auth_rule_t type;
	bool found = FALSE;

	enumerator = auth->create_enumerator(auth);
	while (enumerator->enumerate(enumerator, &type, &value))
	{
		if (type == AUTH_RULE_CA_CERT &&
			cert->equals(cert, (certificate_t*)value))
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
static auth_cfg_t *build_trustchain(private_credential_manager_t *this,
									 certificate_t *subject, auth_cfg_t *auth)
{
	certificate_t *issuer, *current;
	auth_cfg_t *trustchain;
	int pathlen = 0;

	trustchain = auth_cfg_create();

	current = auth->get(auth, AUTH_RULE_CA_CERT);
	if (!current)
	{
		/* no trust anchor specified, return this cert only */
		trustchain->add(trustchain, AUTH_RULE_SUBJECT_CERT,
						subject->get_ref(subject));
		return trustchain;
	}
	current = subject->get_ref(subject);
	while (TRUE)
	{
		if (auth_contains_cacert(auth, current))
		{
			trustchain->add(trustchain, AUTH_RULE_CA_CERT, current);
			return trustchain;
		}
		if (subject == current)
		{
			trustchain->add(trustchain, AUTH_RULE_SUBJECT_CERT, current);
		}
		else
		{
			trustchain->add(trustchain, AUTH_RULE_IM_CERT, current);
		}
		issuer = get_issuer_cert(this, current, FALSE);
		if (!issuer || issuer->equals(issuer, current) ||
			pathlen > X509_MAX_PATH_LEN)
		{
			DESTROY_IF(issuer);
			break;
		}
		current = issuer;
		pathlen++;
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
	identification_t *keyid;
	chunk_t chunk;
	public_key_t *public;

	public = cert->get_public_key(cert);
	if (public)
	{
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &chunk))
		{
			keyid = identification_create_from_encoding(ID_KEY_ID, chunk);
			private = get_private_by_keyid(this, type, keyid);
			keyid->destroy(keyid);
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
								  auth_cfg_t *auth)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	private_key_t *private = NULL;
	auth_cfg_t *trustchain;

	/* check if this is a lookup by key ID, and do it if so */
	if (id && id->get_type(id) == ID_KEY_ID)
	{
		private = get_private_by_keyid(this, type, id);
		if (private)
		{
			return private;
		}
	}

	/* if a specific certificate is preferred, check for a matching key */
	cert = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
	if (cert)
	{
		private = get_private_by_cert(this, cert, type);
		if (private)
		{
			trustchain = build_trustchain(this, cert, auth);
			if (trustchain)
			{
				auth->merge(auth, trustchain, FALSE);
				trustchain->destroy(trustchain);
			}
			return private;
		}
	}

	/* try to build a trust chain for each certificate found */
	enumerator = create_cert_enumerator(this, CERT_ANY, type, id, FALSE);
	while (enumerator->enumerate(enumerator, &cert))
	{
		private = get_private_by_cert(this, cert, type);
		if (private)
		{
			trustchain = build_trustchain(this, cert, auth);
			if (trustchain)
			{
				auth->merge(auth, trustchain, FALSE);
				trustchain->destroy(trustchain);
				break;
			}
			private->destroy(private);
			private = NULL;
		}
	}
	enumerator->destroy(enumerator);

	/* if no valid trustchain was found, fall back to the first usable cert */
	if (!private)
	{
		enumerator = create_cert_enumerator(this, CERT_ANY, type, id, FALSE);
		while (enumerator->enumerate(enumerator, &cert))
		{
			private = get_private_by_cert(this, cert, type);
			if (private)
			{
				auth->add(auth, AUTH_RULE_SUBJECT_CERT, cert->get_ref(cert));
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return private;
}

/**
 * Implementation of credential_manager_t.flush_cache.
 */
static void flush_cache(private_credential_manager_t *this,
						certificate_type_t type)
{
	this->cache->flush(this->cache, type);
}

/**
 * Implementation of credential_manager_t.add_set.
 */
static void add_set(private_credential_manager_t *this,
							   credential_set_t *set)
{
	this->lock->write_lock(this->lock);
	this->sets->insert_last(this->sets, set);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of credential_manager_t.remove_set.
 */
static void remove_set(private_credential_manager_t *this, credential_set_t *set)
{
	this->lock->write_lock(this->lock);
	this->sets->remove(this->sets, set, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of credential_manager_t.destroy
 */
static void destroy(private_credential_manager_t *this)
{
	cache_queue(this);
	this->cache_queue->destroy(this->cache_queue);
	this->sets->remove(this->sets, this->cache, NULL);
	this->sets->destroy(this->sets);
	pthread_key_delete(this->local_sets);
	this->cache->destroy(this->cache);
	this->lock->destroy(this->lock);
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
	this->public.create_cdp_enumerator = (enumerator_t *(*)(credential_manager_t*, certificate_type_t type, identification_t *id))create_cdp_enumerator;
	this->public.get_cert = (certificate_t *(*)(credential_manager_t *this,certificate_type_t cert, key_type_t key,identification_t *, bool))get_cert;
	this->public.get_shared = (shared_key_t *(*)(credential_manager_t *this,shared_key_type_t type,identification_t *me, identification_t *other))get_shared;
	this->public.get_private = (private_key_t*(*)(credential_manager_t*, key_type_t type, identification_t *, auth_cfg_t*))get_private;
	this->public.create_public_enumerator = (enumerator_t*(*)(credential_manager_t*, key_type_t type, identification_t *id, auth_cfg_t *aut))create_public_enumerator;
	this->public.flush_cache = (void(*)(credential_manager_t*, certificate_type_t type))flush_cache;
	this->public.cache_cert = (void(*)(credential_manager_t*, certificate_t *cert))cache_cert;
	this->public.add_set = (void(*)(credential_manager_t*, credential_set_t *set))add_set;
	this->public.remove_set = (void(*)(credential_manager_t*, credential_set_t *set))remove_set;
	this->public.destroy = (void(*)(credential_manager_t*))destroy;

	this->sets = linked_list_create();
	pthread_key_create(&this->local_sets, (void*)this->sets->destroy);
	this->cache = cert_cache_create();
	this->cache_queue = linked_list_create();
	this->sets->insert_first(this->sets, this->cache);
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	return &this->public;
}

