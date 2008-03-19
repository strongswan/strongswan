/*
 * Copyright (C) 2007 Tobias Brunner
 * Copyright (C) 2006-2007 Martin Willi
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "stroke.h"

/* stroke message format definition */
#include <stroke_msg.h>

#include <library.h>
#include <daemon.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/ocsp_request.h>
#include <credentials/certificates/ocsp_response.h>
#include <control/controller.h>
#include <utils/lexparser.h>
#include <asn1/ttodata.h>
#include <asn1/pem.h>
#include <utils/mutex.h>
#include <processing/jobs/callback_job.h>
#include <credentials/credential_set.h>

/* configuration directories and files */
#define CONFIG_DIR IPSEC_CONFDIR
#define IPSEC_D_DIR CONFIG_DIR "/ipsec.d"
#define PRIVATE_KEY_DIR IPSEC_D_DIR "/private"
#define CERTIFICATE_DIR IPSEC_D_DIR "/certs"
#define CA_CERTIFICATE_DIR IPSEC_D_DIR "/cacerts"
#define AA_CERTIFICATE_DIR IPSEC_D_DIR "/aacerts"
#define ATTR_CERTIFICATE_DIR IPSEC_D_DIR "/acerts"
#define OCSP_CERTIFICATE_DIR IPSEC_D_DIR "/ocspcerts"
#define CRL_DIR IPSEC_D_DIR "/crls"
#define SECRETS_FILE CONFIG_DIR "/ipsec.secrets"

/* warning intervals for list functions */
#define CERT_WARNING_INTERVAL  30	/* days */
#define CRL_WARNING_INTERVAL	7	/* days */

typedef struct private_stroke_t private_stroke_t;
typedef struct stroke_credentials_t stroke_credentials_t;
typedef struct ca_creds_t ca_creds_t;
typedef struct creds_t creds_t;
typedef struct ca_section_t ca_section_t;
typedef struct configs_t configs_t;

/**
 * loaded ipsec.conf CA sections
 */
struct ca_section_t {

	/**
	 * name of the CA section
	 */
	char *name;
	
	/**
	 * reference to cert in trusted_credential_t
	 */
	certificate_t *cert;
	
	/**
	 * CRL URIs
	 */
	linked_list_t *crl;
	
	/**
	 * OCSP URIs
	 */
	linked_list_t *ocsp;
};

/**
 * private credentail_set_t implementation for CA sections
 */
struct ca_creds_t {
	/**
	 * implements credential set
	 */
	credential_set_t set;

	/**
	 * list of starters CA sections and its certificates (ca_section_t)
	 */
	linked_list_t *sections;
	
	/**
	 * mutex to lock sections list
	 */
	mutex_t *mutex;
	
};

/**
 * private credential_set_t implementation for trusted certificates and keys
 */
struct creds_t {
	/**
	 * implements credential set
	 */
	credential_set_t set;
	
	/**
	 * list of trusted peer/signer/CA certificates (certificate_t)
	 */
	linked_list_t *certs;

	/**
	 * list of shared secrets (private_shared_key_t)
	 */
	linked_list_t *shared;

	/**
	 * list of private keys (private_key_t)
	 */
	linked_list_t *private;
	
	/**
	 * mutex to lock lists above
	 */
	mutex_t *mutex;
};


typedef struct private_shared_key_t private_shared_key_t;
/**
 * private data of shared_key
 */
struct private_shared_key_t {

	/**
	 * implements shared_key_t
	 */
	shared_key_t public;
	
	/**
	 * type of this key
	 */
	shared_key_type_t type;

	/**
	 * data of the key
	 */
	chunk_t key;

	/**
	 * list of key owners, as identification_t
	 */
	linked_list_t *owners;
	
	/**
	 * reference counter
	 */
	refcount_t ref;
};


/**
 * configuration backend including peer_cfg list
 */
struct configs_t {

	/**
	 * implements backend_t interface
	 */
	backend_t backend;
	
	/**
	 * list of peer_cfg_t
	 */
	linked_list_t *list;
	
	/**
	 * mutex to lock config list
	 */
	mutex_t *mutex;
};

/**
 * Private data of an stroke_t object.
 */
struct private_stroke_t {

	/**
	 * Public part of stroke_t object.
	 */
	stroke_t public;
		
	/**
	 * Unix socket to listen for strokes
	 */
	int socket;
	
	/**
	 * job accepting stroke messages
	 */
	callback_job_t *job;
	
	/**
	 * CA credentials
	 */
	ca_creds_t ca_creds;
	
	/**
	 * other credentials
	 */
	creds_t creds;
	
	/**
	 * configuration backend
	 */
	configs_t configs;
};

typedef struct stroke_log_info_t stroke_log_info_t;

/**
 * helper struct to say what and where to log when using controller callback
 */
struct stroke_log_info_t {

	/**
	 * level to log up to
	 */
	level_t level;
	
	/**
	 * where to write log
	 */
	FILE* out;
};

/**
 * create a new CA section 
 */
static ca_section_t *ca_section_create(char *name, certificate_t *cert)
{
	ca_section_t *ca = malloc_thing(ca_section_t);
	
	ca->name = strdup(name);
	ca->crl = linked_list_create();
	ca->ocsp = linked_list_create();
	ca->cert = cert;
	return ca;
}

/**
 * destroy a ca section entry
 */
static void ca_section_destroy(ca_section_t *this)
{
	this->crl->destroy_function(this->crl, free);
	this->ocsp->destroy_function(this->ocsp, free);
	free(this->name);
	free(this);
}

/**
 * data to pass to create_inner_cdp
 */
typedef struct {
	ca_creds_t *this;
	certificate_type_t type;
	identification_t *id;
} cdp_data_t;

/**
 * destroy cdp enumerator data and unlock list
 */
static void cdp_data_destroy(cdp_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * inner enumerator constructor for CDP URIs
 */
static enumerator_t *create_inner_cdp(ca_section_t *section, cdp_data_t *data)
{
	public_key_t *public;
	identification_t *keyid;
	enumerator_t *enumerator = NULL;
	linked_list_t *list;
	
	if (data->type == CERT_X509_OCSP_RESPONSE)
	{
		list = section->ocsp;
	}
	else
	{
		list = section->crl;
	}

	public = section->cert->get_public_key(section->cert);
	if (public)
	{
		if (!data->id)
		{
			enumerator = list->create_enumerator(list);
		}
		else
		{
			keyid = public->get_id(public, data->id->get_type(data->id));
			if (keyid && keyid->matches(keyid, data->id))
			{
				enumerator = list->create_enumerator(list);		
			}
		}
		public->destroy(public);
	}
	return enumerator;
}

/**
 * Implementation of ca_creds_t.set.create_cdp_enumerator.
 */
static enumerator_t *create_cdp_enumerator(ca_creds_t *this,
								certificate_type_t type, identification_t *id)
{
	cdp_data_t *data;

	switch (type)
	{	/* we serve CRLs and OCSP responders */
		case CERT_X509_CRL:
		case CERT_X509_OCSP_RESPONSE:
		case CERT_ANY:
			break;
		default:
			return NULL;
	}
	data = malloc_thing(cdp_data_t);
	data->this = this;
	data->type = type;
	data->id = id;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_nested(this->sections->create_enumerator(this->sections),
									(void*)create_inner_cdp, data,
									(void*)cdp_data_destroy);
}

/**
 * data to pass to various filters
 */
typedef struct {
	creds_t *this;
	identification_t *id;
} id_data_t;

/**
 * destroy id enumerator data and unlock list
 */
static void id_data_destroy(id_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}


/**
 * filter function for private key enumerator
 */
static bool private_filter(id_data_t *data,
						   private_key_t **in, private_key_t **out)
{
	identification_t *candidate;
	
	if (data->id == NULL)
	{
		*out = *in;
		return TRUE;
	}
	candidate = (*in)->get_id(*in, data->id->get_type(data->id));
	if (candidate && data->id->equals(data->id, candidate))
	{
		*out = *in;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implements creds_t.set.create_private_enumerator
 */
static enumerator_t* create_private_enumerator(creds_t *this,
							key_type_t type, identification_t *id)
{
	id_data_t *data;

	if (type != KEY_RSA && type != KEY_ANY)
	{	/* we only have RSA keys */
		return NULL;
	}
	data = malloc_thing(id_data_t);
	data->this = this;
	data->id = id;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->private->create_enumerator(this->private),
									(void*)private_filter, data,
									(void*)id_data_destroy);
}

/**
 * filter function for certs enumerator
 */
static bool certs_filter(id_data_t *data, certificate_t **in, certificate_t **out)
{
	public_key_t *public;
	identification_t *candidate;
	certificate_t *cert = *in;
	
	if (cert->get_type(cert) == CERT_X509_CRL)
	{
		return FALSE;
	}

	if (data->id == NULL || cert->has_subject(cert, data->id))
	{
		*out = *in;
		return TRUE;
	}
	
	public = (cert)->get_public_key(cert);
	if (public)
	{
		candidate = public->get_id(public, data->id->get_type(data->id));
		if (candidate && data->id->equals(data->id, candidate))
		{
			public->destroy(public);
			*out = *in;
			return TRUE;
		}
		public->destroy(public);
	}
	return FALSE;
}

/**
 * filter function for crl enumerator
 */
static bool crl_filter(id_data_t *data, certificate_t **in, certificate_t **out)
{
	certificate_t *cert = *in;
	
	if (cert->get_type(cert) != CERT_X509_CRL)
	{
		return FALSE;
	}

	if (data->id == NULL || cert->has_issuer(cert, data->id))
	{
		*out = *in;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implements creds_t.set.create_cert_enumerator
 */
static enumerator_t* create_cert_enumerator(creds_t *this,
							certificate_type_t cert, key_type_t key,
							identification_t *id, bool trusted)
{
	id_data_t *data;
	
	if (cert == CERT_X509_CRL)
	{
		data = malloc_thing(id_data_t);
		data->this = this;
		data->id = id;
		
		this->mutex->lock(this->mutex);
		return enumerator_create_filter(this->certs->create_enumerator(this->certs),
										(void*)crl_filter, data,
										(void*)id_data_destroy);
	}
	if (cert != CERT_X509 && cert != CERT_ANY)
	{	/* we only have X509 certificates. TODO: ACs? */
		return NULL;
	}
	if (key != KEY_RSA && key != KEY_ANY)
	{	/* we only have RSA keys */
		return NULL;
	}
	data = malloc_thing(id_data_t);
	data->this = this;
	data->id = id;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->certs->create_enumerator(this->certs),
									(void*)certs_filter, data,
									(void*)id_data_destroy);
}

/**
 * Implementation of shared_key_t.get_type.
 */
static shared_key_type_t get_type(private_shared_key_t *this)
{
	return this->type;
}

/**
 * Implementation of shared_key_t.get_ref.
 */
static private_shared_key_t* get_ref(private_shared_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of shared_key_t.destroy
 */
static void shared_key_destroy(private_shared_key_t *this)
{
	if (ref_put(&this->ref))
	{
		this->owners->destroy_offset(this->owners, offsetof(identification_t, destroy));
		chunk_free(&this->key);
		free(this);
	}
}

/**
 * Implementation of shared_key_t.get_key.
 */
static chunk_t get_key(private_shared_key_t *this)
{
	return this->key;
}

/**
 * create a shared key
 */
static private_shared_key_t *private_shared_key_create(shared_key_type_t type, chunk_t key)
{
	private_shared_key_t *this = malloc_thing(private_shared_key_t);

	this->public.get_type = (shared_key_type_t(*)(shared_key_t*))get_type;
	this->public.get_key = (chunk_t(*)(shared_key_t*))get_key;
	this->public.get_ref = (shared_key_t*(*)(shared_key_t*))get_ref;
	this->public.destroy = (void(*)(shared_key_t*))shared_key_destroy;

	this->owners = linked_list_create();
	this->type = type;
	this->key = key;
	this->ref = 1;
	return this;
}

/**
 * Check if a key has such an owner
 */
static id_match_t has_owner(private_shared_key_t *this, identification_t *owner)
{
	enumerator_t *enumerator;
	id_match_t match, best = ID_MATCH_NONE;
	identification_t *current;
	
	enumerator = this->owners->create_enumerator(this->owners);
	while (enumerator->enumerate(enumerator, &current))
	{
		match  = owner->matches(owner, current);
		if (match > best)
		{
			best = match;
		}
	}
	enumerator->destroy(enumerator);
	return best;
}

typedef struct {
	creds_t *this;
	identification_t *me;
	identification_t *other;
	shared_key_type_t type;
} shared_data_t;

/**
 * free shared key enumerator data and unlock list
 */
static void shared_data_destroy(shared_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * filter function for certs enumerator
 */
static bool shared_filter(shared_data_t *data,
						  private_shared_key_t **in, private_shared_key_t **out,
						  void **unused1, id_match_t *me,
						  void **unused2, id_match_t *other)
{
	id_match_t my_match, other_match;

	if (!(*in)->type == SHARED_ANY && !(*in)->type == data->type)
	{
		return FALSE;
	}
	my_match = has_owner(*in, data->me);
	other_match = has_owner(*in, data->other);
	if (!my_match && !other_match)
	{
		return FALSE;
	}
	*out = *in;
	if (me)
	{
		*me = my_match;
	}
	if (other)
	{
		*other = other_match;
	}
	return TRUE;
}

/**
 * Implements creds_t.set.create_shared_enumerator
 */
static enumerator_t* create_shared_enumerator(creds_t *this, 
							shared_key_type_t type,	identification_t *me,
							identification_t *other)
{
	shared_data_t *data = malloc_thing(shared_data_t);
	
	data->this = this;
	data->me = me;
	data->other = other;
	data->type = type;
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->shared->create_enumerator(this->shared),
									(void*)shared_filter, data,
									(void*)shared_data_destroy);
}

/**
 * Helper function which corrects the string pointers
 * in a stroke_msg_t. Strings in a stroke_msg sent over "wire"
 * contains RELATIVE addresses (relative to the beginning of the
 * stroke_msg). They must be corrected if they reach our address
 * space...
 */
static void pop_string(stroke_msg_t *msg, char **string)
{
	if (*string == NULL)
	{
		return;
	}

	/* check for sanity of string pointer and string */
	if (string < (char**)msg ||
		string > (char**)msg + sizeof(stroke_msg_t) ||
		(unsigned long)*string < (unsigned long)((char*)msg->buffer - (char*)msg) ||
		(unsigned long)*string > msg->length)
	{
		*string = "(invalid pointer in stroke msg)";
	}
	else
	{
		*string = (char*)msg + (unsigned long)*string;
	}
}

/**
 * Load an X.509 certificate
 */
static x509_t* load_cert(char *path, x509_flag_t flag)
{
	bool pgp = FALSE;
	chunk_t chunk;
	x509_t *x509;
	certificate_t *cert;
	time_t notBefore, notAfter, now;
	
	if (!pem_asn1_load_file(path, NULL, &chunk, &pgp))
	{
		DBG1(DBG_CFG, "  could not load certificate file '%s'", path);
		return NULL;
	}
	x509 = (x509_t*)lib->creds->create(lib->creds,
									   CRED_CERTIFICATE, CERT_X509,
									   BUILD_BLOB_ASN1_DER, chunk,
									   BUILD_X509_FLAG, flag,
									   BUILD_END);
	if (x509 == NULL)
	{
		DBG1(DBG_CFG, "  could not load certificate file '%s'", path);
		return NULL;
	}
	DBG1(DBG_CFG, "  loaded certificate file '%s'", path);
	
	/* check validity */
	cert = &x509->interface;
	now = time(NULL);
	cert->get_validity(cert, &now, &notBefore, &notAfter);
	if (now > notAfter)
	{
		DBG1(DBG_CFG, "  certificate expired at %T, discarded", &notAfter);
		cert->destroy(cert);
		return NULL;
	}
	if (now < notBefore)
	{
		DBG1(DBG_CFG, "  certificate not valid before %T", &notBefore);
	}
	return x509;
}

/**
 * Add X.509 certificate to chain
 */
static certificate_t* add_x509_cert(private_stroke_t *this, x509_t* x509)
{
	certificate_t *current, *cert = &x509->interface;
	enumerator_t *enumerator;
	bool new = TRUE;	

	this->creds.mutex->lock(this->creds.mutex);
	enumerator = this->creds.certs->create_enumerator(this->creds.certs);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (current->equals(current, cert))
		{
			/* cert already in queue */
			cert->destroy(cert);
			cert = current;
			new = FALSE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (new)
	{
		this->creds.certs->insert_last(this->creds.certs, cert);
	}
	this->creds.mutex->unlock(this->creds.mutex);
	return cert;
}

/**
 * Verify the signature of an X.509 CRL
 */
static bool verify_crl(crl_t* crl)
{
	certificate_t *crl_cert = &crl->certificate;
	identification_t *issuer = crl_cert->get_issuer(crl_cert);
	identification_t *authKeyIdentifier = crl->get_authKeyIdentifier(crl);
	certificate_t *issuer_cert;

	DBG1(DBG_CFG, "  issuer: %D", issuer);
	if (authKeyIdentifier)
	{
		DBG1(DBG_CFG, "  authkey: %D", authKeyIdentifier);
	}

	issuer_cert = charon->credentials->get_cert(charon->credentials, CERT_X509,
											    KEY_ANY, issuer, TRUE);

	if (issuer_cert)
	{
		
		bool ok = crl_cert->issued_by(crl_cert, issuer_cert, TRUE);

		DBG1(DBG_CFG, "  crl is %strusted: %s signature",
						 ok? "":"un", ok? "good":"bad");
		return ok;
	}
	else
	{
		DBG1(DBG_CFG, "  crl is untrusted: issuer certificate not found");
		return FALSE;
	}
}

/**
 * Add X.509 CRL to chain
 */
static void add_crl(private_stroke_t *this, crl_t* crl)
{
	certificate_t *current, *cert = &crl->certificate;
	enumerator_t *enumerator;
	bool new = TRUE, found = FALSE;	

	this->creds.mutex->lock(this->creds.mutex);
	enumerator = this->creds.certs->create_enumerator(this->creds.certs);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (current->get_type(current) == CERT_X509_CRL)
		{
			crl_t *crl_c = (crl_t*)current;
			identification_t *authkey = crl->get_authKeyIdentifier(crl);
			identification_t *authkey_c = crl_c->get_authKeyIdentifier(crl_c);

			/* if compare authorityKeyIdentifiers if available */
			if (authkey != NULL && authkey_c != NULL &&
				authkey->equals(authkey, authkey_c))
			{
				found = TRUE;
			}
			else
			{
				identification_t *issuer = cert->get_issuer(cert);
				identification_t *issuer_c = current->get_issuer(current);

				/* otherwise compare issuer distinguished names */
				if (issuer->equals(issuer, issuer_c))
				{
					found = TRUE;
				}
			}
			if (found)
			{
				new = cert->is_newer(cert, current);
				if (new)
				{
					this->creds.certs->remove_at(this->creds.certs, enumerator);
				}
				else
				{
					cert->destroy(cert);
				}
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (new)
	{
		this->creds.certs->insert_last(this->creds.certs, cert);
	}
	this->creds.mutex->unlock(this->creds.mutex);
}

/**
 * Load end entitity certificate
 */
static void load_peer_cert(private_stroke_t *this,
						   char *filename, identification_t **id)
{
	char path[PATH_MAX];
	x509_t *x509;
	identification_t *peerid = *id;

	if (*filename == '/')
	{
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/%s", CERTIFICATE_DIR, filename);
	}
	
	x509 = load_cert(path, 0);

	if (x509)
	{
		certificate_t *cert = &x509->interface;;
		identification_t *subject = cert->get_subject(cert);

		if (!cert->has_subject(cert, peerid))
		{
			DBG1(DBG_CFG, "  peerid %D not confirmed by certificate, "
					"defaulting to subject DN", peerid);
			peerid->destroy(peerid);
			*id = subject->clone(subject);
		}
		add_x509_cert(this, x509);
	}
}

/**
 * Load ca certificate
 */
static certificate_t* load_ca_cert(private_stroke_t *this, char *filename)
{
	char path[PATH_MAX];
	x509_t *x509;

	if (*filename == '/')
	{
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/%s", CA_CERTIFICATE_DIR, filename);
	}
	
	x509 = load_cert(path, X509_CA);

	if (x509)
	{
		return add_x509_cert(this, x509);
	}
	else
	{
		return NULL;
	}
}

/**
 * load trusted certificates from a directory
 */
static void load_certdir(private_stroke_t *this,
						 char *path, certificate_type_t type, x509_flag_t flag)
{
	struct stat st;
	char *file;
	
	enumerator_t *enumerator = enumerator_create_directory(path);

	if (!enumerator)
	{
		DBG1(DBG_CFG, "  reading directory failed");
		return;
	}

	while (enumerator->enumerate(enumerator, NULL, &file, &st))
	{
		if (!S_ISREG(st.st_mode))
		{
			/* skip special file */
			continue;
		}
		if (type == CERT_X509)
		{
			x509_t *x509 = load_cert(file, flag);

			if (x509)
			{
				add_x509_cert(this, x509);
			}
		}
		else
		{	
			certificate_t *cert;
			bool pgp = FALSE;
			chunk_t chunk;
	
			if (!pem_asn1_load_file(file, NULL, &chunk, &pgp))
			{
				continue;
			}
			cert = lib->creds->create(lib->creds,
									  CRED_CERTIFICATE, type,
									  BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
			if (type == CERT_X509_CRL)
			{
				if (cert)
				{
					crl_t *crl = (crl_t*)cert;

					DBG1(DBG_CFG, "  loaded crl file '%s'", file);

					/* only trusted crls are added to the store */
					if (verify_crl(crl))
					{
						add_crl(this, crl);
					}
					else
					{
						DBG1(DBG_CFG, "  crl discarded");
						cert->destroy(cert);
					}
				}
				else 
				{
					DBG1(DBG_CFG, " could not load crl file '%s'", file);
				}
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Convert a string of characters into a binary secret
 * A string between single or double quotes is treated as ASCII characters
 * A string prepended by 0x is treated as HEX and prepended by 0s as Base64
 */
static err_t extract_secret(chunk_t *secret, chunk_t *line)
{
	chunk_t raw_secret;
	char delimiter = ' ';
	bool quotes = FALSE;

	if (!eat_whitespace(line))
	{
		return "missing secret";
	}

	if (*line->ptr == '\'' || *line->ptr == '"')
	{
		quotes = TRUE;
		delimiter = *line->ptr;
		line->ptr++;  line->len--;
	}

	if (!extract_token(&raw_secret, delimiter, line))
	{
		if (delimiter == ' ')
		{
			raw_secret = *line;
		}
		else
		{
			return "missing second delimiter";
		}
	}

	if (quotes)
	{	
		/* treat as an ASCII string */
		*secret = chunk_clone(raw_secret);
	}
	else
	{
		size_t len;
		err_t ugh;

		/* secret converted to binary form doesn't use more space than the raw_secret */
		*secret = chunk_alloc(raw_secret.len);

		/* convert from HEX or Base64 to binary */
		ugh = ttodata(raw_secret.ptr, raw_secret.len, 0, secret->ptr, secret->len, &len);

	    if (ugh != NULL)
		{
			chunk_free_randomized(secret);
			return ugh;
		}
		secret->len = len;
	}
	return NULL;
}

/**
 * reload ipsec.secrets
 */
static void load_secrets(private_stroke_t *this)
{
	size_t bytes;
	int line_nr = 0;
	chunk_t chunk, src, line;
	FILE *fd;
	private_key_t *private;
	shared_key_t *shared;

	DBG1(DBG_CFG, "loading secrets from '%s'", SECRETS_FILE);

	fd = fopen(SECRETS_FILE, "r");
	if (fd == NULL)
	{
		DBG1(DBG_CFG, "opening secrets file '%s' failed");
		return;
	}

	/* TODO: do error checks */
	fseek(fd, 0, SEEK_END);
	chunk.len = ftell(fd);
	rewind(fd);
	chunk.ptr = malloc(chunk.len);
	bytes = fread(chunk.ptr, 1, chunk.len, fd);
	fclose(fd);
	src = chunk;

	this->creds.mutex->lock(this->creds.mutex);
	while (this->creds.shared->remove_last(this->creds.shared,
		 								   (void**)&shared) == SUCCESS)
	{
		shared->destroy(shared);
	}
	while (this->creds.private->remove_last(this->creds.private,
		 								    (void**)&private) == SUCCESS)
	{
		private->destroy(private);
	}
	
	while (fetchline(&src, &line))
	{
		chunk_t ids, token;
		shared_key_type_t type;

		line_nr++;

		if (!eat_whitespace(&line))
		{
			continue;
		}
		if (!extract_token(&ids, ':', &line))
		{
			DBG1(DBG_CFG, "line %d: missing ':' separator", line_nr);
			goto error;
		}
		/* NULL terminate the ids string by replacing the : separator */
		*(ids.ptr + ids.len) = '\0';

		if (!eat_whitespace(&line) || !extract_token(&token, ' ', &line))
		{
			DBG1(DBG_CFG, "line %d: missing token", line_nr);
			goto error;
		}
		if (match("RSA", &token))
		{
			char path[PATH_MAX];
			chunk_t filename;
			chunk_t secret = chunk_empty;
			private_key_t *key;
			bool pgp = FALSE;
			chunk_t chunk = chunk_empty;

			err_t ugh = extract_value(&filename, &line);

			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: %s", line_nr, ugh);
				goto error;
			}
			if (filename.len == 0)
			{
				DBG1(DBG_CFG, "line %d: empty filename", line_nr);
				goto error;
			}
			if (*filename.ptr == '/')
			{
				/* absolute path name */
				snprintf(path, sizeof(path), "%.*s", filename.len, filename.ptr);
			}
			else
			{
				/* relative path name */
				snprintf(path, sizeof(path), "%s/%.*s", PRIVATE_KEY_DIR, 
						 filename.len, filename.ptr);
			}

			/* check for optional passphrase */
			if (eat_whitespace(&line))
			{
				ugh = extract_secret(&secret, &line);
				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "line %d: malformed passphrase: %s", line_nr, ugh);
					goto error;
				}
			}

			if (pem_asn1_load_file(path, &secret, &chunk, &pgp))
			{
				key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
										 BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
				if (key)
				{
					DBG1(DBG_CFG, "  loaded private key file '%s'", path);
					this->creds.private->insert_last(this->creds.private, key);
				}
			}
			chunk_free_randomized(&secret);
		}
		else if ((match("PSK", &token) && (type = SHARED_IKE)) ||
				 (match("EAP", &token) && (type = SHARED_EAP)) ||
				 (match("XAUTH", &token) && (type = SHARED_EAP)) ||
				 (match("PIN", &token) && (type = SHARED_PIN)))
		{
			private_shared_key_t *shared_key;
			chunk_t secret = chunk_empty;
			bool any = TRUE;

			err_t ugh = extract_secret(&secret, &line);
			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: malformed secret: %s", line_nr, ugh);
				goto error;
			}
			shared_key = private_shared_key_create(type, secret);
			DBG1(DBG_CFG, "  loaded %N secret for %s", shared_key_type_names, type,
				 ids.len > 0 ? (char*)ids.ptr : "%any");
			DBG4(DBG_CFG, "  secret:", secret);
			
			this->creds.shared->insert_last(this->creds.shared, shared_key);
			while (ids.len > 0)
			{
				chunk_t id;
				identification_t *peer_id;

				ugh = extract_value(&id, &ids);
				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "line %d: %s", line_nr, ugh);
					goto error;
				}
				if (id.len == 0)
				{
					continue;
				}

				/* NULL terminate the ID string */
				*(id.ptr + id.len) = '\0';

				peer_id = identification_create_from_string(id.ptr);
				if (peer_id == NULL)
				{
					DBG1(DBG_CFG, "line %d: malformed ID: %s", line_nr, id.ptr);
					goto error;
				}
				if (peer_id->get_type(peer_id) == ID_ANY)
				{
					peer_id->destroy(peer_id);
					continue;
				}
				
				shared_key->owners->insert_last(shared_key->owners, peer_id);
				any = FALSE;
			}
			if (any)
			{
				shared_key->owners->insert_last(shared_key->owners,
					identification_create_from_encoding(ID_ANY, chunk_empty));
			}
		}
		else
		{
			DBG1(DBG_CFG, "line %d: token must be either "
				 "RSA, PSK, EAP, or PIN", line_nr);
			goto error;
		}
	}
error:
	this->creds.mutex->unlock(this->creds.mutex);
	chunk_free_randomized(&chunk);
}

/**
 * data to pass peer_filter
 */
typedef struct {
	configs_t *this;
	identification_t *me;
	identification_t *other;
} peer_data_t;

/**
 * destroy id enumerator data and unlock list
 */
static void peer_data_destroy(peer_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * filter function for peer configs
 */
static bool peer_filter(peer_data_t *data, peer_cfg_t **in, peer_cfg_t **out)
{

	if ((!data->me || data->me->matches(data->me, (*in)->get_my_id(*in))) &&
		(!data->other || data->other->matches(data->other, (*in)->get_other_id(*in))))
	{
		*out = *in;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of backend_t.create_peer_cfg_enumerator.
 */
static enumerator_t* create_peer_cfg_enumerator(configs_t *this,
												identification_t *me,
												identification_t *other)
{
	peer_data_t *data;
	
	data = malloc_thing(peer_data_t);
	data->this = this;
	data->me = me;
	data->other = other;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->list->create_enumerator(this->list),
									(void*)peer_filter, data,
									(void*)peer_data_destroy);
}

/**
 * data to pass ike_filter
 */
typedef struct {
	configs_t *this;
	host_t *me;
	host_t *other;
} ike_data_t;

/**
 * destroy id enumerator data and unlock list
 */
static void ike_data_destroy(ike_data_t *data)
{
	data->this->mutex->unlock(data->this->mutex);
	free(data);
}

/**
 * filter function for ike configs
 */
static bool ike_filter(ike_data_t *data, peer_cfg_t **in, ike_cfg_t **out)
{
	ike_cfg_t *ike_cfg;
	host_t *me, *other;
	
	ike_cfg = (*in)->get_ike_cfg(*in);
	
	me = ike_cfg->get_my_host(ike_cfg);
	other = ike_cfg->get_other_host(ike_cfg);
	if ((!data->me || me->is_anyaddr(me) || me->ip_equals(me, data->me)) &&
		(!data->other || other->is_anyaddr(other) || other->ip_equals(other, data->other)))
	{
		*out = ike_cfg;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of backend_t.create_ike_cfg_enumerator.
 */
static enumerator_t* create_ike_cfg_enumerator(configs_t *this,
											   host_t *me, host_t *other)
{
	ike_data_t *data;
	
	data = malloc_thing(ike_data_t);
	data->this = this;
	data->me = me;
	data->other = other;
	
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->list->create_enumerator(this->list),
									(void*)ike_filter, data,
									(void*)ike_data_destroy);
}

/**
 * implements backend_t.get_peer_cfg_by_name.
 */
static peer_cfg_t *get_peer_cfg_by_name(configs_t *this, char *name)
{
	enumerator_t *e1, *e2;
	peer_cfg_t *current, *found = NULL;
	child_cfg_t *child;

	this->mutex->lock(this->mutex);
	e1 = this->list->create_enumerator(this->list);
	while (e1->enumerate(e1, &current))
	{
        /* compare peer_cfgs name first */
        if (streq(current->get_name(current), name))
        {
            found = current;
            found->get_ref(found);
            break;
        }
        /* compare all child_cfg names otherwise */
        e2 = current->create_child_cfg_enumerator(current);
        while (e2->enumerate(e2, &child))
        {
            if (streq(child->get_name(child), name))
            {
                found = current;
                found->get_ref(found);
                break;
            }
        }
        e2->destroy(e2);
        if (found)
        {
            break;
        }
	}
	e1->destroy(e1);
	this->mutex->unlock(this->mutex);
	return found;
}

/**
 * Pop the strings of a stroke_end_t struct and log them for debugging purposes
 */
static void pop_end(stroke_msg_t *msg, const char* label, stroke_end_t *end)
{
	pop_string(msg, &end->address);
	pop_string(msg, &end->subnet);
	pop_string(msg, &end->sourceip);
	pop_string(msg, &end->id);
	pop_string(msg, &end->cert);
	pop_string(msg, &end->ca);
	pop_string(msg, &end->groups);
	pop_string(msg, &end->updown);
	
	DBG2(DBG_CFG, "  %s=%s", label, end->address);
	DBG2(DBG_CFG, "  %ssubnet=%s", label, end->subnet);
	DBG2(DBG_CFG, "  %ssourceip=%s", label, end->sourceip);
	DBG2(DBG_CFG, "  %sid=%s", label, end->id);
	DBG2(DBG_CFG, "  %scert=%s", label, end->cert);
	DBG2(DBG_CFG, "  %sca=%s", label, end->ca);
	DBG2(DBG_CFG, "  %sgroups=%s", label, end->groups);
	DBG2(DBG_CFG, "  %supdown=%s", label, end->updown);
}

/**
 * Add a connection to the configuration list
 */
static void stroke_add_conn(private_stroke_t *this,
							stroke_msg_t *msg, FILE *out)
{
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	peer_cfg_t *mediated_by_cfg = NULL;
	child_cfg_t *child_cfg;
	auth_info_t *auth;
	identification_t *my_id, *other_id;
	identification_t *my_ca = NULL;
	identification_t *other_ca = NULL;
	identification_t *peer_id = NULL;
	bool my_ca_same = FALSE;
	bool other_ca_same =FALSE;
	host_t *my_host = NULL, *other_host = NULL, *my_subnet, *other_subnet;
	host_t *my_vip = NULL, *other_vip = NULL;
	proposal_t *proposal;
	traffic_selector_t *my_ts, *other_ts;
	char *interface;
	bool use_existing = FALSE;
	enumerator_t *enumerator;
	u_int32_t vendor;
	
	pop_string(msg, &msg->add_conn.name);
	DBG1(DBG_CFG, "received stroke: add connection '%s'", msg->add_conn.name);
	DBG2(DBG_CFG, "conn %s", msg->add_conn.name);
	pop_end(msg, "left", &msg->add_conn.me);
	pop_end(msg, "right", &msg->add_conn.other);
	pop_string(msg, &msg->add_conn.algorithms.ike);
	pop_string(msg, &msg->add_conn.algorithms.esp);
	DBG2(DBG_CFG, "  ike=%s", msg->add_conn.algorithms.ike);
	DBG2(DBG_CFG, "  esp=%s", msg->add_conn.algorithms.esp);
	pop_string(msg, &msg->add_conn.p2p.mediated_by);
	pop_string(msg, &msg->add_conn.p2p.peerid);
	DBG2(DBG_CFG, "  p2p_mediation=%s", msg->add_conn.p2p.mediation ? "yes" : "no");
	DBG2(DBG_CFG, "  p2p_mediated_by=%s", msg->add_conn.p2p.mediated_by);
	DBG2(DBG_CFG, "  p2p_peerid=%s", msg->add_conn.p2p.peerid);
	
	if (msg->add_conn.me.address)
	{
		my_host = host_create_from_string(msg->add_conn.me.address,
										  IKEV2_UDP_PORT);
	}
	if (my_host == NULL)
	{
		DBG1(DBG_CFG, "invalid host: %s\n", msg->add_conn.me.address);
		return;
	}
	if (msg->add_conn.other.address)
	{
		other_host = host_create_from_string(msg->add_conn.other.address,
											 IKEV2_UDP_PORT);
	}
	if (other_host == NULL)
	{
		DBG1(DBG_CFG, "invalid host: %s\n", msg->add_conn.other.address);
		my_host->destroy(my_host);
		return;
	}
	
	interface = charon->kernel_interface->get_interface(charon->kernel_interface, 
														other_host);
	if (interface)
	{
		stroke_end_t tmp_end;
		host_t *tmp_host;

		DBG2(DBG_CFG, "left is other host, swapping ends\n");

		tmp_host = my_host;
		my_host = other_host;
		other_host = tmp_host;

		tmp_end = msg->add_conn.me;
		msg->add_conn.me = msg->add_conn.other;
		msg->add_conn.other = tmp_end;
		free(interface);
	}
	else
	{
		interface = charon->kernel_interface->get_interface(
											charon->kernel_interface, my_host);
		if (!interface)
		{
			DBG1(DBG_CFG, "left nor right host is our side, assuming left=local");
		}
		else
		{
			free(interface);
		}
	}

	my_id = identification_create_from_string(msg->add_conn.me.id ?
						msg->add_conn.me.id : msg->add_conn.me.address);
	if (my_id == NULL)
	{
		DBG1(DBG_CFG, "invalid ID: %s\n", msg->add_conn.me.id);
		goto destroy_hosts;
	}

	other_id = identification_create_from_string(msg->add_conn.other.id ?
						msg->add_conn.other.id : msg->add_conn.other.address);
	if (other_id == NULL)
	{
		DBG1(DBG_CFG, "invalid ID: %s\n", msg->add_conn.other.id);
		my_id->destroy(my_id);
		goto destroy_hosts;
	}
	
#ifdef P2P
	if (msg->add_conn.p2p.mediation && msg->add_conn.p2p.mediated_by)
	{
		DBG1(DBG_CFG, "a mediation connection cannot be a"
				" mediated connection at the same time, aborting");
		goto destroy_ids;
	}
	
	if (msg->add_conn.p2p.mediated_by)
	{
		mediated_by_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
												msg->add_conn.p2p.mediated_by);
		if (!mediated_by_cfg)
		{
			DBG1(DBG_CFG, "mediation connection '%s' not found, aborting",
					msg->add_conn.p2p.mediated_by);
			goto destroy_ids;
		}
		
		if (!mediated_by_cfg->is_mediation(mediated_by_cfg))
		{
			DBG1(DBG_CFG, "connection '%s' as referred to by '%s' is"
					"no mediation connection, aborting", 
					msg->add_conn.p2p.mediated_by, msg->add_conn.name);
			goto destroy_ids;
		}
	}
	
	if (msg->add_conn.p2p.peerid)
	{
		peer_id = identification_create_from_string(msg->add_conn.p2p.peerid);
		if (!peer_id)
		{
			DBG1(DBG_CFG, "invalid peer ID: %s\n", msg->add_conn.p2p.peerid);
			goto destroy_ids;
		}
	}
	else
	{
		/* no peer ID supplied, assume right ID */
		peer_id = other_id->clone(other_id);
	}
#endif /* P2P */
	
	my_subnet = host_create_from_string(
							msg->add_conn.me.subnet ? msg->add_conn.me.subnet
													: msg->add_conn.me.address, 
							IKEV2_UDP_PORT);
	if (my_subnet == NULL)
	{
		DBG1(DBG_CFG, "invalid subnet: %s\n", msg->add_conn.me.subnet);
		goto destroy_ids;
	}
	
	other_subnet = host_create_from_string(
						msg->add_conn.other.subnet ? msg->add_conn.other.subnet 
												   : msg->add_conn.other.address, 
						IKEV2_UDP_PORT);
	if (other_subnet == NULL)
	{
		DBG1(DBG_CFG, "invalid subnet: %s\n", msg->add_conn.me.subnet);
		my_subnet->destroy(my_subnet);
		goto destroy_ids;
	}
	
	if (msg->add_conn.me.virtual_ip && msg->add_conn.me.sourceip)
	{
		my_vip = host_create_from_string(msg->add_conn.me.sourceip, 0);
	}
	if (msg->add_conn.other.virtual_ip && msg->add_conn.other.sourceip)
	{
		other_vip = host_create_from_string(msg->add_conn.other.sourceip, 0);
	}
	
	if (msg->add_conn.me.tohost)
	{
		my_ts = traffic_selector_create_dynamic(msg->add_conn.me.protocol,
					my_host->get_family(my_host) == AF_INET ?
						TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE,
					msg->add_conn.me.port ? msg->add_conn.me.port : 0,
					msg->add_conn.me.port ? msg->add_conn.me.port : 65535);
	}
	else
	{
		my_ts = traffic_selector_create_from_subnet(my_subnet,
				msg->add_conn.me.subnet ?  msg->add_conn.me.subnet_mask : 0,
				msg->add_conn.me.protocol, msg->add_conn.me.port);
	}
	my_subnet->destroy(my_subnet);
	
	if (msg->add_conn.other.tohost)
	{
		other_ts = traffic_selector_create_dynamic(msg->add_conn.other.protocol,
					other_host->get_family(other_host) == AF_INET ?
						TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE,
					msg->add_conn.other.port ? msg->add_conn.other.port : 0,
					msg->add_conn.other.port ? msg->add_conn.other.port : 65535);
	}
	else
	{
		other_ts = traffic_selector_create_from_subnet(other_subnet, 
				msg->add_conn.other.subnet ?  msg->add_conn.other.subnet_mask : 0,
				msg->add_conn.other.protocol, msg->add_conn.other.port);
	}
	other_subnet->destroy(other_subnet);

	if (msg->add_conn.me.ca)
	{
		if (streq(msg->add_conn.me.ca, "%same"))
		{
			my_ca_same = TRUE;
		}
		else
		{
			my_ca = identification_create_from_string(msg->add_conn.me.ca);
		}
	}
	if (msg->add_conn.other.ca)
	{
		if (streq(msg->add_conn.other.ca, "%same"))
		{
			other_ca_same = TRUE;
		}
		else
		{
			other_ca = identification_create_from_string(msg->add_conn.other.ca);
		}
	}
	if (msg->add_conn.me.cert)
	{
		load_peer_cert(this, msg->add_conn.me.cert, &my_id);
	}
	if (msg->add_conn.other.cert)
	{
		load_peer_cert(this, msg->add_conn.other.cert, &other_id);
	}
	if (other_ca_same && my_ca)
	{
		other_ca = my_ca->clone(my_ca);
	}
	else if (my_ca_same && other_ca)
	{
		my_ca = other_ca->clone(other_ca);
	}
	
	if (my_ca)
	{
		DBG2(DBG_CFG, "  my ca:    %D", my_ca);
	}
	if (other_ca)
	{
		DBG2(DBG_CFG, "  other ca: %D", other_ca);
	}

	if (msg->add_conn.other.groups)
	{
		/* TODO: AC groups */
	}

	/* TODO: update matching */
	/* have a look for an (almost) identical peer config to reuse */
	enumerator = create_peer_cfg_enumerator(&this->configs, NULL, NULL);
	while (enumerator->enumerate(enumerator, &peer_cfg))
	{
		host_t *my_vip_conf, *other_vip_conf;
		bool my_vip_equals = FALSE, other_vip_equals = FALSE;

		my_vip_conf = peer_cfg->get_my_virtual_ip(peer_cfg);
		if ((my_vip && my_vip_conf && my_vip->equals(my_vip, my_vip_conf)) ||
			(!my_vip_conf && !my_vip))
		{
			my_vip_equals = TRUE;
		}
		DESTROY_IF(my_vip_conf);
		other_vip_conf = peer_cfg->get_other_virtual_ip(peer_cfg, NULL);
		if ((other_vip && other_vip_conf && other_vip->equals(other_vip, other_vip_conf)) ||
			(!other_vip_conf && !other_vip))
		{
			other_vip_equals = TRUE;
		}
		DESTROY_IF(other_vip_conf);
	
		ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
		if (my_id->equals(my_id, peer_cfg->get_my_id(peer_cfg))
		&&	other_id->equals(other_id, peer_cfg->get_other_id(peer_cfg))
		&&	my_host->equals(my_host, ike_cfg->get_my_host(ike_cfg))
		&&	other_host->equals(other_host, ike_cfg->get_other_host(ike_cfg))
		&&	peer_cfg->get_ike_version(peer_cfg) == (msg->add_conn.ikev2 ? 2 : 1)
		&&	peer_cfg->get_auth_method(peer_cfg) == msg->add_conn.auth_method
		&&	peer_cfg->get_eap_type(peer_cfg, &vendor) == msg->add_conn.eap_type
		&&  vendor == msg->add_conn.eap_vendor
		&&  my_vip_equals && other_vip_equals)
		{
			DBG1(DBG_CFG, "reusing existing configuration '%s'",
				 peer_cfg->get_name(peer_cfg));
			use_existing = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (use_existing)
	{
		DESTROY_IF(my_vip);
		DESTROY_IF(other_vip);
		my_host->destroy(my_host);
		my_id->destroy(my_id);
		DESTROY_IF(my_ca);
		other_host->destroy(other_host);
		other_id->destroy(other_id);
		DESTROY_IF(other_ca);
		DESTROY_IF(peer_id);
		DESTROY_IF(mediated_by_cfg);
	}
	else
	{
		ike_cfg = ike_cfg_create(msg->add_conn.other.sendcert != CERT_NEVER_SEND,
								 msg->add_conn.force_encap, my_host, other_host);

		if (msg->add_conn.algorithms.ike)
		{
			char *proposal_string;
			char *strict = msg->add_conn.algorithms.ike + strlen(msg->add_conn.algorithms.ike) - 1;

			if (*strict == '!')
				*strict = '\0';
			else
				strict = NULL;

			while ((proposal_string = strsep(&msg->add_conn.algorithms.ike, ",")))
			{
				proposal = proposal_create_from_string(PROTO_IKE, proposal_string);
				if (proposal == NULL)
				{
					DBG1(DBG_CFG, "invalid IKE proposal string: %s", proposal_string);
					my_id->destroy(my_id);
					other_id->destroy(other_id);
					my_ts->destroy(my_ts);
					other_ts->destroy(other_ts);
					DESTROY_IF(my_ca);
					DESTROY_IF(other_ca);
					ike_cfg->destroy(ike_cfg);
					return;
				}
				ike_cfg->add_proposal(ike_cfg, proposal);
			}
			if (!strict)
			{
				proposal = proposal_create_default(PROTO_IKE);
				ike_cfg->add_proposal(ike_cfg, proposal);
			}
		}
		else
		{
			proposal = proposal_create_default(PROTO_IKE);
			ike_cfg->add_proposal(ike_cfg, proposal);
		}
		
		u_int32_t rekey = 0, reauth = 0, over, jitter;
		cert_validation_t valid;
		
		jitter = msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100;
		over = msg->add_conn.rekey.margin;
		if (msg->add_conn.rekey.reauth)
		{
			reauth = msg->add_conn.rekey.ike_lifetime - over;
		}
		else
		{
			rekey = msg->add_conn.rekey.ike_lifetime - over;
		}
		
		peer_cfg = peer_cfg_create(msg->add_conn.name,
					msg->add_conn.ikev2 ? 2 : 1, ike_cfg, my_id, other_id,
					msg->add_conn.me.sendcert, msg->add_conn.auth_method,
					msg->add_conn.eap_type,	msg->add_conn.eap_vendor,
					msg->add_conn.rekey.tries, rekey, reauth, jitter, over,
					msg->add_conn.mobike,
					msg->add_conn.dpd.delay, msg->add_conn.dpd.action, my_vip, other_vip,
					msg->add_conn.p2p.mediation, mediated_by_cfg, peer_id);
		auth = peer_cfg->get_auth(peer_cfg);
		switch (msg->add_conn.crl_policy)
		{
			case CRL_STRICT_YES:
				valid = VALIDATION_GOOD;
				auth->add_item(auth, AUTHZ_CRL_VALIDATION, &valid);
				break;
			case CRL_STRICT_IFURI:
				valid = VALIDATION_SKIPPED;
				auth->add_item(auth, AUTHZ_CRL_VALIDATION, &valid);
				break;
			default:
				break;
		}
					
		if (other_ca)
		{
			DBG1(DBG_CFG, "  required other CA: %D", other_ca);
			certificate_t *cert = charon->credentials->get_cert(charon->credentials, 
										CERT_X509, KEY_ANY, other_ca, TRUE);
			if (!cert)
			{
				DBG1(DBG_CFG, "deleted connection '%s': "
 							  "no trusted certificate found for required other CA",
							   msg->add_conn.name);
				peer_cfg->destroy(peer_cfg);
				other_ca->destroy(other_ca);
				my_ts->destroy(my_ts);
				other_ts->destroy(other_ts);
				return;
			}
			/* require peer to authenticate against this cert */
			auth->add_item(auth, AUTHZ_CA_CERT, cert);
			cert->destroy(cert);
			other_ca->destroy(other_ca);
		}
		if (my_ca)
		{
			certificate_t *cert = charon->credentials->get_cert(charon->credentials, 
										CERT_X509, KEY_ANY, my_ca, TRUE);
			if (!cert)
			{
				DBG1(DBG_CFG, "deleted connection '%s': "
							  "no trusted certificate found for my CA",
					 		   msg->add_conn.name);
				peer_cfg->destroy(peer_cfg);
				my_ca->destroy(my_ca);
				my_ts->destroy(my_ts);
				other_ts->destroy(other_ts);
				return;
			}
			/* we authenticate against this cert */
			auth->add_item(auth, AUTHN_CA_CERT, cert);
			cert->destroy(cert);
		}
	}
	child_cfg = child_cfg_create(
				msg->add_conn.name, msg->add_conn.rekey.ipsec_lifetime,
				msg->add_conn.rekey.ipsec_lifetime - msg->add_conn.rekey.margin,
				msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100, 
				msg->add_conn.me.updown, msg->add_conn.me.hostaccess,
				msg->add_conn.mode);
	
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);
	
	child_cfg->add_traffic_selector(child_cfg, TRUE, my_ts);
	child_cfg->add_traffic_selector(child_cfg, FALSE, other_ts);
	
	if (msg->add_conn.algorithms.esp)
	{
		char *proposal_string;
		char *strict = msg->add_conn.algorithms.esp + strlen(msg->add_conn.algorithms.esp) - 1;

		if (*strict == '!')
			*strict = '\0';
		else
			strict = NULL;
		
		while ((proposal_string = strsep(&msg->add_conn.algorithms.esp, ",")))
		{
			proposal = proposal_create_from_string(PROTO_ESP, proposal_string);
			if (proposal == NULL)
			{
				DBG1(DBG_CFG, "invalid ESP proposal string: %s", proposal_string);
				peer_cfg->destroy(peer_cfg);
				return;
			}
			child_cfg->add_proposal(child_cfg, proposal);
		}
		if (!strict)
		{
			proposal = proposal_create_default(PROTO_ESP);
			child_cfg->add_proposal(child_cfg, proposal);
		}
	}
	else
	{
		proposal = proposal_create_default(PROTO_ESP);
		child_cfg->add_proposal(child_cfg, proposal);
	}
	
	if (!use_existing)
	{
		/* add config to backend */
		this->configs.mutex->lock(this->configs.mutex);
		this->configs.list->insert_last(this->configs.list, peer_cfg);
		this->configs.mutex->unlock(this->configs.mutex);
		DBG1(DBG_CFG, "added configuration '%s': %H[%D]...%H[%D]",
			 msg->add_conn.name, my_host, my_id, other_host, other_id);
	}
	return;

	/* mopping up after parsing errors */

destroy_ids:
	my_id->destroy(my_id);
	other_id->destroy(other_id);
	DESTROY_IF(mediated_by_cfg);
	DESTROY_IF(peer_id);

destroy_hosts:
	my_host->destroy(my_host);
	other_host->destroy(other_host);
}

/**
 * Delete a connection from the list
 */
static void stroke_del_conn(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	enumerator_t *enumerator, *children;
	peer_cfg_t *peer;
	child_cfg_t *child;
	
	pop_string(msg, &(msg->del_conn.name));
	DBG1(DBG_CFG, "received stroke: delete connection '%s'", msg->del_conn.name);
	
	this->configs.mutex->lock(this->configs.mutex);
	enumerator = this->configs.list->create_enumerator(this->configs.list);
	while (enumerator->enumerate(enumerator, (void**)&peer))
	{
		/* remove peer config with such a name */
		if (streq(peer->get_name(peer), msg->del_conn.name))
		{
			this->configs.list->remove_at(this->configs.list, enumerator);
			peer->destroy(peer);
			continue;
		}
		/* remove any child with such a name */
		children = peer->create_child_cfg_enumerator(peer);
		while (children->enumerate(children, &child))
		{
			if (streq(child->get_name(child), msg->del_conn.name))
			{
				peer->remove_child_cfg(peer, enumerator);
				child->destroy(child);
			}
		}
		children->destroy(children);
	}
	enumerator->destroy(enumerator);
	this->configs.mutex->unlock(this->configs.mutex);
	
	fprintf(out, "deleted connection '%s'\n", msg->del_conn.name);
}

/**
 * get the child_cfg with the same name as the peer cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;
	
	enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * logging to the stroke interface
 */
static bool stroke_log(stroke_log_info_t *info, signal_t signal, level_t level,
					   ike_sa_t *ike_sa, char *format, va_list args)
{
	if (level <= info->level)
	{
		if (vfprintf(info->out, format, args) < 0 ||
			fprintf(info->out, "\n") < 0 ||
			fflush(info->out) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * initiate a connection by name
 */
static void stroke_initiate(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->initiate.name));
	DBG1(DBG_CFG, "received stroke: initiate '%s'", msg->initiate.name);
	
	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  msg->initiate.name);
	if (peer_cfg == NULL)
	{
		fprintf(out, "no config named '%s'\n", msg->initiate.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		DBG1(DBG_CFG, "ignoring initiation request for IKEv%d config",
			 peer_cfg->get_ike_version(peer_cfg));
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	child_cfg = get_child_from_peer(peer_cfg, msg->initiate.name);
	if (child_cfg == NULL)
	{
		fprintf(out, "no child config named '%s'\n", msg->initiate.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	if (msg->output_verbosity < 0)
	{
		charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 NULL, NULL);
	}
	else
	{
		info.out = out;
		info.level = msg->output_verbosity;
		charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 (controller_cb_t)stroke_log, &info);
	}
}

/**
 * route a policy (install SPD entries)
 */
static void stroke_route(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->route.name));
	DBG1(DBG_CFG, "received stroke: route '%s'", msg->route.name);
	
	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  msg->route.name);
	if (peer_cfg == NULL)
	{
		fprintf(out, "no config named '%s'\n", msg->route.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	child_cfg = get_child_from_peer(peer_cfg, msg->route.name);
	if (child_cfg == NULL)
	{
		fprintf(out, "no child config named '%s'\n", msg->route.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	info.out = out;
	info.level = msg->output_verbosity;
	charon->controller->route(charon->controller, peer_cfg, child_cfg,
							  (controller_cb_t)stroke_log, &info);
	peer_cfg->destroy(peer_cfg);
	child_cfg->destroy(child_cfg);
}

/**
 * unroute a policy
 */
static void stroke_unroute(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	char *name;
	ike_sa_t *ike_sa;
	iterator_t *iterator;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->terminate.name));
	name = msg->terminate.name;
	
	info.out = out;
	info.level = msg->output_verbosity;
	
	iterator = charon->controller->create_ike_sa_iterator(charon->controller);
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;
		u_int32_t id;

		children = ike_sa->create_child_sa_iterator(ike_sa);
		while (children->iterate(children, (void**)&child_sa))
		{
			if (child_sa->get_state(child_sa) == CHILD_ROUTED &&
				streq(name, child_sa->get_name(child_sa)))
			{
				id = child_sa->get_reqid(child_sa);
				children->destroy(children);
				iterator->destroy(iterator);
				charon->controller->unroute(charon->controller, id,
								(controller_cb_t)stroke_log, &info);
				return;
			}
		}
		children->destroy(children);
	}
	iterator->destroy(iterator);
	DBG1(DBG_CFG, "no such SA found");
}

/**
 * terminate a connection by name
 */
static void stroke_terminate(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	char *string, *pos = NULL, *name = NULL;
	u_int32_t id = 0;
	bool child;
	int len;
	ike_sa_t *ike_sa;
	iterator_t *iterator;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->terminate.name));
	string = msg->terminate.name;
	DBG1(DBG_CFG, "received stroke: terminate '%s'", string);
	
	len = strlen(string);
	if (len < 1)
	{
		DBG1(DBG_CFG, "error parsing string");
		return;
	}
	switch (string[len-1])
	{
		case '}':
			child = TRUE;
			pos = strchr(string, '{');
			break;
		case ']':
			child = FALSE;
			pos = strchr(string, '[');
			break;
		default:
			name = string;
			child = FALSE;
			break;
	}
	
	if (name)
	{
		/* is a single name */
	}
	else if (pos == string + len - 2)
	{	/* is name[] or name{} */
		string[len-2] = '\0';
		name = string;
	}
	else
	{	/* is name[123] or name{23} */
		string[len-1] = '\0';
		id = atoi(pos + 1);
		if (id == 0)
		{
			DBG1(DBG_CFG, "error parsing string");
			return;
		}
	}
	
	info.out = out;
	info.level = msg->output_verbosity;
	
	iterator = charon->controller->create_ike_sa_iterator(charon->controller);
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;
		
		if (child)
		{
			children = ike_sa->create_child_sa_iterator(ike_sa);
			while (children->iterate(children, (void**)&child_sa))
			{
				if ((name && streq(name, child_sa->get_name(child_sa))) ||
					(id && id == child_sa->get_reqid(child_sa)))
				{
					id = child_sa->get_reqid(child_sa);
					children->destroy(children);
					iterator->destroy(iterator);
					
					charon->controller->terminate_child(charon->controller, id,
									(controller_cb_t)stroke_log, &info);
					return;
				}
			}
			children->destroy(children);
		}
		else if ((name && streq(name, ike_sa->get_name(ike_sa))) ||
				 (id && id == ike_sa->get_unique_id(ike_sa)))
		{
			id = ike_sa->get_unique_id(ike_sa);
			/* unlock manager first */
			iterator->destroy(iterator);
			
			charon->controller->terminate_ike(charon->controller, id,
								 	(controller_cb_t)stroke_log, &info);
			return;
		}
		
	}
	iterator->destroy(iterator);
	DBG1(DBG_CFG, "no such SA found");
}

/**
 * Add a ca information record to the cainfo list
 */
static void stroke_add_ca(private_stroke_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	certificate_t *cert;
	ca_section_t *ca;
	
	pop_string(msg, &msg->add_ca.name);
	pop_string(msg, &msg->add_ca.cacert);
	pop_string(msg, &msg->add_ca.crluri);
	pop_string(msg, &msg->add_ca.crluri2);
	pop_string(msg, &msg->add_ca.ocspuri);
	pop_string(msg, &msg->add_ca.ocspuri2);
	
	DBG1(DBG_CFG, "received stroke: add ca '%s'", msg->add_ca.name);
	
	DBG2(DBG_CFG, "ca %s",        msg->add_ca.name);
	DBG2(DBG_CFG, "  cacert=%s",  msg->add_ca.cacert);
	DBG2(DBG_CFG, "  crluri=%s",  msg->add_ca.crluri);
	DBG2(DBG_CFG, "  crluri2=%s", msg->add_ca.crluri2);
	DBG2(DBG_CFG, "  ocspuri=%s", msg->add_ca.ocspuri);
	DBG2(DBG_CFG, "  ocspuri2=%s", msg->add_ca.ocspuri2);

	if (msg->add_ca.cacert == NULL)
	{
		DBG1(DBG_CFG, "missing cacert parameter");
		return;
	}

	cert = load_ca_cert(this, msg->add_ca.cacert);
	if (cert)
	{
		ca = ca_section_create(msg->add_ca.name, cert);
		if (msg->add_ca.crluri)
		{
			ca->crl->insert_last(ca->crl, strdup(msg->add_ca.crluri));
		}
		if (msg->add_ca.crluri2)
		{
			ca->crl->insert_last(ca->crl, strdup(msg->add_ca.crluri2));
		}
		if (msg->add_ca.ocspuri)
		{
			ca->ocsp->insert_last(ca->ocsp, strdup(msg->add_ca.ocspuri));
		}
		if (msg->add_ca.ocspuri2)
		{
			ca->ocsp->insert_last(ca->ocsp, strdup(msg->add_ca.ocspuri2));
		}
		this->ca_creds.mutex->lock(this->ca_creds.mutex);
		this->ca_creds.sections->insert_last(this->ca_creds.sections, ca);
		this->ca_creds.mutex->unlock(this->ca_creds.mutex);
		DBG1(DBG_CFG, "added ca '%s'", msg->add_ca.name);
	}
}

/**
 * Delete a ca information record from the cainfo list
 */
static void stroke_del_ca(private_stroke_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	enumerator_t *enumerator;
	ca_section_t *ca = NULL;
	
	pop_string(msg, &(msg->del_ca.name));
	DBG1(DBG_CFG, "received stroke: delete ca '%s'", msg->del_ca.name);
	
	this->ca_creds.mutex->lock(this->ca_creds.mutex);
	enumerator = this->ca_creds.sections->create_enumerator(this->ca_creds.sections);
	while (enumerator->enumerate(enumerator, &ca))
	{
		if (streq(ca->name, msg->del_ca.name))
		{
			this->ca_creds.sections->remove_at(this->ca_creds.sections, enumerator);
			break;
		}
		ca = NULL;
	}
	enumerator->destroy(enumerator);
	this->ca_creds.mutex->unlock(this->ca_creds.mutex);
	if (ca == NULL)
	{
		fprintf(out, "no ca named '%s' found\n", msg->del_ca.name);
		return;
	}
	ca_section_destroy(ca);
	/* TODO: flush cached certs */
}

/**
 * log an IKE_SA to out
 */
static void log_ike_sa(FILE *out, ike_sa_t *ike_sa, bool all)
{
	ike_sa_id_t *id = ike_sa->get_id(ike_sa);
	u_int32_t rekey, reauth;

	fprintf(out, "%12s[%d]: %N, %H[%D]...%H[%D]\n",
			ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
			ike_sa_state_names, ike_sa->get_state(ike_sa),
			ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
			ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
	
	if (all)
	{
		fprintf(out, "%12s[%d]: IKE SPIs: %.16llx_i%s %.16llx_r%s",
				ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
				id->get_initiator_spi(id), id->is_initiator(id) ? "*" : "",
				id->get_responder_spi(id), id->is_initiator(id) ? "" : "*");
	
		rekey = ike_sa->get_statistic(ike_sa, STAT_REKEY_TIME);
		reauth = ike_sa->get_statistic(ike_sa, STAT_REAUTH_TIME);
		if (rekey)
		{
			fprintf(out, ", rekeying in %V", &rekey);
		}
		if (reauth)
		{
			fprintf(out, ", reauthentication in %V", &reauth);
		}
		if (!rekey && !reauth)
		{
			fprintf(out, ", rekeying disabled");
		}
		fprintf(out, "\n");
	}
}

/**
 * log an CHILD_SA to out
 */
static void log_child_sa(FILE *out, child_sa_t *child_sa, bool all)
{
	u_int32_t rekey, now = time(NULL);
	u_int32_t use_in, use_out, use_fwd;
	encryption_algorithm_t encr_alg;
	integrity_algorithm_t int_alg;
	size_t encr_len, int_len;
	mode_t mode;
	
	child_sa->get_stats(child_sa, &mode, &encr_alg, &encr_len,
						&int_alg, &int_len, &rekey, &use_in, &use_out,
						&use_fwd);
	
	fprintf(out, "%12s{%d}:  %N, %N", 
			child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			child_sa_state_names, child_sa->get_state(child_sa),
			mode_names, mode);
	
	if (child_sa->get_state(child_sa) == CHILD_INSTALLED)
	{
		fprintf(out, ", %N SPIs: %.8x_i %.8x_o",
				protocol_id_names, child_sa->get_protocol(child_sa),
				htonl(child_sa->get_spi(child_sa, TRUE)),
				htonl(child_sa->get_spi(child_sa, FALSE)));
		
		if (all)
		{
			fprintf(out, "\n%12s{%d}:  ", child_sa->get_name(child_sa), 
					child_sa->get_reqid(child_sa));
			
			
			if (child_sa->get_protocol(child_sa) == PROTO_ESP)
			{
				fprintf(out, "%N", encryption_algorithm_names, encr_alg);
				
				if (encr_len)
				{
					fprintf(out, "-%d", encr_len);
				}
				fprintf(out, "/");
			}
			
			fprintf(out, "%N", integrity_algorithm_names, int_alg);
			if (int_len)
			{
				fprintf(out, "-%d", int_len);
			}
			fprintf(out, ", rekeying ");
			
			if (rekey)
			{
				fprintf(out, "in %#V", &now, &rekey);
			}
			else
			{
				fprintf(out, "disabled");
			}
			
			fprintf(out, ", last use: ");
			use_in = max(use_in, use_fwd);
			if (use_in)
			{
				fprintf(out, "%ds_i ", now - use_in);
			}
			else
			{
				fprintf(out, "no_i ");
			}
			if (use_out)
			{
				fprintf(out, "%ds_o ", now - use_out);
			}
			else
			{
				fprintf(out, "no_o ");
			}
		}
	}
	
	fprintf(out, "\n%12s{%d}:   %#R=== %#R\n",
			child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			child_sa->get_traffic_selectors(child_sa, TRUE),
			child_sa->get_traffic_selectors(child_sa, FALSE));
}

/**
 * show status of daemon
 */
static void stroke_status(private_stroke_t *this, stroke_msg_t *msg, FILE *out,
						  bool all)
{
	enumerator_t *enumerator, *children;
	iterator_t *iterator;
	host_t *host;
	peer_cfg_t *peer_cfg;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	ike_sa_t *ike_sa;
	char *name = NULL;
	
	if (msg->status.name)
	{
		pop_string(msg, &(msg->status.name));
		name = msg->status.name;
	}
	
	if (all)
	{
		fprintf(out, "Performance:\n");
		fprintf(out, "  worker threads: %d idle of %d,",
				charon->processor->get_idle_threads(charon->processor),
				charon->processor->get_total_threads(charon->processor));
		fprintf(out, " job queue load: %d,",
				charon->processor->get_job_load(charon->processor));
		fprintf(out, " scheduled events: %d\n",
				charon->scheduler->get_job_load(charon->scheduler));
		iterator = charon->kernel_interface->create_address_iterator(
													charon->kernel_interface);
		fprintf(out, "Listening IP addresses:\n");
		while (iterator->iterate(iterator, (void**)&host))
		{
			fprintf(out, "  %H\n", host);
		}
		iterator->destroy(iterator);
	
		fprintf(out, "Connections:\n");
		enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends);
		while (enumerator->enumerate(enumerator, (void**)&peer_cfg))
		{
			if (peer_cfg->get_ike_version(peer_cfg) != 2 ||
				(name && !streq(name, peer_cfg->get_name(peer_cfg))))
			{
				continue;
			}
			
			ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
			fprintf(out, "%12s:  %H[%D]...%H[%D]\n", peer_cfg->get_name(peer_cfg),
					ike_cfg->get_my_host(ike_cfg), peer_cfg->get_my_id(peer_cfg),
					ike_cfg->get_other_host(ike_cfg), peer_cfg->get_other_id(peer_cfg));
			/* TODO: list CAs and groups */
			children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
			while (children->enumerate(children, &child_cfg))
			{
				linked_list_t *my_ts, *other_ts;
				my_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, NULL);
				other_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, NULL);
				fprintf(out, "%12s:    %#R=== %#R\n", child_cfg->get_name(child_cfg),
						my_ts, other_ts);
				my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
				other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));
			}
			children->destroy(children);
		}
		enumerator->destroy(enumerator);
	}
	
	iterator = charon->ike_sa_manager->create_iterator(charon->ike_sa_manager);
	if (all && iterator->get_count(iterator) > 0)
	{
		fprintf(out, "Security Associations:\n");
	}
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		bool ike_printed = FALSE;
		child_sa_t *child_sa;
		iterator_t *children = ike_sa->create_child_sa_iterator(ike_sa);

		if (name == NULL || streq(name, ike_sa->get_name(ike_sa)))
		{
			log_ike_sa(out, ike_sa, all);
			ike_printed = TRUE;
		}

		while (children->iterate(children, (void**)&child_sa))
		{
			if (name == NULL || streq(name, child_sa->get_name(child_sa)))
			{
				if (!ike_printed)
				{
					log_ike_sa(out, ike_sa, all);
					ike_printed = TRUE;
				}
				log_child_sa(out, child_sa, all);
			}	
		}
		children->destroy(children);
	}
	iterator->destroy(iterator);
}

/**
 * list all X.509 certificates matching the flags
 */
static void stroke_list_certs(char *label, x509_flag_t flags, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t now = time(NULL);
	certificate_t *cert;
	enumerator_t *enumerator;
	
	enumerator = charon->credentials->create_cert_enumerator(
						charon->credentials, CERT_X509, KEY_ANY, NULL, FALSE);
	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		x509_t *x509 = (x509_t*)cert;
		x509_flag_t x509_flags = x509->get_flags(x509);

		/* list only if flag is set, or flags == 0 (ignoring self-signed) */
		if ((x509_flags & flags) || (flags == (x509_flags & ~X509_SELF_SIGNED)))
		{
			enumerator_t *enumerator;
			identification_t *altName;
			bool first_altName = TRUE;
			chunk_t serial = x509->get_serial(x509);
			identification_t *authkey = x509->get_authKeyIdentifier(x509);
			time_t notBefore, notAfter;
			public_key_t *public = cert->get_public_key(cert);

			if (first)
			{
				fprintf(out, "\n");
				fprintf(out, "List of %s:\n", label);
				first = FALSE;
			}
			fprintf(out, "\n");

			/* list subjectAltNames */
			enumerator = x509->create_subjectAltName_enumerator(x509);
			while (enumerator->enumerate(enumerator, (void**)&altName))
			{
				if (first_altName)
				{
					fprintf(out, "  altNames:  ");
					first_altName = FALSE;
				}
				else
				{
					fprintf(out, ", ");
				}
				fprintf(out, "%D", altName);
			}
			if (!first_altName)
			{
				fprintf(out, "\n");
			}
			enumerator->destroy(enumerator);

			fprintf(out, "  subject:  %D\n", cert->get_subject(cert));
			fprintf(out, "  issuer:   %D\n", cert->get_issuer(cert));
			fprintf(out, "  serial:    %#B\n", &serial);

			/* list validity */
			cert->get_validity(cert, &now, &notBefore, &notAfter);
			fprintf(out, "  validity:  not before %#T, ", &notBefore, utc);
			if (now < notBefore)
			{
				fprintf(out, "not valid yet (valid in %#V)\n", &now, &notBefore);
			}
			else
			{
				fprintf(out, "ok\n");
			}
			fprintf(out, "             not after  %#T, ", &notAfter, utc);
			if (now > notAfter)
			{
				fprintf(out, "expired (%#V ago)\n", &now, &notAfter);
			}
			else
			{
				fprintf(out, "ok");
				if (now > notAfter - CERT_WARNING_INTERVAL * 60 * 60 * 24)
				{
					fprintf(out, " (expires in %#V)", &now, &notAfter);
				}
				fprintf(out, " \n");
			}
	
			/* list public key information */
			if (public)
			{
				private_key_t *private = NULL;
				identification_t *id, *keyid;
			
				id    = public->get_id(public, ID_PUBKEY_SHA1);
				keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);

				private = charon->credentials->get_private(
									charon->credentials, 
									public->get_type(public), keyid, NULL);
				fprintf(out, "  pubkey:    %N %d bits%s\n",
						key_type_names, public->get_type(public),
						public->get_keysize(public) * 8,
						private ? ", has private key" : "");
				fprintf(out, "  keyid:     %D\n", keyid);
				fprintf(out, "  subjkey:   %D\n", id);
				DESTROY_IF(private);
				public->destroy(public);
			}
	
			/* list optional authorityKeyIdentifier */
			if (authkey)
			{
				fprintf(out, "  authkey:   %D\n", authkey);
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all X.509 CRLs
 */
static void stroke_list_crls(bool utc, FILE *out)
{
	bool first = TRUE;
	time_t thisUpdate, nextUpdate, now = time(NULL);
	certificate_t *cert;
	enumerator_t *enumerator;
	
	enumerator = charon->credentials->create_cert_enumerator(
						charon->credentials, CERT_X509_CRL, KEY_ANY, NULL, FALSE);
	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		crl_t *crl = (crl_t*)cert;
		chunk_t serial  = crl->get_serial(crl);
		identification_t *authkey = crl->get_authKeyIdentifier(crl);

		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 CRLs:\n");
			first = FALSE;
		}
		fprintf(out, "\n");

		fprintf(out, "  issuer:   %D\n", cert->get_issuer(cert));

		/* list optional crlNumber */
		if (serial.ptr)
		{
			fprintf(out, "  serial:    %#B\n", &serial);
		}

		/* count the number of revoked certificates */
		{
			int count = 0;
			enumerator_t *enumerator = crl->create_enumerator(crl);

			while (enumerator->enumerate(enumerator, NULL, NULL, NULL))
			{
				count++;
			}
			fprintf(out, "  revoked:   %d certificate%s\n", count,
							(count == 1)? "" : "s");
			enumerator->destroy(enumerator);
		}

		/* list validity */
		cert->get_validity(cert, &now, &thisUpdate, &nextUpdate);
		fprintf(out, "  updates:   this %#T\n",  &thisUpdate, utc);
		fprintf(out, "             next %#T, ", &nextUpdate, utc);
		if (now > nextUpdate)
		{
			fprintf(out, "expired (%#V ago)\n", &now, &nextUpdate);
		}
		else
		{
			fprintf(out, "ok");
			if (now > nextUpdate - CRL_WARNING_INTERVAL * 60 * 60 * 24)
			{
				fprintf(out, " (expires in %#V)", &now, &nextUpdate);
			}
			fprintf(out, " \n");
		}

		/* list optional authorityKeyIdentifier */
		if (authkey)
		{
			fprintf(out, "  authkey:   %D\n", authkey);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all CA information sections
 */
static void stroke_list_cainfos(private_stroke_t *this, FILE *out)
{
	bool first = TRUE;
	ca_section_t *section;
	enumerator_t *enumerator;
	
	this->ca_creds.mutex->lock(this->ca_creds.mutex);
	enumerator = this->ca_creds.sections->create_enumerator(this->ca_creds.sections);
	while (enumerator->enumerate(enumerator, (void**)&section))
	{
		certificate_t *cert = section->cert;
		public_key_t *public = cert->get_public_key(cert);

		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of CA Information Sections:\n");
			first = FALSE;
		}
		fprintf(out, "\n");
		fprintf(out, "  authname: %D\n", cert->get_subject(cert));

		/* list authkey and keyid */
		if (public)
		{
			fprintf(out, "  authkey:   %D\n",
					public->get_id(public, ID_PUBKEY_SHA1));
			fprintf(out, "  keyid:     %D\n",
					public->get_id(public, ID_PUBKEY_INFO_SHA1));
			public->destroy(public);
		}
		
		/* list CRL URIs */
		{
			bool first = TRUE;
			char *crluri;
			enumerator_t *enumerator;

			enumerator = section->crl->create_enumerator(section->crl);
			while (enumerator->enumerate(enumerator, (void**)&crluri))
			{
				if (first)
				{
					fprintf(out, "  crluris:  ");
					first = FALSE;
				}
				else
				{
					fprintf(out, "            ");
				}
				fprintf(out, "'%s'\n", crluri);
			}
			enumerator->destroy(enumerator);
		}

		/* list OCSP URIs */
		{
			bool first = TRUE;
			char *ocspuri;
			enumerator_t *enumerator;

			enumerator = section->ocsp->create_enumerator(section->ocsp);
			while (enumerator->enumerate(enumerator, (void**)&ocspuri))
			{
				if (first)
				{
					fprintf(out, "  ocspuris: ");
					first = FALSE;
				}
				else
				{
					fprintf(out, "            ");
				}
				fprintf(out, "'%s'\n", ocspuri);
			}
			enumerator->destroy(enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->ca_creds.mutex->unlock(this->ca_creds.mutex);
}

/**
 * list various information
 */
static void stroke_list(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	if (msg->list.flags & LIST_CERTS)
	{
		stroke_list_certs("X.509 End Entity Certificates",
						  0, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_CACERTS)
	{
		stroke_list_certs("X.509 CA Certificates",
						  X509_CA, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_OCSPCERTS)
	{
		stroke_list_certs("X.509 OCSP Signer Certificates",
						  X509_OCSP_SIGNER, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_AACERTS)
	{
		stroke_list_certs("X.509 AA Certificates",
						  X509_AA, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_ACERTS)
	{

	}
	if (msg->list.flags & LIST_CAINFOS)
	{
		stroke_list_cainfos(this, out);
	}
	if (msg->list.flags & LIST_CRLS)
	{
		stroke_list_crls(msg->list.utc, out);
	}
	if (msg->list.flags & LIST_OCSP)
	{

	}
}

/**
 * reread various information
 */
static void stroke_reread(private_stroke_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	if (msg->reread.flags & REREAD_SECRETS)
	{
		DBG1(DBG_CFG, "rereading secrets");
		load_secrets(this);
	}
	if (msg->reread.flags & REREAD_CACERTS)
	{
		DBG1(DBG_CFG, "rereading CA certificates from '%s'",
			 CA_CERTIFICATE_DIR);
		load_certdir(this, CA_CERTIFICATE_DIR, CERT_X509, X509_CA);
	}
	if (msg->reread.flags & REREAD_OCSPCERTS)
	{
		DBG1(DBG_CFG, "rereading OCSP signer certificates from '%s'",
			 OCSP_CERTIFICATE_DIR);
		load_certdir(this, OCSP_CERTIFICATE_DIR, CERT_X509,
			 X509_OCSP_SIGNER);
	}
	if (msg->reread.flags & REREAD_AACERTS)
	{
		DBG1(DBG_CFG, "rereading AA certificates from '%s'",
			 AA_CERTIFICATE_DIR);
		load_certdir(this, AA_CERTIFICATE_DIR, CERT_X509, X509_AA);
	}
	if (msg->reread.flags & REREAD_ACERTS)
	{
		DBG1(DBG_CFG, "rereading attribute certificates from '%s'",
			 ATTR_CERTIFICATE_DIR);
		load_certdir(this, ATTR_CERTIFICATE_DIR, CERT_X509_AC, 0);
	}
	if (msg->reread.flags & REREAD_CRLS)
	{
		DBG1(DBG_CFG, "rereading CRLs from '%s'",
			 CRL_DIR);
		load_certdir(this, CRL_DIR, CERT_X509_CRL, 0);
	}
}

/**
 * purge various information
 */
static void stroke_purge(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	/* TODO: flush cache */
}

signal_t get_signal_from_logtype(char *type)
{
	if      (strcasecmp(type, "any") == 0) return SIG_ANY;
	else if (strcasecmp(type, "mgr") == 0) return DBG_MGR;
	else if (strcasecmp(type, "ike") == 0) return DBG_IKE;
	else if (strcasecmp(type, "chd") == 0) return DBG_CHD;
	else if (strcasecmp(type, "job") == 0) return DBG_JOB;
	else if (strcasecmp(type, "cfg") == 0) return DBG_CFG;
	else if (strcasecmp(type, "knl") == 0) return DBG_KNL;
	else if (strcasecmp(type, "net") == 0) return DBG_NET;
	else if (strcasecmp(type, "enc") == 0) return DBG_ENC;
	else if (strcasecmp(type, "lib") == 0) return DBG_LIB;
	else return -1;
}

/**
 * set the verbosity debug output
 */
static void stroke_loglevel(private_stroke_t *this, stroke_msg_t *msg, FILE *out)
{
	signal_t signal;
	
	pop_string(msg, &(msg->loglevel.type));
	DBG1(DBG_CFG, "received stroke: loglevel %d for %s",
		 msg->loglevel.level, msg->loglevel.type);
	
	signal = get_signal_from_logtype(msg->loglevel.type);
	if (signal < 0)
	{
		fprintf(out, "invalid type (%s)!\n", msg->loglevel.type);
		return;
	}
	
	charon->outlog->set_level(charon->outlog, signal, msg->loglevel.level);
	charon->syslog->set_level(charon->syslog, signal, msg->loglevel.level);
}

typedef struct stroke_job_context_t stroke_job_context_t;

/** job context to pass to processing thread */
struct stroke_job_context_t {

	/** file descriptor to read from */
	int fd;
	
	/** global stroke interface */
	private_stroke_t *this;
};

/**
 * destroy a job context
 */
static void stroke_job_context_destroy(stroke_job_context_t *this)
{
	close(this->fd);
	free(this);
}

/**
 * process a stroke request from the socket pointed by "fd"
 */
static job_requeue_t stroke_process(stroke_job_context_t *ctx)
{
	stroke_msg_t *msg;
	u_int16_t msg_length;
	ssize_t bytes_read;
	FILE *out;
	private_stroke_t *this = ctx->this;
	int strokefd = ctx->fd;
	
	/* peek the length */
	bytes_read = recv(strokefd, &msg_length, sizeof(msg_length), MSG_PEEK);
	if (bytes_read != sizeof(msg_length))
	{
		DBG1(DBG_CFG, "reading length of stroke message failed: %s",
			 strerror(errno));
		close(strokefd);
		return JOB_REQUEUE_NONE;
	}
	
	/* read message */
	msg = malloc(msg_length);
	bytes_read = recv(strokefd, msg, msg_length, 0);
	if (bytes_read != msg_length)
	{
		DBG1(DBG_CFG, "reading stroke message failed: %s", strerror(errno));
		close(strokefd);
		return JOB_REQUEUE_NONE;
	}
	
	out = fdopen(strokefd, "w");
	if (out == NULL)
	{
		DBG1(DBG_CFG, "opening stroke output channel failed: %s", strerror(errno));
		close(strokefd);
		free(msg);
		return JOB_REQUEUE_NONE;
	}
	
	DBG3(DBG_CFG, "stroke message %b", (void*)msg, msg_length);
	
	/* the stroke_* functions are blocking, as they listen on the bus. Add
	 * cancellation handlers. */
	pthread_cleanup_push((void*)fclose, out);
	pthread_cleanup_push(free, msg);
	
	switch (msg->type)
	{
		case STR_INITIATE:
			stroke_initiate(this, msg, out);
			break;
		case STR_ROUTE:
			stroke_route(this, msg, out);
			break;
		case STR_UNROUTE:
			stroke_unroute(this, msg, out);
			break;
		case STR_TERMINATE:
			stroke_terminate(this, msg, out);
			break;
		case STR_STATUS:
			stroke_status(this, msg, out, FALSE);
			break;
		case STR_STATUS_ALL:
			stroke_status(this, msg, out, TRUE);
			break;
		case STR_ADD_CONN:
			stroke_add_conn(this, msg, out);
			break;
		case STR_DEL_CONN:
			stroke_del_conn(this, msg, out);
			break;
		case STR_ADD_CA:
			stroke_add_ca(this, msg, out);
			break;
		case STR_DEL_CA:
			stroke_del_ca(this, msg, out);
			break;
		case STR_LOGLEVEL:
			stroke_loglevel(this, msg, out);
			break;
		case STR_LIST:
			stroke_list(this, msg, out);
			break;
		case STR_REREAD:
			stroke_reread(this, msg, out);
			break;
		case STR_PURGE:
			stroke_purge(this, msg, out);
			break;
		default:
			DBG1(DBG_CFG, "received unknown stroke");
	}
	/* remove and execute cancellation handlers */
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	
	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of private_stroke_t.stroke_receive.
 */
static job_requeue_t stroke_receive(private_stroke_t *this)
{
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	int strokefd;
	int oldstate;
	callback_job_t *job;
	stroke_job_context_t *ctx;
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	pthread_setcancelstate(oldstate, NULL);
	
	if (strokefd < 0)
	{
		DBG1(DBG_CFG, "accepting stroke connection failed: %s", strerror(errno));
		return JOB_REQUEUE_FAIR;
	}
	
	ctx = malloc_thing(stroke_job_context_t);
	ctx->fd = strokefd;
	ctx->this = this;
	job = callback_job_create((callback_job_cb_t)stroke_process,
							  ctx, (void*)stroke_job_context_destroy, this->job);
	charon->processor->queue_job(charon->processor, (job_t*)job);
	
	return JOB_REQUEUE_FAIR;
}

/**
 * Implementation of interface_t.destroy.
 */
static void destroy(private_stroke_t *this)
{
	this->job->cancel(this->job);
	charon->credentials->remove_set(charon->credentials, &this->ca_creds.set);
	charon->credentials->remove_set(charon->credentials, &this->creds.set);
	charon->backends->remove_backend(charon->backends, &this->configs.backend);
	this->ca_creds.sections->destroy_function(this->ca_creds.sections, (void*)ca_section_destroy);
	this->ca_creds.mutex->destroy(this->ca_creds.mutex);
	this->creds.certs->destroy_offset(this->creds.certs, offsetof(certificate_t, destroy));
	this->creds.shared->destroy_offset(this->creds.shared, offsetof(shared_key_t, destroy));
	this->creds.private->destroy_offset(this->creds.private, offsetof(private_key_t, destroy));
	this->creds.mutex->destroy(this->creds.mutex);
	this->configs.list->destroy_offset(this->configs.list, offsetof(peer_cfg_t, destroy));
	this->configs.mutex->destroy(this->configs.mutex);
	free(this);
}

/**
 * initialize and open stroke socket
 */
static bool open_socket(private_stroke_t *this)
{
	struct sockaddr_un socket_addr = { AF_UNIX, STROKE_SOCKET};
	mode_t old;
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "could not create stroke socket");
		return FALSE;
	}
	
	unlink(socket_addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		DBG1(DBG_CFG, "could not bind stroke socket: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(socket_addr.sun_path, IPSEC_UID, IPSEC_GID) != 0)
	{
		DBG1(DBG_CFG, "changing stroke socket permissions failed: %s",
			 strerror(errno));
	}
	
	if (listen(this->socket, 0) < 0)
	{
		DBG1(DBG_CFG, "could not listen on stroke socket: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

/**
 * load all certificates from ipsec.d
 */
static void load_certs(private_stroke_t *this)
{
	DBG1(DBG_CFG, "loading CA certificates from '%s'",
		 CA_CERTIFICATE_DIR);
	load_certdir(this, CA_CERTIFICATE_DIR, CERT_X509, X509_CA);

	DBG1(DBG_CFG, "loading AA certificates from '%s'",
		 AA_CERTIFICATE_DIR);
	load_certdir(this, AA_CERTIFICATE_DIR, CERT_X509, X509_AA);

	DBG1(DBG_CFG, "loading OCSP signer certificates from '%s'",
		 OCSP_CERTIFICATE_DIR);
	load_certdir(this, OCSP_CERTIFICATE_DIR, CERT_X509, X509_OCSP_SIGNER);

	DBG1(DBG_CFG, "loading attribute certificates from '%s'",
		 ATTR_CERTIFICATE_DIR);
	load_certdir(this, ATTR_CERTIFICATE_DIR, CERT_X509_AC, 0);

	DBG1(DBG_CFG, "loading CRLs from '%s'",
		 CRL_DIR);
	load_certdir(this, CRL_DIR, CERT_X509_CRL, 0);
}

/*
 * Described in header-file
 */
plugin_t *plugin_create()
{
	private_stroke_t *this = malloc_thing(private_stroke_t);

	/* public functions */
	this->public.plugin.destroy = (void (*)(plugin_t*))destroy;
	
	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}
	
	this->ca_creds.sections = linked_list_create();
	this->ca_creds.mutex = mutex_create(MUTEX_RECURSIVE);
	this->creds.certs = linked_list_create();
	this->creds.shared = linked_list_create();
	this->creds.private = linked_list_create();
	this->creds.mutex = mutex_create(MUTEX_RECURSIVE);
	this->configs.list = linked_list_create();
	this->configs.mutex = mutex_create(MUTEX_RECURSIVE);
	
	this->ca_creds.set.create_private_enumerator = (void*)return_null;
	this->ca_creds.set.create_cert_enumerator = (void*)return_null;
	this->ca_creds.set.create_shared_enumerator = (void*)return_null;
	this->ca_creds.set.create_cdp_enumerator = (void*)create_cdp_enumerator;
	charon->credentials->add_set(charon->credentials, &this->ca_creds.set);
	
	this->creds.set.create_private_enumerator = (void*)create_private_enumerator;
	this->creds.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->creds.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->creds.set.create_cdp_enumerator = (void*)return_null;
	charon->credentials->add_set(charon->credentials, &this->creds.set);

	load_certs(this);
	load_secrets(this);
	
	this->configs.backend.create_peer_cfg_enumerator = (enumerator_t*(*)(backend_t*, identification_t *me, identification_t *other))create_peer_cfg_enumerator;
	this->configs.backend.create_ike_cfg_enumerator = (enumerator_t*(*)(backend_t*, host_t *me, host_t *other))create_ike_cfg_enumerator;
	this->configs.backend.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_t*,char*))get_peer_cfg_by_name;
	charon->backends->add_backend(charon->backends, &this->configs.backend);
	
	this->job = callback_job_create((callback_job_cb_t)stroke_receive,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public.plugin;
}

