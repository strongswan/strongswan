/*
 * Copyright (C) 2008 Martin Willi
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

#include "stroke_cred.h"
#include "stroke_shared_key.h"

#include <sys/stat.h>

#include <credentials/certificates/x509.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/ac.h>
#include <utils/linked_list.h>
#include <utils/mutex.h>
#include <utils/lexparser.h>
#include <asn1/ttodata.h>
#include <asn1/pem.h>
#include <daemon.h>

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

typedef struct private_stroke_cred_t private_stroke_cred_t;

/**
 * private data of stroke_cred
 */
struct private_stroke_cred_t {

	/**
	 * public functions
	 */
	stroke_cred_t public;
	
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
	
	/**
	 * cache CRLs to disk?
	 */
	bool cachecrl;
};

/**
 * data to pass to various filters
 */
typedef struct {
	private_stroke_cred_t *this;
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
 * Implements credential_set_t.create_private_enumerator
 */
static enumerator_t* create_private_enumerator(private_stroke_cred_t *this,
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
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_cert_enumerator(private_stroke_cred_t *this,
							certificate_type_t cert, key_type_t key,
							identification_t *id, bool trusted)
{
	id_data_t *data;
	
	if (cert == CERT_X509_CRL)
	{
		if (trusted)
		{
			return NULL;
		}
		
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

typedef struct {
	private_stroke_cred_t *this;
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
						  stroke_shared_key_t **in, shared_key_t **out,
						  void **unused1, id_match_t *me,
						  void **unused2, id_match_t *other)
{
	id_match_t my_match, other_match;
	stroke_shared_key_t *stroke = *in;
	shared_key_t *shared = &stroke->shared;

	if (data->type != SHARED_ANY && shared->get_type(shared) != data->type)
	{
		return FALSE;
	}
	
	my_match = stroke->has_owner(stroke, data->me);
	other_match = stroke->has_owner(stroke, data->other);
	if (!my_match && !other_match)
	{
		return FALSE;
	}
	*out = shared;
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
 * Implements credential_set_t.create_shared_enumerator
 */
static enumerator_t* create_shared_enumerator(private_stroke_cred_t *this, 
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
 * Add a certificate to chain
 */
static certificate_t* add_cert(private_stroke_cred_t *this, certificate_t *cert)
{
	certificate_t *current;
	enumerator_t *enumerator;
	bool new = TRUE;	

	this->mutex->lock(this->mutex);
	enumerator = this->certs->create_enumerator(this->certs);
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
		this->certs->insert_last(this->certs, cert);
	}
	this->mutex->unlock(this->mutex);
	return cert;
}
	
/**
 * Implementation of stroke_cred_t.load_ca.
 */
static certificate_t* load_ca(private_stroke_cred_t *this, char *filename)
{
	certificate_t *cert;
	char path[PATH_MAX];
	
	if (*filename == '/')
	{
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/%s", CA_CERTIFICATE_DIR, filename);
	}
	
	cert = lib->creds->create(lib->creds,
							  CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, path,
							  BUILD_X509_FLAG, X509_CA,
							  BUILD_END);
	if (cert)
	{
		return (certificate_t*)add_cert(this, cert);
	}
	return NULL;
}

/**
 * Add X.509 CRL to chain
 */
static bool add_crl(private_stroke_cred_t *this, crl_t* crl)
{
	certificate_t *current, *cert = &crl->certificate;
	enumerator_t *enumerator;
	bool new = TRUE, found = FALSE;	

	this->mutex->lock(this->mutex);
	enumerator = this->certs->create_enumerator(this->certs);
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
					this->certs->remove_at(this->certs, enumerator);
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
		this->certs->insert_last(this->certs, cert);
	}
	this->mutex->unlock(this->mutex);
	return new;
}

/**
 * Implementation of stroke_cred_t.load_peer.
 */
static certificate_t* load_peer(private_stroke_cred_t *this, char *filename)
{
	certificate_t *cert;
	char path[PATH_MAX];

	if (*filename == '/')
	{
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/%s", CERTIFICATE_DIR, filename);
	}
	
	cert = lib->creds->create(lib->creds,
							  CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, path,
							  BUILD_X509_FLAG, 0,
							  BUILD_END);
	if (cert)
	{
		cert = add_cert(this, cert);
		return cert->get_ref(cert);
	}
	return NULL;
}

/**
 * load trusted certificates from a directory
 */
static void load_certdir(private_stroke_cred_t *this, char *path,
						 certificate_type_t type, x509_flag_t flag)
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
		certificate_t *cert;

		if (!S_ISREG(st.st_mode))
		{
			/* skip special file */
			continue;
		}
		switch (type)
		{
			case CERT_X509:
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509,
										  BUILD_FROM_FILE, file,
										  BUILD_X509_FLAG, flag,
										  BUILD_END);
				if (cert)
				{
					add_cert(this, cert);
				}
				break;
			case CERT_X509_CRL:
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509_CRL,
										  BUILD_FROM_FILE, file,
										  BUILD_END);
				if (cert)
				{
					add_crl(this, (crl_t*)cert);
				}
				break;
			case CERT_X509_AC:
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509_AC,
										  BUILD_FROM_FILE, file,
										  BUILD_END);
				if (cert)
				{
					cert->destroy(cert);
				}
				break;
			default:
				break;	
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of credential_set_t.cache_cert.
 */
static void cache_cert(private_stroke_cred_t *this, certificate_t *cert)
{
	if (cert->get_type(cert) == CERT_X509_CRL && this->cachecrl)
	{
		/* CRLs get cached to /etc/ipsec.d/crls/authkeyId.der */
		crl_t *crl = (crl_t*)cert;
	
		cert->get_ref(cert);
		if (add_crl(this, crl))
		{
			char buf[256];
			char *hex;
			chunk_t chunk;
			identification_t *id;
			
			id = crl->get_authKeyIdentifier(crl);
			chunk = id->get_encoding(id);
			hex = chunk_to_hex(chunk, FALSE);
			snprintf(buf, sizeof(buf), "%s/%s.der", CRL_DIR, hex);
			free(hex);
			
			chunk = cert->get_encoding(cert);
			if (chunk_write(chunk, buf, 022, TRUE))
			{
				DBG1(DBG_CFG, "cached crl to %s", buf);
			}
			else
			{
				DBG1(DBG_CFG, "caching  crl to %s failed", buf);
			}
			free(chunk.ptr);
		}
	}
}

/**
 * Implementation of stroke_cred_t.cachecrl.
 */
static void cachecrl(private_stroke_cred_t *this, bool enabled)
{
	DBG1(DBG_CFG, "crl caching to %s %s",
		 CRL_DIR, enabled ? "enabled" : "disabled");
	this->cachecrl = enabled;
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
			chunk_clear(secret);
			return ugh;
		}
		secret->len = len;
	}
	return NULL;
}

/**
 * reload ipsec.secrets
 */
static void load_secrets(private_stroke_cred_t *this)
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

	this->mutex->lock(this->mutex);
	while (this->shared->remove_last(this->shared,
		 								   (void**)&shared) == SUCCESS)
	{
		shared->destroy(shared);
	}
	while (this->private->remove_last(this->private,
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
		if (!extract_last_token(&ids, ':', &line))
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
					this->private->insert_last(this->private, key);
				}
			}
			chunk_clear(&secret);
		}
		else if ((match("PSK", &token) && (type = SHARED_IKE)) ||
				 (match("EAP", &token) && (type = SHARED_EAP)) ||
				 (match("XAUTH", &token) && (type = SHARED_EAP)) ||
				 (match("PIN", &token) && (type = SHARED_PIN)))
		{
			stroke_shared_key_t *shared_key;
			chunk_t secret = chunk_empty;
			bool any = TRUE;

			err_t ugh = extract_secret(&secret, &line);
			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: malformed secret: %s", line_nr, ugh);
				goto error;
			}
			shared_key = stroke_shared_key_create(type, secret);
			DBG1(DBG_CFG, "  loaded %N secret for %s", shared_key_type_names, type,
				 ids.len > 0 ? (char*)ids.ptr : "%any");
			DBG4(DBG_CFG, "  secret: %#B", &secret);
			
			this->shared->insert_last(this->shared, shared_key);
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
				
				shared_key->add_owner(shared_key, peer_id);
				any = FALSE;
			}
			if (any)
			{
				shared_key->add_owner(shared_key,
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
	this->mutex->unlock(this->mutex);
	chunk_clear(&chunk);
}

/**
 * load all certificates from ipsec.d
 */
static void load_certs(private_stroke_cred_t *this)
{
	DBG1(DBG_CFG, "loading ca certificates from '%s'",
		 CA_CERTIFICATE_DIR);
	load_certdir(this, CA_CERTIFICATE_DIR, CERT_X509, X509_CA);

	DBG1(DBG_CFG, "loading aa certificates from '%s'",
		 AA_CERTIFICATE_DIR);
	load_certdir(this, AA_CERTIFICATE_DIR, CERT_X509, X509_AA);

	DBG1(DBG_CFG, "loading ocsp signer certificates from '%s'",
		 OCSP_CERTIFICATE_DIR);
	load_certdir(this, OCSP_CERTIFICATE_DIR, CERT_X509, X509_OCSP_SIGNER);

	DBG1(DBG_CFG, "loading attribute certificates from '%s'",
		 ATTR_CERTIFICATE_DIR);
	load_certdir(this, ATTR_CERTIFICATE_DIR, CERT_X509_AC, 0);

	DBG1(DBG_CFG, "loading crls from '%s'",
		 CRL_DIR);
	load_certdir(this, CRL_DIR, CERT_X509_CRL, 0);
}

/**
 * Implementation of stroke_cred_t.reread.
 */
static void reread(private_stroke_cred_t *this, stroke_msg_t *msg)
{
	if (msg->reread.flags & REREAD_SECRETS)
	{
		DBG1(DBG_CFG, "rereading secrets");
		load_secrets(this);
	}
	if (msg->reread.flags & REREAD_CACERTS)
	{
		DBG1(DBG_CFG, "rereading ca certificates from '%s'",
			 CA_CERTIFICATE_DIR);
		load_certdir(this, CA_CERTIFICATE_DIR, CERT_X509, X509_CA);
	}
	if (msg->reread.flags & REREAD_OCSPCERTS)
	{
		DBG1(DBG_CFG, "rereading ocsp signer certificates from '%s'",
			 OCSP_CERTIFICATE_DIR);
		load_certdir(this, OCSP_CERTIFICATE_DIR, CERT_X509,
			 X509_OCSP_SIGNER);
	}
	if (msg->reread.flags & REREAD_AACERTS)
	{
		DBG1(DBG_CFG, "rereading aa certificates from '%s'",
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
		DBG1(DBG_CFG, "rereading crls from '%s'",
			 CRL_DIR);
		load_certdir(this, CRL_DIR, CERT_X509_CRL, 0);
	}
}

/**
 * Implementation of stroke_cred_t.destroy
 */
static void destroy(private_stroke_cred_t *this)
{
	this->certs->destroy_offset(this->certs, offsetof(certificate_t, destroy));
	this->shared->destroy_offset(this->shared, offsetof(shared_key_t, destroy));
	this->private->destroy_offset(this->private, offsetof(private_key_t, destroy));
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
stroke_cred_t *stroke_cred_create()
{
	private_stroke_cred_t *this = malloc_thing(private_stroke_cred_t);
	
	this->public.set.create_private_enumerator = (void*)create_private_enumerator;
	this->public.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->public.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.set.cache_cert = (void*)cache_cert;
	this->public.reread = (void(*)(stroke_cred_t*, stroke_msg_t *msg))reread;
	this->public.load_ca = (certificate_t*(*)(stroke_cred_t*, char *filename))load_ca;
	this->public.load_peer = (certificate_t*(*)(stroke_cred_t*, char *filename))load_peer;
	this->public.cachecrl = (void(*)(stroke_cred_t*, bool enabled))cachecrl;
	this->public.destroy = (void(*)(stroke_cred_t*))destroy;
	
	this->certs = linked_list_create();
	this->shared = linked_list_create();
	this->private = linked_list_create();
	this->mutex = mutex_create(MUTEX_RECURSIVE);

	load_certs(this);
	load_secrets(this);
	
	this->cachecrl = FALSE;
	
	return &this->public;
}

