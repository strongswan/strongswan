/**
 * @file local_credential_store.c
 * 
 * @brief Implementation of local_credential_store_t.
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

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <pthread.h>

#include <types.h>
#include <utils/lexparser.h>
#include <utils/linked_list.h>
#include <crypto/certinfo.h>
#include <crypto/rsa/rsa_public_key.h>
#include <crypto/x509.h>
#include <crypto/crl.h>
#include <asn1/ttodata.h>

#include "local_credential_store.h"

#define PATH_BUF			256
#define MAX_CA_PATH_LEN		7

typedef struct shared_key_t shared_key_t;

/**
 * Private date of a shared_key_t object
 */
struct shared_key_t {

	/**
	 * shared secret
	 */
	chunk_t secret;

	/**
	 * list of peer IDs
	 */
	linked_list_t *peers;
};


/**
 * Implementation of shared_key_t.destroy.
 */
static void shared_key_destroy(shared_key_t *this)
{
	this->peers->destroy_offset(this->peers, offsetof(identification_t, destroy));
	chunk_free(&this->secret);
	free(this);
}

/**
 * @brief Creates a shared_key_t object.
 * 
 * @param shared_key		shared key value
 * @return					shared_key_t object
 * 
 * @ingroup config
 */
static shared_key_t *shared_key_create(chunk_t secret)
{
	shared_key_t *this = malloc_thing(shared_key_t);

	/* private data */
	this->secret = chunk_clone(secret);
	this->peers = linked_list_create();

	return (this);
}


typedef struct private_local_credential_store_t private_local_credential_store_t;

/**
 * Private data of an local_credential_store_t object
 */
struct private_local_credential_store_t {

	/**
	 * Public part
	 */
	local_credential_store_t public;
	
	/**
	 * list of shared keys
	 */
	linked_list_t *shared_keys;
	
	/**
	 * list of key_entry_t's with private keys
	 */
	linked_list_t *private_keys;
	
	/**
	 * list of X.509 certificates with public keys
	 */
	linked_list_t *certs;

	/**
	 * list of X.509 CA certificates with public keys
	 */
	linked_list_t *ca_certs;

	/**
	 * list of X.509 CRLs
	 */
	linked_list_t *crls;

	/**
	 * mutex controlling the access to the crls linked list
	 */
	pthread_mutex_t crls_mutex;

	/**
	 * enforce strict crl policy
	 */
	bool strict;
};


/**
 * Implementation of local_credential_store_t.get_shared_key.
 */	
static status_t get_shared_key(private_local_credential_store_t *this,
							   identification_t *my_id,
							   identification_t *other_id, chunk_t *secret)
{
	typedef enum {
		PRIO_UNDEFINED=		0x00,
		PRIO_ANY_MATCH= 	0x01,
		PRIO_MY_MATCH= 		0x02,
		PRIO_OTHER_MATCH=	0x04,
	} prio_t;

	prio_t best_prio = PRIO_UNDEFINED;
	chunk_t found = CHUNK_INITIALIZER;
	shared_key_t *shared_key;

	iterator_t *iterator = this->shared_keys->create_iterator(this->shared_keys, TRUE);

	while (iterator->iterate(iterator, (void**)&shared_key))
	{
		iterator_t *peer_iterator;
		identification_t *peer_id;
		prio_t prio = PRIO_UNDEFINED;

		peer_iterator = shared_key->peers->create_iterator(shared_key->peers, TRUE);

		if (peer_iterator->get_count(peer_iterator) == 0)
		{
			/* this is a wildcard shared key */
			prio = PRIO_ANY_MATCH;
		}
		else
		{
			while (peer_iterator->iterate(peer_iterator, (void**)&peer_id))
			{
				if (my_id->equals(my_id, peer_id))
				{
					prio |= PRIO_MY_MATCH; 
				}
				if (other_id->equals(other_id, peer_id))
				{
					prio |= PRIO_OTHER_MATCH; 
				}
			}
		}
		peer_iterator->destroy(peer_iterator);

		if (prio > best_prio)
		{
			best_prio = prio;
			found = shared_key->secret;
		}
	}
	iterator->destroy(iterator);

	if (best_prio == PRIO_UNDEFINED)
	{
		return NOT_FOUND;
	}
	else
	{
		*secret = chunk_clone(found);
		return SUCCESS;
	}
}

/**
 * Implementation of credential_store_t.get_certificate.
 */
static x509_t* get_certificate(private_local_credential_store_t *this,
							   identification_t *id)
{
	x509_t *found = NULL;
	x509_t *current_cert;

	iterator_t *iterator = this->certs->create_iterator(this->certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		if (id->equals(id, current_cert->get_subject(current_cert)) ||
			current_cert->equals_subjectAltName(current_cert, id))
		{
			found = current_cert;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of local_credential_store_t.get_rsa_public_key.
 */
static rsa_public_key_t *get_rsa_public_key(private_local_credential_store_t *this,
											identification_t *id)
{
	x509_t *cert = get_certificate(this, id);

	return (cert == NULL)? NULL:cert->get_public_key(cert);
}

/**
 * Implementation of local_credential_store_t.get_trusted_public_key.
 */
static rsa_public_key_t *get_trusted_public_key(private_local_credential_store_t *this,
												identification_t *id)
{
	cert_status_t status;
	err_t ugh;

	x509_t *cert = get_certificate(this, id);

	if (cert == NULL)
		return NULL;

	ugh = cert->is_valid(cert, NULL);
	if (ugh != NULL)
	{
		DBG1(DBG_CFG, "certificate %s", ugh);
		return NULL;
	}

	status = cert->get_status(cert);
	if (status == CERT_REVOKED || status == CERT_UNTRUSTED || (this->strict && status != CERT_GOOD))
	{
		DBG1(DBG_CFG, "certificate status: %N", cert_status_names, status);
		return NULL;
	}
	if (status == CERT_GOOD && cert->get_until(cert) < time(NULL))
	{
		DBG1(DBG_CFG, "certificate is good but crl is stale");
		return NULL;
	}

	return cert->get_public_key(cert);
}

/**
 * Implementation of local_credential_store_t.get_rsa_private_key.
 */
static rsa_private_key_t *get_rsa_private_key(private_local_credential_store_t *this,
											  rsa_public_key_t *pubkey)
{
	rsa_private_key_t *found = NULL, *current;

	iterator_t *iterator = this->private_keys->create_iterator(this->private_keys, TRUE);

	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->belongs_to(current, pubkey))
		{
			found = current->clone(current);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of local_credential_store_t.has_rsa_private_key.
 */
static bool has_rsa_private_key(private_local_credential_store_t *this, rsa_public_key_t *pubkey)
{
	bool found = FALSE;
	rsa_private_key_t *current;

	iterator_t *iterator = this->private_keys->create_iterator(this->private_keys, TRUE);

	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->belongs_to(current, pubkey))
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of credential_store_t.get_ca_certificate.
 */
static x509_t* get_ca_certificate(private_local_credential_store_t *this,
								  identification_t *id)
{
	x509_t *found = NULL;
	x509_t *current_cert;

	iterator_t *iterator = this->ca_certs->create_iterator(this->ca_certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		if (id->equals(id, current_cert->get_subject(current_cert)))
		{
			found = current_cert;
			break;
		}
	}
	iterator->destroy(iterator);

	return found;
}

/**
 * Implementation of credential_store_t.get_ca_certificate_by_keyid.
 */
static x509_t* get_ca_certificate_by_keyid(private_local_credential_store_t *this,
										   chunk_t keyid)
{
	x509_t *found = NULL;
	x509_t *current_cert;

	iterator_t *iterator = this->ca_certs->create_iterator(this->ca_certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		rsa_public_key_t *pubkey = current_cert->get_public_key(current_cert);

		if (chunk_equals(keyid, pubkey->get_keyid(pubkey)))
		{
			found = current_cert;
			break;
		}
	}
	iterator->destroy(iterator);

	return found;
}

/**
 * Implementation of credential_store_t.get_issuer_certificate.
 */
static x509_t* get_issuer_certificate(private_local_credential_store_t *this,
									  const x509_t *cert)
{
	x509_t *found = NULL;
	x509_t *current_cert;

	iterator_t *iterator = this->ca_certs->create_iterator(this->ca_certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		if (cert->is_issuer(cert, current_cert))
		{
			found = current_cert;
			break;
		}
	}
	iterator->destroy(iterator);

	return found;
}

/**
 * Implementation of credential_store_t.get_crl.
 */
static crl_t* get_crl(private_local_credential_store_t *this, const x509_t *issuer)
{
	crl_t *crl = NULL, *current_crl;

	iterator_t *iterator = this->crls->create_iterator(this->crls, TRUE);

	while (iterator->iterate(iterator, (void**)&current_crl))
	{
		if (current_crl->is_issuer(current_crl, issuer))
		{
			crl = current_crl;
			break;
		}
	}
	iterator->destroy(iterator);

	return crl;
}

/**
 *  Verify the certificate status using CRLs
 */
static cert_status_t verify_by_crl(private_local_credential_store_t* this, const x509_t *cert,
	const x509_t *issuer_cert, certinfo_t *certinfo)
{
	crl_t *crl;
	bool valid_signature;
	rsa_public_key_t *issuer_public_key;


	pthread_mutex_lock(&(this->crls_mutex));

	crl = get_crl(this, issuer_cert);
	if (crl == NULL)
	{
		DBG1(DBG_CFG, "crl not found");
		goto err;
	}
	DBG2(DBG_CFG, "crl found");
	
	issuer_public_key = issuer_cert->get_public_key(issuer_cert);
	valid_signature = crl->verify(crl, issuer_public_key);

	if (!valid_signature)
	{
		DBG1(DBG_CFG, "crl signature is invalid");
		goto err;
	}
	DBG2(DBG_CFG, "crl signature is valid");

	crl->get_status(crl, certinfo);

err:
	pthread_mutex_unlock(&(this->crls_mutex));
	return certinfo->get_status(certinfo);
}

/**
  * Verify the certificate status using OCSP
  */
static cert_status_t verify_by_ocsp(private_local_credential_store_t* this,
	 		const x509_t *cert, certinfo_t *certinfo)
{
	/* TODO implement function */
	return CERT_UNDEFINED;
}

/**
 * Find an exact copy of a certificate in a linked list
 */
static x509_t* find_certificate_copy(linked_list_t *certs, x509_t *cert)
{
	x509_t *found_cert = NULL, *current_cert;

	iterator_t *iterator = certs->create_iterator(certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		if (cert->equals(cert, current_cert))
		{
			found_cert = current_cert;
			break;
		}
	}
	iterator->destroy(iterator);

	return found_cert;
}

/**
 * Implementation of credential_store_t.verify.
 */
static bool verify(private_local_credential_store_t *this, x509_t *cert, bool *found)
{
	int pathlen;
	time_t until = UNDEFINED_TIME;

	x509_t *end_cert = cert;
	x509_t *cert_copy = find_certificate_copy(this->certs, end_cert);
	
	*found = (cert_copy != NULL);
	if (*found)
	{
		DBG2(DBG_CFG,
			 "end entitity certificate is already in credential store");
	}

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
	{
		err_t ugh = NULL;
		x509_t *issuer_cert;
		rsa_public_key_t *issuer_public_key;
		bool valid_signature;

		identification_t *subject = cert->get_subject(cert);
		identification_t *issuer  = cert->get_issuer(cert);

		DBG2(DBG_CFG, "subject: '%D'", subject);
		DBG2(DBG_CFG, "issuer:  '%D'", issuer);

		ugh = cert->is_valid(cert, &until);
		if (ugh != NULL)
		{
			DBG1(DBG_CFG, "certificate %s", ugh);
			return FALSE;
		}
		DBG2(DBG_CFG, "certificate is valid");

		issuer_cert = get_issuer_certificate(this, cert);
		if (issuer_cert == NULL)
		{
			DBG1(DBG_CFG, "issuer certificate not found");
			return FALSE;
		}
		DBG2(DBG_CFG, "issuer certificate found");

		issuer_public_key = issuer_cert->get_public_key(issuer_cert);
		valid_signature = cert->verify(cert, issuer_public_key);

		if (!valid_signature)
		{
			DBG1(DBG_CFG, "certificate signature is invalid");
			return FALSE;
		}
		DBG2(DBG_CFG, "certificate signature is valid");

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && cert->is_self_signed(cert))
		{
			DBG2(DBG_CFG, "reached self-signed root ca");

			/* set the definite status and trust interval of the end entity certificate */
			end_cert->set_until(end_cert, until);
			if (cert_copy)
			{
				cert_copy->set_status(cert_copy, end_cert->get_status(end_cert));
				cert_copy->set_until(cert_copy, until);
			}
			return TRUE;
		}
		else
		{
			time_t nextUpdate;
			cert_status_t status;
			certinfo_t *certinfo = certinfo_create(cert->get_serialNumber(cert));

			certinfo->set_nextUpdate(certinfo, until);

			/* first check certificate revocation using ocsp */
			status = verify_by_ocsp(this, cert, certinfo);

			/* if ocsp service is not available then fall back to crl */
			if ((status == CERT_UNDEFINED) || (status == CERT_UNKNOWN && this->strict))
			{
				status = verify_by_crl(this, cert, issuer_cert, certinfo);
			}
			
			nextUpdate = certinfo->get_nextUpdate(certinfo);
			cert->set_status(cert, status);

			switch (status)
			{
				case CERT_GOOD:
					/* set nextUpdate */
					cert->set_until(cert, nextUpdate);

					/* if status information is stale */
					if (this->strict && nextUpdate < time(NULL))
					{
						DBG2(DBG_CFG, "certificate is good but status is stale");
						return FALSE;
					}
					DBG2(DBG_CFG, "certificate is good");

					/* with strict crl policy the public key must have the same
					 * lifetime as the validity of the ocsp status or crl lifetime
					 */
					if (this->strict && nextUpdate < until)
		    			until = nextUpdate;
					break;
				case CERT_REVOKED:
					{
						time_t revocationTime = certinfo->get_revocationTime(certinfo);
						DBG1(DBG_CFG,
							 "certificate was revoked on %T, reason: %N",
							 revocationTime, crl_reason_names,
							 certinfo->get_revocationReason(certinfo));

						/* set revocationTime */
						cert->set_until(cert, revocationTime);

						/* update status of end certificate in the credential store */
						if (cert_copy)
						{
							if (pathlen > 0)
							{
								cert_copy->set_status(cert_copy, CERT_UNTRUSTED);
							}
							else
							{
								cert_copy->set_status(cert_copy, CERT_REVOKED);
								cert_copy->set_until(cert_copy,
										certinfo->get_revocationTime(certinfo));
							}
						}
						return FALSE;
					}
				case CERT_UNKNOWN:
				case CERT_UNDEFINED:
				default:
					DBG2(DBG_CFG, "certificate status unknown");
					if (this->strict)
					{
						/* update status of end certificate in the credential store */
						if (cert_copy)
						{
							cert_copy->set_status(cert_copy, CERT_UNTRUSTED);
						}
						return FALSE;
					}
					break;
			}
			certinfo->destroy(certinfo);
		}
		/* go up one step in the trust chain */
		cert = issuer_cert;
	}
	DBG1(DBG_CFG, "maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
	return FALSE;
}

/**
 * Add a unique certificate to a linked list
 */
static x509_t* add_certificate(linked_list_t *certs, x509_t *cert)
{
	x509_t *found_cert = find_certificate_copy(certs, cert);

	if (found_cert)
	{
		cert->destroy(cert);
		return found_cert;
	}
	else
	{
		certs->insert_last(certs, (void*)cert);
		return cert;
	}
}

/**
 * Implements local_credential_store_t.add_end_certificate
 */
static x509_t* add_end_certificate(private_local_credential_store_t *this, x509_t *cert)
{
	return add_certificate(this->certs, cert);
}

/**
 * Implements local_credential_store_t.add_ca_certificate
 */
static x509_t* add_ca_certificate(private_local_credential_store_t *this, x509_t *cert)
{
	return add_certificate(this->ca_certs, cert);
}

/**
 * Implements local_credential_store_t.create_cert_iterator
 */
static iterator_t* create_cert_iterator(private_local_credential_store_t *this)
{
	return this->certs->create_iterator(this->certs, TRUE);
}

/**
 * Implements local_credential_store_t.create_cacert_iterator
 */
static iterator_t* create_cacert_iterator(private_local_credential_store_t *this)
{
	return this->ca_certs->create_iterator(this->ca_certs, TRUE);
}

/**
 * Implements local_credential_store_t.create_crl_iterator
 */
static iterator_t* create_crl_iterator(private_local_credential_store_t *this)
{
	return this->crls->create_iterator_locked(this->crls, &(this->crls_mutex));
}

/**
 * Implements local_credential_store_t.load_ca_certificates
 */
static void load_ca_certificates(private_local_credential_store_t *this)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	x509_t *cert;
	
	DBG1(DBG_CFG, "loading ca certificates from '%s/'", CA_CERTIFICATE_DIR);

	dir = opendir(CA_CERTIFICATE_DIR);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening ca certs directory %s'", CA_CERTIFICATE_DIR);
		return;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		char file[PATH_BUF];

		snprintf(file, sizeof(file), "%s/%s", CA_CERTIFICATE_DIR, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			cert = x509_create_from_file(file, "ca certificate");
			if (cert)
			{
				err_t ugh = cert->is_valid(cert, NULL);

				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "warning: ca certificate %s", ugh);
				}
				if (cert->is_ca(cert))
				{
					cert = add_certificate(this->ca_certs, cert);
				}
				else
				{
					DBG1(DBG_CFG, "  CA basic constraints flag not set, cert discarded");
					cert->destroy(cert);
				}
			}
		}
	}
	closedir(dir);
}

/**
 * Add the latest crl to a linked list
 */
static crl_t* add_crl(linked_list_t *crls, crl_t *crl)
{
	bool found = FALSE;
	crl_t *current_crl;

	iterator_t *iterator = crls->create_iterator(crls, TRUE);

	while (iterator->iterate(iterator, (void**)&current_crl))
	{
		if (crl->equals_issuer(crl, current_crl))
		{
			found = TRUE;
			if (crl->is_newer(crl, current_crl))
			{
				crl_t *old_crl = NULL;
				
				iterator->replace(iterator, (void**)&old_crl, (void*)crl);
				if (old_crl != NULL)
				{
					old_crl->destroy(old_crl);
				}
				DBG2(DBG_CFG, "  thisUpdate is newer - existing crl replaced");
			}
			else
			{
				crl->destroy(crl);
				crl = current_crl;
				DBG2(DBG_CFG, "  thisUpdate is not newer - existing crl retained");
			}
			break;
		}
	}
	iterator->destroy(iterator);

	if (!found)
	{
		crls->insert_last(crls, (void*)crl);
		DBG2(DBG_CFG, "  crl added");
	}
	return crl;
}

/**
 * Implements local_credential_store_t.load_crls
 */
static void load_crls(private_local_credential_store_t *this)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	crl_t *crl;
	
	DBG1(DBG_CFG, "loading crls from '%s/'", CRL_DIR);

	dir = opendir(CRL_DIR);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening crl directory %s'", CRL_DIR);
		return;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		char file[PATH_BUF];

		snprintf(file, sizeof(file), "%s/%s", CRL_DIR, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			crl = crl_create_from_file(file);
			if (crl)
			{
				err_t ugh = crl->is_valid(crl, NULL, this->strict);

				if (ugh != NULL)	
				{
					DBG1(DBG_CFG, "warning: crl %s", ugh);
				}
				pthread_mutex_lock(&(this->crls_mutex));
				crl = add_crl(this->crls, crl);
				pthread_mutex_unlock(&(this->crls_mutex));
			}
		}
	}
	closedir(dir);
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
	{	/* treat as an ASCII string */
		if (raw_secret.len > secret->len)
			return "secret larger than buffer";
		memcpy(secret->ptr, raw_secret.ptr, raw_secret.len);
		secret->len = raw_secret.len;
	}
	else
	{	/* convert from HEX or Base64 to binary */
		size_t len;
		err_t ugh = ttodata(raw_secret.ptr, raw_secret.len, 0, secret->ptr, secret->len, &len);

	    if (ugh != NULL)
			return ugh;
		if (len > secret->len)
			return "secret larger than buffer";
		secret->len = len;
	}
	return NULL;
}

/**
 * Implements local_credential_store_t.load_secrets
 */
static void load_secrets(private_local_credential_store_t *this)
{
	FILE *fd = fopen(SECRETS_FILE, "r");

	if (fd)
	{
		int bytes;
		int line_nr = 0;
    	chunk_t chunk, src, line;

		DBG1(DBG_CFG, "loading secrets from \"%s\"", SECRETS_FILE);

		fseek(fd, 0, SEEK_END);
		chunk.len = ftell(fd);
		rewind(fd);
		chunk.ptr = malloc(chunk.len);
		bytes = fread(chunk.ptr, 1, chunk.len, fd);
		fclose(fd);

		src = chunk;

		while (fetchline(&src, &line))
		{
			chunk_t ids, token;

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
				char path[PATH_BUF];
				chunk_t filename;

				char buf[BUF_LEN];
				chunk_t secret = { buf, BUF_LEN };
				chunk_t *passphrase = NULL;

				rsa_private_key_t *key;

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
					if (secret.len > 0)
						passphrase = &secret;
				}
				key = rsa_private_key_create_from_file(path, passphrase);
				if (key)
				{
					this->private_keys->insert_last(this->private_keys, (void*)key);
				}
			}
			else if (match("PSK", &token))
			{
				shared_key_t *shared_key;

				char buf[BUF_LEN];
				chunk_t secret = { buf, BUF_LEN };

				err_t ugh = extract_secret(&secret, &line);
				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "line %d: malformed secret: %s", line_nr, ugh);
					goto error;
				}

				if (ids.len > 0)
				{
					DBG1(DBG_CFG, "  loading shared key for %s", ids.ptr);
				}
				else
				{
					DBG1(DBG_CFG, "  loading shared key for %%any");
				}

				DBG4(DBG_CFG, "  secret:", secret);

				shared_key = shared_key_create(secret);
				if (shared_key)
				{
					this->shared_keys->insert_last(this->shared_keys, (void*)shared_key);
				}
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
					shared_key->peers->insert_last(shared_key->peers, (void*)peer_id);
				}
			}
			else if (match("PIN", &token))
			{

			}
			else
			{
				DBG1(DBG_CFG, "line %d: token must be either "
					 "RSA, PSK, or PIN", line_nr, token.len);
				goto error;
			}
		}
error:
		free(chunk.ptr);
	}
	else
	{
		DBG1(DBG_CFG, "could not open file '%s'", SECRETS_FILE);
	}
}

/**
 * Implementation of local_credential_store_t.destroy.
 */
static void destroy(private_local_credential_store_t *this)
{
	this->certs->destroy_offset(this->certs, offsetof(x509_t, destroy));
	this->ca_certs->destroy_offset(this->ca_certs, offsetof(x509_t, destroy));
	this->crls->destroy_offset(this->crls, offsetof(crl_t, destroy));
	this->private_keys->destroy_offset(this->private_keys, offsetof(rsa_private_key_t, destroy));
	this->shared_keys->destroy_function(this->shared_keys, (void*)shared_key_destroy);
	free(this);
}

/**
 * Described in header.
 */
local_credential_store_t * local_credential_store_create(bool strict)
{
	private_local_credential_store_t *this = malloc_thing(private_local_credential_store_t);
	
	this->public.credential_store.get_shared_key = (status_t (*) (credential_store_t*,identification_t*,identification_t*,chunk_t*))get_shared_key;
	this->public.credential_store.get_rsa_public_key = (rsa_public_key_t*(*)(credential_store_t*,identification_t*))get_rsa_public_key;
	this->public.credential_store.get_rsa_private_key = (rsa_private_key_t* (*) (credential_store_t*,rsa_public_key_t*))get_rsa_private_key;
	this->public.credential_store.has_rsa_private_key = (bool (*) (credential_store_t*,rsa_public_key_t*))has_rsa_private_key;
	this->public.credential_store.get_trusted_public_key = (rsa_public_key_t*(*)(credential_store_t*,identification_t*))get_trusted_public_key;
	this->public.credential_store.get_certificate = (x509_t* (*) (credential_store_t*,identification_t*))get_certificate;
	this->public.credential_store.get_ca_certificate = (x509_t* (*) (credential_store_t*,identification_t*))get_ca_certificate;
	this->public.credential_store.get_ca_certificate_by_keyid = (x509_t* (*) (credential_store_t*,chunk_t))get_ca_certificate_by_keyid;
	this->public.credential_store.get_issuer_certificate = (x509_t* (*) (credential_store_t*,const x509_t*))get_issuer_certificate;
	this->public.credential_store.verify = (bool (*) (credential_store_t*,x509_t*,bool*))verify;
	this->public.credential_store.add_end_certificate = (x509_t* (*) (credential_store_t*,x509_t*))add_end_certificate;
	this->public.credential_store.add_ca_certificate = (x509_t* (*) (credential_store_t*,x509_t*))add_ca_certificate;
	this->public.credential_store.create_cert_iterator = (iterator_t* (*) (credential_store_t*))create_cert_iterator;
	this->public.credential_store.create_cacert_iterator = (iterator_t* (*) (credential_store_t*))create_cacert_iterator;
	this->public.credential_store.create_crl_iterator = (iterator_t* (*) (credential_store_t*))create_crl_iterator;
	this->public.credential_store.load_ca_certificates = (void (*) (credential_store_t*))load_ca_certificates;
	this->public.credential_store.load_crls = (void (*) (credential_store_t*))load_crls;
	this->public.credential_store.load_secrets = (void (*) (credential_store_t*))load_secrets;
	this->public.credential_store.destroy = (void (*) (credential_store_t*))destroy;
	
	/* initialize mutexes */
	pthread_mutex_init(&(this->crls_mutex), NULL);

	/* private variables */
	this->shared_keys = linked_list_create();
	this->private_keys = linked_list_create();
	this->certs = linked_list_create();
	this->ca_certs = linked_list_create();
	this->crls = linked_list_create();
	this->strict = strict;

	return (&this->public);
}
