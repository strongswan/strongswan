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

#include <library.h>
#include <utils/lexparser.h>
#include <utils/linked_list.h>
#include <crypto/rsa/rsa_public_key.h>
#include <crypto/certinfo.h>
#include <crypto/x509.h>
#include <crypto/ca.h>
#include <crypto/ac.h>
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

/* ------------------------------------------------------------------------ *
 * the ca_info_t object as a central control element

+--------------------------------------------------------+
| local_credential_store_t                               |
+--------------------------------------------------------+
  |                              |
+---------------------------+  +-------------------------+
| linked_list_t *auth_certs |  | linked_list_t *ca_infos |
+---------------------------+  +-------------------------+
  |                              |
  |                 +------------------------- +
  |                 | ca_info_t                |
  |                 +--------------------------+
+---------------+   | char *name               |
| x509_t        |<--| x509_t *cacert           |
+---------------+   | linked_list_t *attrcerts |   +----------------------+
| chunk_t keyid |   | linked_list_t *certinfos |-->| certinfo_t           |
+---------------+   | linked_list_t *ocspuris  |   +----------------------+
  |                 | crl_t *crl               |   | chunk_t serialNumber |
  |                 | linked_list_t *crluris   |   | cert_status_t status |
+---------------+   | pthread_mutex_t mutex    |   | time_t thisUpdate    |
| x509_t        |   +--------------------------+   | time_t nextUpdate    |
+---------------+                |                 | bool once            |
| chunk_t keyid |                |                 +----------------------+
+---------------+   +------------------------- +     |
  |                 | ca_info_t                |   +----------------------+
  |                 +--------------------------+   | certinfo_t           |
+---------------+   | char *name               |   +----------------------+
| x509_t        |<--| x509_t *cacert           |   | chunk_t serialNumber |
+---------------+   | linked_list_t *attrcerts |   | cert_status_t status |
| chunk_t keyid |   | linked_list_t *certinfos |   | time_t thisUpdate    |
+---------------+   | linked_list_t *ocspuris  |   | time_t nextUpdate    |
  |                 | crl_t *crl               |   | bool once            |
  |                 | linked_list_t *crluris   |   +----------------------+
  |                 | pthread_mutex_t mutex;   |     |
  |                 +--------------------------+
  |                              |

 * ------------------------------------------------------------------------ */

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
	 * list of EAP keys
	 */
	linked_list_t *eap_keys;
	
	/**
	 * list of key_entry_t's with private keys
	 */
	linked_list_t *private_keys;
	
	/**
	 * list of X.509 certificates with public keys
	 */
	linked_list_t *certs;

	/**
	 * list of X.509 authority certificates with public keys
	 */
	linked_list_t *auth_certs;

	/**
	 * list of X.509 CA information records
	 */
	linked_list_t *ca_infos;

	/**
	 * enforce strict crl policy
	 */
	bool strict;
};


/**
 * Get a key from a list with shared_key_t's
 */	
static status_t get_key(linked_list_t *keys,
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
	chunk_t found = chunk_empty;
	shared_key_t *shared_key;

	iterator_t *iterator = keys->create_iterator(keys, TRUE);

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
 * Implementation of local_credential_store_t.get_shared_key.
 */	
static status_t get_shared_key(private_local_credential_store_t *this,
							   identification_t *my_id,
							   identification_t *other_id, chunk_t *secret)
{
	return get_key(this->shared_keys, my_id, other_id, secret);
}

/**
 * Implementation of local_credential_store_t.get_eap_key.
 */	
static status_t get_eap_key(private_local_credential_store_t *this,
							identification_t *my_id,
							identification_t *other_id, chunk_t *secret)
{
	return get_key(this->eap_keys, my_id, other_id, secret);
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
 * Implementation of credential_store_t.get_auth_certificate.
 */
static x509_t* get_auth_certificate(private_local_credential_store_t *this,
									u_int auth_flags,
									identification_t *id)
{
	x509_t *found = NULL;
	x509_t *current_cert;

	iterator_t *iterator = this->auth_certs->create_iterator(this->auth_certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		if (current_cert->has_authority_flag(current_cert, auth_flags)
		&&  id->equals(id, current_cert->get_subject(current_cert)))
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

	iterator_t *iterator = this->auth_certs->create_iterator(this->auth_certs, TRUE);

	while (iterator->iterate(iterator, (void**)&current_cert))
	{
		rsa_public_key_t *pubkey = current_cert->get_public_key(current_cert);

		if (current_cert->has_authority_flag(current_cert, AUTH_CA)
		&&  chunk_equals(keyid, pubkey->get_keyid(pubkey)))
		{
			found = current_cert;
			break;
		}
	}
	iterator->destroy(iterator);

	return found;
}

/**
 * Implementation of credential_store_t.get_issuer.
 */
static ca_info_t* get_issuer(private_local_credential_store_t *this, const x509_t *cert)
{
	ca_info_t *found = NULL;
	ca_info_t *ca_info;

	iterator_t *iterator = this->ca_infos->create_iterator(this->ca_infos, TRUE);

	while (iterator->iterate(iterator, (void**)&ca_info))
	{
		if (ca_info->is_cert_issuer(ca_info, cert))
		{
			found = ca_info;
			break;
		}
	}
	iterator->destroy(iterator);

	return found;
}

/**
 * Find an exact copy of a certificate in a linked list
 */
static x509_t* find_certificate(linked_list_t *certs, x509_t *cert)
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
 * Adds crl and ocsp uris to the corresponding issuer info record
 */
static void add_uris(ca_info_t *issuer, x509_t *cert)
{
	iterator_t *iterator;
	identification_t *uri;

	/* add any crl distribution points to the issuer ca info record */
	iterator = cert->create_crluri_iterator(cert);
	
	while (iterator->iterate(iterator, (void**)&uri))
	{
		issuer->add_crluri(issuer, uri->get_encoding(uri));
	}
	iterator->destroy(iterator);

	/* add any ocsp access points to the issuer ca info record */
	iterator = cert->create_ocspuri_iterator(cert);
	
	while (iterator->iterate(iterator, (void**)&uri))
	{
		issuer->add_ocspuri(issuer, uri->get_encoding(uri));
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of credential_store_t.is_trusted
 */
static bool is_trusted(private_local_credential_store_t *this, x509_t *cert)
{
	int pathlen;
	time_t until = UNDEFINED_TIME;
	x509_t *cert_to_be_trusted = cert;

	DBG2(DBG_CFG, "establishing trust in certificate:");

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
	{
		err_t ugh = NULL;
		ca_info_t *issuer;
		x509_t *issuer_cert;
		rsa_public_key_t *issuer_public_key;
		bool valid_signature;

		DBG2(DBG_CFG, "subject: '%D'", cert->get_subject(cert));
		DBG2(DBG_CFG, "issuer:  '%D'", cert->get_issuer(cert));

		ugh = cert->is_valid(cert, &until);
		if (ugh != NULL)
		{
			DBG1(DBG_CFG, "certificate %s", ugh);
			return FALSE;
		}
		DBG2(DBG_CFG, "certificate is valid");
	
		issuer = get_issuer(this, cert);
		if (issuer == NULL)
		{
			DBG1(DBG_CFG, "issuer not found");
			return FALSE;
		}
		DBG2(DBG_CFG, "issuer found");

		issuer_cert = issuer->get_certificate(issuer);
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
			cert_to_be_trusted->set_until(cert_to_be_trusted, until);
			cert_to_be_trusted->set_status(cert_to_be_trusted, CERT_GOOD);
			return TRUE;
		}
		else
		{
			/* go up one step in the trust chain */
			cert = issuer_cert;
		}
	}
	DBG1(DBG_CFG, "maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
	return FALSE;
}

/**
 * Implementation of credential_store_t.verify.
 */
static bool verify(private_local_credential_store_t *this, x509_t *cert, bool *found)
{
	int pathlen;
	time_t until = UNDEFINED_TIME;

	x509_t *end_cert = cert;
	x509_t *cert_copy = find_certificate(this->certs, end_cert);
	
	DBG2(DBG_CFG, "verifying end entity certificate:");

	*found = (cert_copy != NULL);
	if (*found)
	{
		DBG2(DBG_CFG,
			 "end entitity certificate is already in credential store");
	}

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
	{
		err_t ugh = NULL;
		ca_info_t *issuer;
		x509_t *issuer_cert;
		rsa_public_key_t *issuer_public_key;
		bool valid_signature;

		DBG1(DBG_CFG, "subject: '%D'", cert->get_subject(cert));
		DBG1(DBG_CFG, "issuer:  '%D'", cert->get_issuer(cert));

		ugh = cert->is_valid(cert, &until);
		if (ugh != NULL)
		{
			DBG1(DBG_CFG, "certificate %s", ugh);
			return FALSE;
		}
		DBG2(DBG_CFG, "certificate is valid");

		issuer = get_issuer(this, cert);
		if (issuer == NULL)
		{
			DBG1(DBG_CFG, "issuer not found");
			return FALSE;
		}
		DBG2(DBG_CFG, "issuer found");

		issuer_cert = issuer->get_certificate(issuer);
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
			DBG1(DBG_CFG, "reached self-signed root ca");

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

			if (pathlen == 0)
			{
				/* add any crl and ocsp uris contained in the certificate under test */
				add_uris(issuer, cert);
			}

			/* first check certificate revocation using ocsp */
			status = issuer->verify_by_ocsp(issuer, certinfo, &this->public.credential_store);

			/* if ocsp service is not available then fall back to crl */
			if ((status == CERT_UNDEFINED) || (status == CERT_UNKNOWN && this->strict))
			{
				status = issuer->verify_by_crl(issuer, certinfo, CRL_DIR);
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
						certinfo->destroy(certinfo);
						return FALSE;
					}
					DBG1(DBG_CFG, "certificate is good");

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
							 &revocationTime, crl_reason_names,
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
						certinfo->destroy(certinfo);
						return FALSE;
					}
				case CERT_UNKNOWN:
				case CERT_UNDEFINED:
				default:
					DBG1(DBG_CFG, "certificate status unknown");
					if (this->strict)
					{
						/* update status of end certificate in the credential store */
						if (cert_copy)
						{
							cert_copy->set_status(cert_copy, CERT_UNTRUSTED);
						}
						certinfo->destroy(certinfo);
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
	x509_t *found_cert = find_certificate(certs, cert);

	if (found_cert)
	{
		/* add the authority flags */
		found_cert->add_authority_flags(found_cert, cert->get_authority_flags(cert));

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
 * Add a unique ca info record to a linked list
 */
static void add_ca_info(private_local_credential_store_t *this, ca_info_t *ca_info)
{
	ca_info_t *current_ca_info;
	ca_info_t *found_ca_info = NULL;

	iterator_t *iterator = this->ca_infos->create_iterator(this->ca_infos, TRUE);

	while (iterator->iterate(iterator, (void**)&current_ca_info))
	{
		if (current_ca_info->equals(current_ca_info, ca_info))
		{
			found_ca_info = current_ca_info;
			break;
		}
	}
	iterator->destroy(iterator);

	if (found_ca_info)
	{
		current_ca_info->add_info(current_ca_info, ca_info);
		ca_info->destroy(ca_info);
	}
	else
	{
		this->ca_infos->insert_last(this->ca_infos, (void*)ca_info);
	}
}

/**
 * Release ca info record of a given name
 */
static status_t release_ca_info(private_local_credential_store_t *this, const char *name)
{
	status_t status = NOT_FOUND;
	ca_info_t *ca_info;

	iterator_t *iterator = this->ca_infos->create_iterator(this->ca_infos, TRUE);

	while (iterator->iterate(iterator, (void**)&ca_info))
	{
		if (ca_info->equals_name_release_info(ca_info, name))
		{
			status = SUCCESS;
			break;
		}
	}
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implements local_credential_store_t.add_end_certificate
 */
static x509_t* add_end_certificate(private_local_credential_store_t *this, x509_t *cert)
{
	x509_t *ret_cert = add_certificate(this->certs, cert);

	/* add crl and ocsp uris the first time the certificate is added */
	if (ret_cert == cert)
	{
		ca_info_t *issuer = get_issuer(this, cert);

		if (issuer)
		{
			add_uris(issuer, cert);
		}
	}
	return ret_cert;
}

/**
 * Implements local_credential_store_t.add_auth_certificate
 */
static x509_t* add_auth_certificate(private_local_credential_store_t *this, x509_t *cert, u_int auth_flags)
{
	cert->add_authority_flags(cert, auth_flags);
	return add_certificate(this->auth_certs, cert);
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
static iterator_t* create_auth_cert_iterator(private_local_credential_store_t *this)
{
	return this->auth_certs->create_iterator(this->auth_certs, TRUE);
}

/**
 * Implements local_credential_store_t.create_cainfo_iterator
 */
static iterator_t* create_cainfo_iterator(private_local_credential_store_t *this)
{
	return this->ca_infos->create_iterator(this->ca_infos, TRUE);
}

/**
 * Implements local_credential_store_t.load_auth_certificates
 */
static void load_auth_certificates(private_local_credential_store_t *this,
								   u_int auth_flag,
								   const char* label,
								   const char* path)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	
	DBG1(DBG_CFG, "loading %s certificates from '%s'", label, path);

	dir = opendir(path);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening %s certs directory '%s'", label, path);
		return;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		char file[PATH_BUF];

		snprintf(file, sizeof(file), "%s/%s", path, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			x509_t *cert = x509_create_from_file(file, label);

			if (cert)
			{
				err_t ugh = cert->is_valid(cert, NULL);

				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "warning: %s certificate %s", label, ugh);
				}

				if (auth_flag == AUTH_CA && !cert->is_ca(cert))
				{
					DBG1(DBG_CFG, "  CA basic constraints flag not set, cert discarded");
					cert->destroy(cert);
				}
				else
				{
					x509_t *ret_cert;

					cert->add_authority_flags(cert, auth_flag);

					ret_cert = add_certificate(this->auth_certs, cert);

					if (auth_flag == AUTH_CA && ret_cert == cert)
					{
						ca_info_t *ca_info = ca_info_create(NULL, cert);

						add_ca_info(this, ca_info);
					}
				}
			}
		}
	}
	closedir(dir);
}

/**
 * Implements local_credential_store_t.load_ca_certificates
 */
static void load_ca_certificates(private_local_credential_store_t *this)
{
	load_auth_certificates(this, AUTH_CA, "ca", CA_CERTIFICATE_DIR);

	/* add any crl and ocsp uris found in the ca certificates to the
     * corresponding issuer info record. We can do this only after all
     * ca certificates have been loaded and the ca hierarchy is known.
     */
	{
		iterator_t *iterator = this->ca_infos->create_iterator(this->ca_infos, TRUE);
		ca_info_t *ca_info;

		while (iterator->iterate(iterator, (void **)&ca_info))
		{
			x509_t *cacert = ca_info->get_certificate(ca_info);
			ca_info_t *issuer = get_issuer(this, cacert);

			if (issuer)
			{
				add_uris(issuer, cacert);
			}
		}
		iterator->destroy(iterator);
	}
}

/**
 * Implements local_credential_store_t.load_aa_certificates
 */
static void load_aa_certificates(private_local_credential_store_t *this)
{
	load_auth_certificates(this, AUTH_AA, "aa", AA_CERTIFICATE_DIR);
}

/**
 * Add a unique attribute certificate to a linked list
 */
static void add_attr_certificate(private_local_credential_store_t *this, x509ac_t *cert)
{
  /* TODO add a new attribute certificate to the linked list */
}

/**
 * Implements local_credential_store_t.load_attr_certificates
 */
static void load_attr_certificates(private_local_credential_store_t *this)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;

	const char *path = ATTR_CERTIFICATE_DIR;
	
	DBG1(DBG_CFG, "loading attribute certificates from '%s'", path);

	dir = opendir(ATTR_CERTIFICATE_DIR);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening attribute certs directory '%s'", path);
		return;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		char file[PATH_BUF];

		snprintf(file, sizeof(file), "%s/%s", path, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			x509ac_t *cert = x509ac_create_from_file(file);

			if (cert)
			{
				err_t ugh = cert->is_valid(cert, NULL);

				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "warning: attribute certificate %s", ugh);
				}
				add_attr_certificate(this, cert);
			}
		}
	}
	closedir(dir);


}

/**
 * Implements local_credential_store_t.load_ocsp_certificates
 */
static void load_ocsp_certificates(private_local_credential_store_t *this)
{
	load_auth_certificates(this, AUTH_OCSP, "ocsp", OCSP_CERTIFICATE_DIR);
}

/**
 * Add the latest crl to the issuing ca
 */
static void add_crl(private_local_credential_store_t *this, crl_t *crl, const char *path)
{
	iterator_t *iterator = this->ca_infos->create_iterator(this->ca_infos, TRUE);
	ca_info_t *ca_info;
	bool found = FALSE;

	while (iterator->iterate(iterator, (void**)&ca_info))
	{
		if (ca_info->is_crl_issuer(ca_info, crl))
		{
			char buffer[BUF_LEN];
			chunk_t uri = { buffer, 7 + strlen(path) };

			ca_info->add_crl(ca_info, crl);
			if (uri.len < BUF_LEN)
			{
				snprintf(buffer, BUF_LEN, "file://%s", path);
				ca_info->add_crluri(ca_info, uri);
			}
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	
	if (!found)
	{
		crl->destroy(crl);
		DBG2(DBG_CFG, "  no issuing ca found for this crl - discarded");
	}
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
	
	DBG1(DBG_CFG, "loading crls from '%s'", CRL_DIR);

	dir = opendir(CRL_DIR);
	if (dir == NULL)
	{
		DBG1(DBG_CFG, "error opening crl directory '%s'", CRL_DIR);
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
				DBG1(DBG_CFG, "  crl is %s", crl->is_valid(crl)? "valid":"stale");
				add_crl(this, crl, file);
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
			bool is_eap = FALSE;

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
			else if ( match("PSK", &token) ||
					((match("EAP", &token) || match("XAUTH", &token)) && (is_eap = TRUE)))
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
				
				DBG1(DBG_CFG, "  loading %s key for %s", 
					 is_eap ? "EAP" : "shared", 
					 ids.len > 0 ? (char*)ids.ptr : "%any");

				DBG4(DBG_CFG, "  secret:", secret);

				shared_key = shared_key_create(secret);
				if (shared_key)
				{
					if (is_eap)
					{
						this->eap_keys->insert_last(this->eap_keys, (void*)shared_key);
					}
					else
					{
						this->shared_keys->insert_last(this->shared_keys, (void*)shared_key);
					}
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
					 "RSA, PSK, EAP, or PIN", line_nr, token.len);
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
	this->auth_certs->destroy_offset(this->auth_certs, offsetof(x509_t, destroy));
	this->ca_infos->destroy_offset(this->ca_infos, offsetof(ca_info_t, destroy));
	this->private_keys->destroy_offset(this->private_keys, offsetof(rsa_private_key_t, destroy));
	this->shared_keys->destroy_function(this->shared_keys, (void*)shared_key_destroy);
	this->eap_keys->destroy_function(this->eap_keys, (void*)shared_key_destroy);
	free(this);
}

/**
 * Described in header.
 */
local_credential_store_t * local_credential_store_create(bool strict)
{
	private_local_credential_store_t *this = malloc_thing(private_local_credential_store_t);
	
	this->public.credential_store.get_shared_key = (status_t (*) (credential_store_t*,identification_t*,identification_t*,chunk_t*))get_shared_key;
	this->public.credential_store.get_eap_key = (status_t (*) (credential_store_t*,identification_t*,identification_t*,chunk_t*))get_eap_key;
	this->public.credential_store.get_rsa_public_key = (rsa_public_key_t*(*)(credential_store_t*,identification_t*))get_rsa_public_key;
	this->public.credential_store.get_rsa_private_key = (rsa_private_key_t* (*) (credential_store_t*,rsa_public_key_t*))get_rsa_private_key;
	this->public.credential_store.has_rsa_private_key = (bool (*) (credential_store_t*,rsa_public_key_t*))has_rsa_private_key;
	this->public.credential_store.get_trusted_public_key = (rsa_public_key_t*(*)(credential_store_t*,identification_t*))get_trusted_public_key;
	this->public.credential_store.get_certificate = (x509_t* (*) (credential_store_t*,identification_t*))get_certificate;
	this->public.credential_store.get_auth_certificate = (x509_t* (*) (credential_store_t*,u_int,identification_t*))get_auth_certificate;
	this->public.credential_store.get_ca_certificate_by_keyid = (x509_t* (*) (credential_store_t*,chunk_t))get_ca_certificate_by_keyid;
	this->public.credential_store.get_issuer = (ca_info_t* (*) (credential_store_t*,const x509_t*))get_issuer;
	this->public.credential_store.is_trusted = (bool (*) (credential_store_t*,x509_t*))is_trusted;
	this->public.credential_store.verify = (bool (*) (credential_store_t*,x509_t*,bool*))verify;
	this->public.credential_store.add_end_certificate = (x509_t* (*) (credential_store_t*,x509_t*))add_end_certificate;
	this->public.credential_store.add_auth_certificate = (x509_t* (*) (credential_store_t*,x509_t*,u_int))add_auth_certificate;
	this->public.credential_store.add_ca_info = (void (*) (credential_store_t*,ca_info_t*))add_ca_info;
	this->public.credential_store.release_ca_info = (status_t (*) (credential_store_t*,const char*))release_ca_info;
	this->public.credential_store.create_cert_iterator = (iterator_t* (*) (credential_store_t*))create_cert_iterator;
	this->public.credential_store.create_auth_cert_iterator = (iterator_t* (*) (credential_store_t*))create_auth_cert_iterator;
	this->public.credential_store.create_cainfo_iterator = (iterator_t* (*) (credential_store_t*))create_cainfo_iterator;
	this->public.credential_store.load_ca_certificates = (void (*) (credential_store_t*))load_ca_certificates;
	this->public.credential_store.load_aa_certificates = (void (*) (credential_store_t*))load_aa_certificates;
	this->public.credential_store.load_attr_certificates = (void (*) (credential_store_t*))load_attr_certificates;
	this->public.credential_store.load_ocsp_certificates = (void (*) (credential_store_t*))load_ocsp_certificates;
	this->public.credential_store.load_crls = (void (*) (credential_store_t*))load_crls;
	this->public.credential_store.load_secrets = (void (*) (credential_store_t*))load_secrets;
	this->public.credential_store.destroy = (void (*) (credential_store_t*))destroy;
	
	/* private variables */
	this->shared_keys = linked_list_create();
	this->eap_keys = linked_list_create();
	this->private_keys = linked_list_create();
	this->certs = linked_list_create();
	this->auth_certs = linked_list_create();
	this->ca_infos = linked_list_create();
	this->strict = strict;

	return (&this->public);
}
