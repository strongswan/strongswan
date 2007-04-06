/**
 * @file ca.c
 * 
 * @brief Implementation of ca_info_t.
 * 
 */

/*
 * Copyright (C) 2007 Andreas Steffen
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
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certinfo.h"
#include "ocsp.h"

#include <library.h>
#include <debug.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <utils/fetcher.h>

typedef struct private_ca_info_t private_ca_info_t;

/**
 * Private data of a ca_info_t object.
 */
struct private_ca_info_t {
	/**
	 * Public interface for this ca info record
	 */
	ca_info_t public;
	
	/**
	 * Name of the ca info record
	 */
	char *name;

	/**
	 * Time when ca info record was installed
	 */
	time_t installed;

	/**
	 * Distinguished Name of the CA
	 */
	x509_t *cacert;
	
	/**
	 * List of crl URIs
	 */
	linked_list_t *crluris;

	/**
	 * List of ocsp URIs
	 */
	linked_list_t *ocspuris;

	/**
	 * CRL issued by this ca
	 */
	crl_t *crl;

	/**
	 * List of certificate info records
	 */
	linked_list_t *certinfos;

	/**
	 * mutex controls access to the elements:
	 * name, crluris, ocspuris, crl, and certinfos
	 */
	pthread_mutex_t mutex;
};

/**
 * static options set by ca_info_set_options()
 */
static bool cache_crls = FALSE;
static u_int crl_check_interval = 0;

/**
 * Implements ca_info_t.equals
 */
static bool equals(const private_ca_info_t *this, const private_ca_info_t *that)
{
	return chunk_equals(this->cacert->get_keyid(this->cacert),
						that->cacert->get_keyid(that->cacert));
}

/**
 * Implements ca_info_t.equals_name_release_info
 */
static bool equals_name_release_info(private_ca_info_t *this, const char *name)
{
	bool found;

	pthread_mutex_lock(&(this->mutex));
	found = this->name != NULL && streq(this->name, name);

	if (found)
	{
		this->crluris->destroy_offset(this->crluris,
									  offsetof(identification_t, destroy));
		this->crluris = linked_list_create();

		this->ocspuris->destroy_offset(this->ocspuris,
									   offsetof(identification_t, destroy));
		this->ocspuris = linked_list_create();

		free(this->name);
		this->name = NULL;
	}

	pthread_mutex_unlock(&(this->mutex));
	return found;
}

/**
 * Implements ca_info_t.is_crl_issuer
 */
static bool is_cert_issuer(private_ca_info_t *this, const x509_t *cert)
{
	return cert->is_issuer(cert, this->cacert);
}

/**
 * Implements ca_info_t.is_crl_issuer
 */
static bool is_crl_issuer(private_ca_info_t *this, const crl_t *crl)
{
	return crl->is_issuer(crl, this->cacert);
}

/**
 * Implements ca_info_t.has_crl
 */
static bool has_crl(private_ca_info_t *this)
{
	bool found;

	pthread_mutex_lock(&(this->mutex));
	found = this->crl != NULL;
	pthread_mutex_unlock(&(this->mutex));

	return found;
}

/**
 * Implements ca_info_t.has_certinfos
 */
static bool has_certinfos(private_ca_info_t *this)
{
	bool found;

	pthread_mutex_lock(&(this->mutex));
	found = this->certinfos->get_count(this->certinfos) > 0;
	pthread_mutex_unlock(&(this->mutex));

	return found;
}

/**
 * Implements ca_info_t.add_crl
 */
static void add_crl(private_ca_info_t *this, crl_t *crl)
{
	pthread_mutex_lock(&(this->mutex));

	if (this->crl)
	{
		if (crl->is_newer(crl, this->crl))
		{
			this->crl->destroy(this->crl);
			this->crl = crl;
			DBG1("  this crl is newer - existing crl replaced");
		}
		else
		{
			crl->destroy(crl);
			DBG1("  this crl is not newer - existing crl retained");
		}
	}
	else
	{
		this->crl = crl;
		DBG2("  crl added");
	}

	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implements ca_info_t.list_crl
 */
static void list_crl(private_ca_info_t *this, FILE *out, bool utc)
{
	pthread_mutex_lock(&(this->mutex));

	fprintf(out, "%#U\n", this->crl, utc);

	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implements ca_info_t.list_certinfos
 */
static void list_certinfos(private_ca_info_t *this, FILE *out, bool utc)
{
	pthread_mutex_lock(&(this->mutex));

	fprintf(out,"    authname:  '%D'\n", this->cacert->get_subject(this->cacert));
	{
		chunk_t authkey = this->cacert->get_subjectKeyID(this->cacert);

		fprintf(out,"    authkey:    %#B\n", &authkey);
	}
	{
		iterator_t *iterator = this->certinfos->create_iterator(this->certinfos, TRUE);
		certinfo_t *certinfo;

		while (iterator->iterate(iterator, (void**)&certinfo))
		{
			fprintf(out, "%#Y\n", certinfo, utc);
		}
		iterator->destroy(iterator);
	}

	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Find an exact copy of an identification in a linked list
 */
static identification_t* find_identification(linked_list_t *list, identification_t *id)
{
	identification_t *found_id = NULL, *current_id;

	iterator_t *iterator = list->create_iterator(list, TRUE);

	while (iterator->iterate(iterator, (void**)&current_id))
	{
		if (id->equals(id, current_id))
		{
			found_id = current_id;
			break;
		}
	}
	iterator->destroy(iterator);

	return found_id;
}

/**
 * Add a unique identification to a linked list
 */
static identification_t *add_identification(linked_list_t *list, identification_t *id)
{
	identification_t *found_id = find_identification(list, id);

	if (found_id)
	{
		id->destroy(id);
		return found_id;
	}
	else
	{
		list->insert_last(list, (void*)id);
		return id;
	}
}

/**
 * Implements ca_info_t.add_crluri
 */
static void add_crluri(private_ca_info_t *this, chunk_t uri)
{
	if (uri.len < 6 ||
	   (strncasecmp(uri.ptr, "http", 4) != 0  &&
		strncasecmp(uri.ptr, "ldap", 4) != 0  &&
		strncasecmp(uri.ptr, "file", 4) != 0  &&
		strncasecmp(uri.ptr, "ftp",  3) != 0))
	{
		DBG1("  invalid crl uri '%#B'", uri);
		return;
	}
	else
	{
		identification_t *crluri = identification_create_from_encoding(ID_DER_ASN1_GN_URI, uri);

		pthread_mutex_lock(&(this->mutex));
		add_identification(this->crluris, crluri);
		pthread_mutex_unlock(&(this->mutex));
	}
}

/**
 * Implements ca_info_t.add_ocspuri
 */
static void add_ocspuri(private_ca_info_t *this, chunk_t uri)
{
	if (uri.len < 7 || strncasecmp(uri.ptr, "http", 4) != 0)
	{
		DBG1("  invalid ocsp uri '%.*s'", uri.len, uri.ptr);
		return;
	}
	else
	{
		identification_t *ocspuri = identification_create_from_encoding(ID_DER_ASN1_GN_URI, uri);

		pthread_mutex_lock(&(this->mutex));
		add_identification(this->ocspuris, ocspuri);
		pthread_mutex_unlock(&(this->mutex));
	}
}

/**
 * Implements ca_info_t.add_info.
 */
void add_info (private_ca_info_t *this, const private_ca_info_t *that)
{
	pthread_mutex_lock(&(this->mutex));

	if (this->name == NULL && that->name != NULL)
	{
		this->name = strdup(that->name);
	}

	pthread_mutex_unlock(&(this->mutex));

	{
		identification_t *uri;

		iterator_t *iterator = that->crluris->create_iterator(that->crluris, TRUE);

		while (iterator->iterate(iterator, (void**)&uri))
		{
			add_crluri(this, uri->get_encoding(uri));
		}
		iterator->destroy(iterator);
	}

	{
		identification_t *uri;

		iterator_t *iterator = that->ocspuris->create_iterator(that->ocspuris, TRUE);

		while (iterator->iterate(iterator, (void**)&uri))
		{
			add_ocspuri(this, uri->get_encoding(uri));
		}
		iterator->destroy(iterator);
	}
}

/**
 *  Implements ca_info_t.get_certificate.
 */
static x509_t* get_certificate(private_ca_info_t* this)
{
	return this->cacert;
}

/**
 * caches a crl by saving it to a given crl directory
 */
void cache_crl(private_ca_info_t* this, const char *crl_dir, crl_t *crl)
{
	char buffer[BUF_LEN];
	char *path;
	char *pos = buffer;
	int len = BUF_LEN;
	int n;

	chunk_t authKeyID = this->cacert->get_subjectKeyID(this->cacert);
	chunk_t uri;

	uri.ptr = buffer;
	uri.len = 7 + strlen(crl_dir) + 1 + 2*authKeyID.len + 4;

	if (uri.len >= BUF_LEN)	
	{
		DBG1("file uri exceeds buffer length of %d bytes - crl not saved", BUF_LEN);
		return;
	}

	/* print the file uri prefix */
	n = snprintf(pos, len, "file://");
	pos += n;  len -= n;

	/* remember the start of the path string */
	path = pos;

	/* print the default crl directory path */
	n = snprintf(pos, len, "%s/", crl_dir);
	pos += n;  len -= n;

	/* create and print a unique crl filename derived from the authKeyID */
	while (authKeyID.len-- > 0)
	{
		n = snprintf(pos, len, "%02x", *authKeyID.ptr++);
		pos += n; len -= n;
	}

	/* add the file suffix */
	n = snprintf(pos, len, ".crl");

	if (crl->write_to_file(crl, path, 0022, TRUE))
	{
		identification_t *crluri = identification_create_from_encoding(ID_DER_ASN1_GN_URI, uri);

		add_identification(this->crluris, crluri);
	}
}

/**
 *  Implements ca_info_t.verify_by_crl.
 */
static cert_status_t verify_by_crl(private_ca_info_t* this, certinfo_t *certinfo,
								   const char *crl_dir)
{
	rsa_public_key_t *issuer_public_key = this->cacert->get_public_key(this->cacert);
	bool stale;

	pthread_mutex_lock(&(this->mutex));
	if (this->crl == NULL)
	{
		stale = TRUE;
		DBG1("no crl is locally available");
	}
	else
	{
		stale = !this->crl->is_valid(this->crl);
		DBG1("crl is %s", stale? "stale":"valid");
	}

	if (stale && crl_check_interval > 0)
	{
		iterator_t *iterator = this->crluris->create_iterator(this->crluris, TRUE);
		identification_t *uri;
		
		while (iterator->iterate(iterator, (void**)&uri))
		{
			fetcher_t *fetcher;
			char uri_string[BUF_LEN];
			chunk_t uri_chunk = uri->get_encoding(uri);
			chunk_t response_chunk;

			snprintf(uri_string, BUF_LEN, "%.*s", uri_chunk.len, uri_chunk.ptr);
			fetcher = fetcher_create(uri_string);
			
			response_chunk = fetcher->get(fetcher);
			fetcher->destroy(fetcher);
			if (response_chunk.ptr != NULL)
			{
				crl_t *crl = crl_create_from_chunk(response_chunk);
		
				if (crl == NULL)
				{
					free(response_chunk.ptr);
					continue;
				}
				if (!is_crl_issuer(this, crl))
				{
					DBG1("  fetched crl has wrong issuer");
					crl->destroy(crl);
					continue;
				}
				if (!crl->verify(crl, issuer_public_key))
				{
					DBG1("fetched crl signature is invalid");
					crl->destroy(crl);
					continue;
				}
				DBG2("fetched crl signature is valid");

				if (this->crl == NULL)
				{
					this->crl = crl;
				}
				else if (crl->is_newer(crl, this->crl))
				{
					this->crl->destroy(this->crl);
					this->crl = crl;
					DBG1("this crl is newer - existing crl replaced");
				}
				else
				{
					crl->destroy(crl);
					DBG1("this crl is not newer - existing crl retained");
					continue;
				}
				if (crl->is_valid(crl))
				{
					if (cache_crls && strncasecmp(uri_string, "file", 4) != 0)
					{
						cache_crl(this, crl_dir, crl);
					}
					/* we found a valid crl and therefore exit the fetch loop */
					break;
				}
				else
				{
					DBG1("fetched crl is stale");
				}
			}
		}
		iterator->destroy(iterator);
	}

	if (this->crl)
	{
		if (!this->crl->verify(this->crl, issuer_public_key))
		{
			DBG1("crl signature is invalid");
			goto ret;
		}
		DBG2("crl signature is valid");

		this->crl->get_status(this->crl, certinfo);
	}

ret:
	pthread_mutex_unlock(&(this->mutex));
	return certinfo->get_status(certinfo);
}

/**
  * Implements ca_info_t.verify_by_ocsp.
  */
static cert_status_t verify_by_ocsp(private_ca_info_t* this,
									certinfo_t *certinfo,
									credential_store_t *credentials)
{
	bool stale;
	iterator_t *iterator;
	certinfo_t *cached_certinfo = NULL;
	int comparison = 1;

	pthread_mutex_lock(&(this->mutex));

	/* do we support OCSP at all? */
	if (this->ocspuris->get_count(this->ocspuris) == 0)
	{
		goto ret;
	}

	iterator = this->certinfos->create_iterator(this->certinfos, TRUE);

	/* find the list insertion point in alphabetical order */
	while(iterator->iterate(iterator, (void**)&cached_certinfo))
	{
		comparison = certinfo->compare_serialNumber(certinfo, cached_certinfo);

		if (comparison <= 0)
		{
			break;
		}
	}

	/* do we have a valid certinfo_t for this serial number in our cache? */
	if (comparison == 0)
	{	
		stale = cached_certinfo->get_nextUpdate(cached_certinfo) < time(NULL);
		DBG1("ocsp status in cache is %s", stale ? "stale":"fresh");
	}
	else
	{
		stale = TRUE;
		DBG1("ocsp status is not in cache");
	}

	if (stale)
	{
		ocsp_t *ocsp;

		ocsp = ocsp_create(this->cacert, this->ocspuris);
		ocsp->fetch(ocsp, certinfo, credentials);
		if (certinfo->get_status(certinfo) != CERT_UNDEFINED)
		{
			if (comparison != 0)
			{
				cached_certinfo = certinfo_create(certinfo->get_serialNumber(certinfo));

				if (comparison > 0)
				{
					iterator->insert_after(iterator, (void *)cached_certinfo);
				}
				else
				{
					iterator->insert_before(iterator, (void *)cached_certinfo);
				}
			}
			cached_certinfo->update(cached_certinfo, certinfo);
		}
		ocsp->destroy(ocsp);
	}
	else
	{
		certinfo->update(certinfo, cached_certinfo);
	}

	iterator->destroy(iterator);

ret:
	pthread_mutex_unlock(&(this->mutex));
	return certinfo->get_status(certinfo);
}

/**
 * Implements ca_info_t.purge_ocsp
 */
static void purge_ocsp(private_ca_info_t *this)
{
	pthread_mutex_lock(&(this->mutex));

	this->certinfos->destroy_offset(this->certinfos,
									offsetof(certinfo_t, destroy));
	this->certinfos = linked_list_create();

	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implements ca_info_t.destroy
 */
static void destroy(private_ca_info_t *this)
{
	this->crluris->destroy_offset(this->crluris,
								  offsetof(identification_t, destroy));
	this->ocspuris->destroy_offset(this->ocspuris,
								   offsetof(identification_t, destroy));
	this->certinfos->destroy_offset(this->certinfos,
								   offsetof(certinfo_t, destroy));
	DESTROY_IF(this->crl);
	free(this->name);
	free(this);
}

/**
 * output handler in printf()
 */
static int print(FILE *stream, const struct printf_info *info,
				 const void *const *args)
{
	private_ca_info_t *this = *((private_ca_info_t**)(args[0]));
	bool utc = TRUE;
	int written = 0;
	const x509_t *cacert;
	
	if (info->alt)
	{
		utc = *((bool*)args[1]);
	}
	if (this == NULL)
	{
		return fprintf(stream, "(null)");
	}

	pthread_mutex_lock(&(this->mutex));
	written += fprintf(stream, "%#T", &this->installed, utc);

	if (this->name)
	{
		written += fprintf(stream, ", \"%s\"\n", this->name);
	}
	else
	{
		written += fprintf(stream, "\n");
	}

	cacert = this->cacert;
	written += fprintf(stream, "    authname:  '%D'\n", cacert->get_subject(cacert));
	{
		chunk_t authkey = cacert->get_subjectKeyID(cacert);

		written += fprintf(stream, "    authkey:    %#B\n", &authkey);
	}
	{
		chunk_t keyid = cacert->get_keyid(cacert);

		written += fprintf(stream, "    keyid:      %#B\n", &keyid);
	}
	{
		identification_t *crluri;
		iterator_t *iterator = this->crluris->create_iterator(this->crluris, TRUE);
		bool first = TRUE;

		while (iterator->iterate(iterator, (void**)&crluri))
		{
			written += fprintf(stream, "    %s   '%D'\n",
							   first? "crluris:":"        ", crluri);
			first = FALSE;
		}
		iterator->destroy(iterator);
	}
	{
		identification_t *ocspuri;
		iterator_t *iterator = this->ocspuris->create_iterator(this->ocspuris, TRUE);
		bool first = TRUE;

		while (iterator->iterate(iterator, (void**)&ocspuri))
		{
			written += fprintf(stream, "    %s  '%D'\n",
							   first? "ocspuris:":"         ", ocspuri);
			first = FALSE;
		}
		iterator->destroy(iterator);
	}
	pthread_mutex_unlock(&(this->mutex));
	return written;
}

/**
 * register printf() handlers
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(PRINTF_CAINFO, print, arginfo_ptr_alt_ptr_int);
}

/*
 * Described in header.
 */
void ca_info_set_options(bool cache, u_int interval)
{
	cache_crls = cache;
	crl_check_interval = interval;
}

/*
 * Described in header.
 */
ca_info_t *ca_info_create(const char *name, x509_t *cacert)
{
	private_ca_info_t *this = malloc_thing(private_ca_info_t);
	
	/* initialize */
	this->installed = time(NULL);
	this->name = (name == NULL)? NULL:strdup(name);
	this->cacert = cacert;
	this->crluris = linked_list_create();
	this->ocspuris = linked_list_create();
	this->certinfos = linked_list_create();
	this->crl = NULL;
	
	/* initialize the mutex */
	pthread_mutex_init(&(this->mutex), NULL);

	/* public functions */
	this->public.equals = (bool (*) (const ca_info_t*,const ca_info_t*))equals;
	this->public.equals_name_release_info = (bool (*) (ca_info_t*,const char*))equals_name_release_info;
	this->public.is_cert_issuer = (bool (*) (ca_info_t*,const x509_t*))is_cert_issuer;
	this->public.is_crl_issuer = (bool (*) (ca_info_t*,const crl_t*))is_crl_issuer;
	this->public.add_info = (void (*) (ca_info_t*,const ca_info_t*))add_info;
	this->public.add_crl = (void (*) (ca_info_t*,crl_t*))add_crl;
	this->public.has_crl = (bool (*) (ca_info_t*))has_crl;
	this->public.has_certinfos = (bool (*) (ca_info_t*))has_certinfos;
	this->public.list_crl = (void (*) (ca_info_t*,FILE*,bool))list_crl;
	this->public.list_certinfos = (void (*) (ca_info_t*,FILE*,bool))list_certinfos;
	this->public.add_crluri = (void (*) (ca_info_t*,chunk_t))add_crluri;
	this->public.add_ocspuri = (void (*) (ca_info_t*,chunk_t))add_ocspuri;
	this->public.get_certificate = (x509_t* (*) (ca_info_t*))get_certificate;
	this->public.verify_by_crl = (cert_status_t (*) (ca_info_t*,certinfo_t*, const char*))verify_by_crl;
	this->public.verify_by_ocsp = (cert_status_t (*) (ca_info_t*,certinfo_t*,credential_store_t*))verify_by_ocsp;
	this->public.purge_ocsp = (void (*) (ca_info_t*))purge_ocsp;
	this->public.destroy = (void (*) (ca_info_t*))destroy;

	return &this->public;
}
