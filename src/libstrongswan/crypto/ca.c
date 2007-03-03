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

#include <library.h>
#include <debug.h>
#include <utils/linked_list.h>
#include <utils/identification.h>

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
			DBG1("  thisUpdate is newer - existing crl replaced");
		}
		else
		{
			crl->destroy(crl);
			DBG1("  thisUpdate is not newer - existing crl retained");
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
 *  Implements ca_info_t.verify_by_crl.
 */
static cert_status_t verify_by_crl(private_ca_info_t* this, const x509_t *cert,
								   certinfo_t *certinfo)
{
	bool valid_signature;
	rsa_public_key_t *issuer_public_key;


	pthread_mutex_lock(&(this->mutex));

	if (this->crl == NULL)
	{
		DBG1("crl not found");
		goto err;
	}
	DBG2("crl found");
	
	issuer_public_key = this->cacert->get_public_key(this->cacert);
	valid_signature = this->crl->verify(this->crl, issuer_public_key);

	if (!valid_signature)
	{
		DBG1("crl signature is invalid");
		goto err;
	}
	DBG2("crl signature is valid");

	this->crl->get_status(this->crl, certinfo);

err:
	pthread_mutex_unlock(&(this->mutex));
	return certinfo->get_status(certinfo);
}

/**
  * Implements ca_info_t.verify_by_ocsp.
  */
static cert_status_t verify_by_ocsp(private_ca_info_t* this, const x509_t *cert,
									certinfo_t *certinfo)
{
	/* TODO implement function */
	return CERT_UNDEFINED;
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
	chunk_t keyid;
	
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
	this->public.list_crl = (void (*) (ca_info_t*,FILE*,bool))list_crl;
	this->public.add_crluri = (void (*) (ca_info_t*,chunk_t))add_crluri;
	this->public.add_ocspuri = (void (*) (ca_info_t*,chunk_t))add_ocspuri;
	this->public.get_certificate = (x509_t* (*) (ca_info_t*))get_certificate;
	this->public.verify_by_crl = (cert_status_t (*) (ca_info_t*,const x509_t*,certinfo_t*))verify_by_crl;
	this->public.verify_by_ocsp = (cert_status_t (*) (ca_info_t*,const x509_t*,certinfo_t*))verify_by_ocsp;
	this->public.destroy = (void (*) (ca_info_t*))destroy;

	return &this->public;
}
