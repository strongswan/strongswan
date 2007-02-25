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

#include "ca.h"

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
	const x509_t *cacert;
	
	/**
	 * List of crl URIs
	 */
	linked_list_t *crlURIs;

	/**
	 * List of ocsp URIs
	 */
	linked_list_t *ocspURIs;
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
 * Implements ca_info_t.equals_name
 */
static bool equals_name(const private_ca_info_t *this, const char *name)
{
	return this->name != NULL && streq(this->name, name);
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
		identification_t *crlURI = identification_create_from_encoding(ID_DER_ASN1_GN_URI, uri);

		add_identification(this->crlURIs, crlURI);
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
		identification_t *ocspURI = identification_create_from_encoding(ID_DER_ASN1_GN_URI, uri);

		add_identification(this->ocspURIs, ocspURI);
	}
}

/**
 * Implements ca_info_t.add_info
 */
void add_info (private_ca_info_t *this, const private_ca_info_t *that)
{
	if (this->name == NULL && that->name != NULL)
	{
		this->name = strdup(that->name);
	}
	{
		identification_t *uri;

		iterator_t *iterator = that->crlURIs->create_iterator(that->crlURIs, TRUE);

		while (iterator->iterate(iterator, (void**)&uri))
		{
			add_crluri(this, uri->get_encoding(uri));
		}
		iterator->destroy(iterator);
	}
	{
		identification_t *uri;

		iterator_t *iterator = that->ocspURIs->create_iterator(that->ocspURIs, TRUE);

		while (iterator->iterate(iterator, (void**)&uri))
		{
			add_ocspuri(this, uri->get_encoding(uri));
		}
		iterator->destroy(iterator);
	}
}

/**
 * Implements ca_info_t.release_info
 */
static void release_info(private_ca_info_t *this)
{
	this->crlURIs->destroy_offset(this->crlURIs,
								  offsetof(identification_t, destroy));
	this->crlURIs = linked_list_create();

	this->ocspURIs->destroy_offset(this->ocspURIs,
								   offsetof(identification_t, destroy));
	this->ocspURIs = linked_list_create();

	free(this->name);
	this->name = NULL;
}

/**
 * Implements ca_info_t.destroy
 */
static void destroy(private_ca_info_t *this)
{
	this->crlURIs->destroy_offset(this->crlURIs,
								  offsetof(identification_t, destroy));
	this->ocspURIs->destroy_offset(this->ocspURIs,
								   offsetof(identification_t, destroy));
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
		identification_t *crlURI;
		iterator_t *iterator = this->crlURIs->create_iterator(this->crlURIs, TRUE);
		bool first = TRUE;

		while (iterator->iterate(iterator, (void**)&crlURI))
		{
			written += fprintf(stream, "    %s   '%D'\n",
							   first? "crluris:":"        ", crlURI);
			first = FALSE;
		}
		iterator->destroy(iterator);
	}
	{
		identification_t *ocspURI;
		iterator_t *iterator = this->ocspURIs->create_iterator(this->ocspURIs, TRUE);
		bool first = TRUE;

		while (iterator->iterate(iterator, (void**)&ocspURI))
		{
			written += fprintf(stream, "    %s  '%D'\n",
							   first? "ocspuris:":"         ", ocspURI);
			first = FALSE;
		}
		iterator->destroy(iterator);
	}
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
ca_info_t *ca_info_create(const char *name, const x509_t *cacert)
{
	private_ca_info_t *this = malloc_thing(private_ca_info_t);
	
	/* initialize */
	this->installed = time(NULL);
	this->name = (name == NULL)? NULL:strdup(name);
	this->cacert = cacert;
	this->crlURIs = linked_list_create();
	this->ocspURIs = linked_list_create();
	
	/* public functions */
	this->public.equals = (bool (*) (const ca_info_t*,const ca_info_t*))equals;
	this->public.equals_name = (bool (*) (const ca_info_t*,const char*))equals_name;
	this->public.add_info = (void (*) (ca_info_t*,const ca_info_t*))add_info;
	this->public.add_crluri = (void (*) (ca_info_t*,chunk_t))add_crluri;
	this->public.add_ocspuri = (void (*) (ca_info_t*,chunk_t))add_ocspuri;
	this->public.release_info = (void (*) (ca_info_t*))release_info;
	this->public.destroy = (void (*) (ca_info_t*))destroy;

	return &this->public;
}
