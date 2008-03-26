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


#include "auth_info.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <credentials/certificates/certificate.h>

ENUM(auth_item_names, AUTHN_CA_CERT, AUTHZ_AC_GROUP,
	"AUTHN_CA_CERT",
	"AUTHN_CA_CERT_KEYID",
	"AUTHN_CA_CERT_NAME",
	"AUTHN_IM_CERT",
	"AUTHN_SUBJECT_CERT",
	"AUTHZ_PUBKEY",
	"AUTHZ_PSK",
	"AUTHZ_EAP",
	"AUTHZ_CA_CERT",
	"AUTHZ_CA_CERT_NAME",
	"AUTHZ_IM_CERT",
	"AUTHZ_SUBJECT_CERT",
	"AUTHZ_CRL_VALIDATION",
	"AUTHZ_OCSP_VALIDATION",
	"AUTHZ_AC_GROUP",
);

typedef struct private_auth_info_t private_auth_info_t;

/**
 * private data of item_set
 */
struct private_auth_info_t {

	/**
	 * public functions
	 */
	auth_info_t public;
	
	/**
	 * list of item_t's
	 */
	linked_list_t *items;
};

typedef struct item_t item_t;

struct item_t {
	/** type of this item */
	auth_item_t type;
	/** associated privlege value, if any */
	void *value;
};

/**
 * implements item_enumerator_t.enumerate
 */
static bool item_filter(void *data, item_t **item, auth_item_t *type,
									void *unused, void **value)
{
	*type = (*item)->type;
	*value = (*item)->value;
	return TRUE;
}

/**
 * Implementation of auth_info_t.create_item_enumerator.
 */
static enumerator_t* create_item_enumerator(private_auth_info_t *this)
{
	return enumerator_create_filter(this->items->create_enumerator(this->items),
									(void*)item_filter, NULL, NULL);
}

/**
 * Implementation of auth_info_t.get_item.
 */
static bool get_item(private_auth_info_t *this, auth_item_t type, void** value)
{
	enumerator_t *enumerator;
	void *current_value;
	auth_item_t current_type;
	bool found = FALSE;
	
	enumerator = create_item_enumerator(this);
	while (enumerator->enumerate(enumerator, &current_type, &current_value))
	{
		if (type == current_type)
		{
			*value = current_value;
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Implementation of auth_info_t.add_item.
 */
static void add_item(private_auth_info_t *this, auth_item_t type, void *value)
{
	item_t *item = malloc_thing(item_t);
	
	item->type = type;
	switch (type)
	{		
		case AUTHZ_PUBKEY:
		{
			public_key_t *key = (public_key_t*)value;

			item->value = key->get_ref(key);
			break;
		}
		case AUTHZ_PSK:
		{
			shared_key_t *key = (shared_key_t*)value;

			item->value = key->get_ref(key);
			break;
		}
		case AUTHN_CA_CERT:
		case AUTHN_IM_CERT:
		case AUTHN_SUBJECT_CERT:
		case AUTHZ_CA_CERT:
		case AUTHZ_IM_CERT:
		case AUTHZ_SUBJECT_CERT:
		{
			certificate_t *cert = (certificate_t*)value;

			item->value = cert->get_ref(cert);
			break;
		}
		case AUTHZ_CRL_VALIDATION:
		case AUTHZ_OCSP_VALIDATION:
		{
			cert_validation_t *validation = malloc_thing(cert_validation_t);

			*validation = *(cert_validation_t*)value;
			item->value = validation;
			break;
		}
		case AUTHZ_EAP:
		{
			eap_method_t *method = malloc_thing(eap_method_t);

			*method = *(eap_method_t*)value;
			item->value = method;
			break;
		}
		case AUTHN_CA_CERT_KEYID:
		case AUTHN_CA_CERT_NAME:
		case AUTHZ_CA_CERT_NAME:
		case AUTHZ_AC_GROUP:
		{
			identification_t *id = (identification_t*)value;

			item->value = id->clone(id);
			break;
		}
	}
	this->items->insert_last(this->items, item);
}


/**
 * Implementation of auth_info_t.complies.
 */
static bool complies(private_auth_info_t *this, auth_info_t *constraints)
{
	enumerator_t *enumerator;
	bool success = TRUE;
	auth_item_t type;
	void *value;
	
	enumerator = constraints->create_item_enumerator(constraints);
	while (enumerator->enumerate(enumerator, &type, &value))
	{
		switch (type)
		{
			case AUTHN_CA_CERT_KEYID:
			case AUTHN_CA_CERT:
			case AUTHN_CA_CERT_NAME:
			case AUTHN_IM_CERT:
			case AUTHN_SUBJECT_CERT:
			{	/* skip non-authorization tokens */
				continue;
			}
			case AUTHZ_CRL_VALIDATION:
			case AUTHZ_OCSP_VALIDATION:
			{
				cert_validation_t *valid;
			
				/* OCSP validation is also sufficient for CRL constraint, but
				 * not vice-versa */
				if (!get_item(this, type, (void**)&valid) &&
					type == AUTHZ_CRL_VALIDATION &&
					!get_item(this, AUTHZ_OCSP_VALIDATION, (void**)&valid))
				{
					DBG1(DBG_CFG, "constraint check failed: %N requires at "
						 "least %N, but no check done", auth_item_names, type,
						 cert_validation_names, *(cert_validation_t*)value);
					success = FALSE;
					break;
				}
				switch (*(cert_validation_t*)value)
				{
					case VALIDATION_SKIPPED:
						if (*valid == VALIDATION_SKIPPED)
						{
							break;
						}	/* FALL */
					case VALIDATION_GOOD:
						if (*valid == VALIDATION_GOOD)
						{
							break;
						}	/* FALL */
					default:
						DBG1(DBG_CFG, "constraint check failed: %N is %N, but "
							 "requires at least %N", auth_item_names, type,
							 cert_validation_names, *valid,
							 cert_validation_names, *(cert_validation_t*)value);
						success = FALSE;
						break;
				}
				break;
			}
			case AUTHZ_CA_CERT_NAME:
			case AUTHZ_PUBKEY:
			case AUTHZ_PSK:
			case AUTHZ_IM_CERT:
			case AUTHZ_SUBJECT_CERT:
			case AUTHZ_EAP:
			case AUTHZ_AC_GROUP:
				DBG1(DBG_CFG, "constraint check %N not implemented!",
					 auth_item_names, type);
				success = FALSE;
				break;
			case AUTHZ_CA_CERT:
			{
				certificate_t *cert;
			
				if (!get_item(this, AUTHZ_CA_CERT, (void**)&cert) ||
					!cert->equals(cert, (certificate_t*)value))
				{
					cert = (certificate_t*)value;
					DBG1(DBG_CFG, "constraint check failed: peer not "
						 "authenticated by CA '%D'.", cert->get_issuer(cert));
					success = FALSE;
				}
				break;
			}
		}
		if (!success)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return success;
}

/**
 * Implementation of auth_info_t.merge.
 */
static void merge(private_auth_info_t *this, private_auth_info_t *other)
{
	item_t *item;
	
	while (other->items->remove_first(other->items, (void**)&item) == SUCCESS)
	{
		this->items->insert_last(this->items, item);
	}
}

/**
 * Implementation of auth_info_t.equals.
 */
static bool equals(private_auth_info_t *this, private_auth_info_t *other)
{
	enumerator_t *e1, *e2;
	item_t *i1, *i2;
	bool equal = TRUE, found;
	
	e1 = this->items->create_enumerator(this->items);
	while (e1->enumerate(e1, &i1))
	{
		found = FALSE;
		e2 = this->items->create_enumerator(this->items);
		while (e2->enumerate(e2, &i2))
		{
			if (i1->type == i2->type)
			{
				switch (i1->type)
				{
					case AUTHZ_CRL_VALIDATION:
					case AUTHZ_OCSP_VALIDATION:
					{
						cert_validation_t c1, c2;
						
						c1 = *(cert_validation_t*)i1->value;
						c2 = *(cert_validation_t*)i2->value;
					
						if (c1 == c2)
						{
							found = TRUE;
							break;
						}
						continue;
					}
					case AUTHN_CA_CERT:
					case AUTHN_IM_CERT:
					case AUTHN_SUBJECT_CERT:
					case AUTHZ_CA_CERT:
					case AUTHZ_IM_CERT:
					case AUTHZ_SUBJECT_CERT:
					{
						certificate_t *c1, *c2;
						
						c1 = (certificate_t*)i1->value;
						c2 = (certificate_t*)i2->value;
					
						if (c1->equals(c1, c2))
						{
							found = TRUE;
							break;
						}
						continue;
					}
					case AUTHN_CA_CERT_KEYID:
					case AUTHN_CA_CERT_NAME:
					case AUTHZ_CA_CERT_NAME:
					{
						identification_t *c1, *c2;
						
						c1 = (identification_t*)i1->value;
						c2 = (identification_t*)i2->value;
					
						if (c1->equals(c1, c2))
						{
							found = TRUE;
							break;
						}
						continue;
					}
					case AUTHZ_PUBKEY:
					case AUTHZ_PSK:
					case AUTHZ_EAP:
					case AUTHZ_AC_GROUP:
						/* TODO: implement value comparison */
						break;
				}
				break;
			}
		}
		e2->destroy(e2);
		if (!found)
		{
			equal = FALSE;
			break;
		}
	}
	e1->destroy(e1);
	return equal;
}

/**
 * Implementation of auth_info_t.destroy
 */
static void destroy(private_auth_info_t *this)
{
	item_t *item;
	
	while (this->items->remove_last(this->items, (void**)&item) == SUCCESS)
	{
		switch (item->type)
		{
			case AUTHZ_PUBKEY:
			{
				public_key_t *key = (public_key_t*)item->value;
				key->destroy(key);
				break;
			}
			case AUTHZ_PSK:
			{
				shared_key_t *key = (shared_key_t*)item->value;
				key->destroy(key);
				break;
			}
			case AUTHN_CA_CERT:
			case AUTHN_IM_CERT:
			case AUTHN_SUBJECT_CERT:
			case AUTHZ_CA_CERT:
			case AUTHZ_IM_CERT:
			case AUTHZ_SUBJECT_CERT:
			{
				certificate_t *cert = (certificate_t*)item->value;
				cert->destroy(cert);
				break;
			}
			case AUTHZ_CRL_VALIDATION:
			case AUTHZ_OCSP_VALIDATION:
			case AUTHZ_EAP:
			{
				free(item->value);
				break;
			}
			case AUTHN_CA_CERT_KEYID:
			case AUTHN_CA_CERT_NAME:
			case AUTHZ_CA_CERT_NAME:
			case AUTHZ_AC_GROUP:
			{
				identification_t *id = (identification_t*)item->value;
				id->destroy(id);
				break;
			}
		}
		free(item);
	}
	this->items->destroy(this->items);
	free(this);
}

/*
 * see header file
 */
auth_info_t *auth_info_create()
{
	private_auth_info_t *this = malloc_thing(private_auth_info_t);
	
	this->public.add_item = (void(*)(auth_info_t*, auth_item_t type, void *value))add_item;
	this->public.get_item = (bool(*)(auth_info_t*, auth_item_t type, void **value))get_item;
	this->public.create_item_enumerator = (enumerator_t*(*)(auth_info_t*))create_item_enumerator;
	this->public.complies = (bool(*)(auth_info_t*, auth_info_t *))complies;
	this->public.merge = (void(*)(auth_info_t*, auth_info_t *other))merge;
	this->public.equals = (bool(*)(auth_info_t*, auth_info_t *other))equals;
	this->public.destroy = (void(*)(auth_info_t*))destroy;
	
	this->items = linked_list_create();
	
	return &this->public;
}

