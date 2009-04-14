/*
 * Copyright (C) 2007-2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
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

#include "auth_cfg.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <credentials/certificates/certificate.h>

ENUM(auth_rule_names, AUTH_RULE_IDENTITY, AUTH_HELPER_SUBJECT_HASH_URL,
	"RULE_IDENTITY",
	"RULE_AUTH_CLASS",
	"RULE_EAP_IDENTITY",
	"RULE_EAP_TYPE",
	"RULE_EAP_VENDOR",
	"RULE_CA_CERT",
	"RULE_IM_CERT",
	"RULE_SUBJECT_CERT",
	"RULE_CRL_VALIDATION",
	"RULE_OCSP_VALIDATION",
	"RULE_AC_GROUP",
	"HELPER_IM_CERT",
	"HELPER_SUBJECT_CERT",
	"HELPER_IM_HASH_URL",
	"HELPER_SUBJECT_HASH_URL",
);

typedef struct private_auth_cfg_t private_auth_cfg_t;

/**
 * private data of item_set
 */
struct private_auth_cfg_t {
	
	/**
	 * public functions
	 */
	auth_cfg_t public;
	
	/**
	 * list of entry_t
	 */
	linked_list_t *entries;
};

typedef struct entry_t entry_t;

struct entry_t {
	/** rule type */
	auth_rule_t type;
	/** associated value */
	void *value;
};

/**
 * enumerator for auth_cfg_t.create_enumerator()
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** inner enumerator from linked_list_t */
	enumerator_t *inner;
	/** current entry */
	entry_t *current;
} entry_enumerator_t;

/**
 * enumerate function for item_enumerator_t
 */
static bool enumerate(entry_enumerator_t *this, auth_rule_t *type, void **value)
{
	entry_t *entry;
	
	if (this->inner->enumerate(this->inner, &entry))
	{
		this->current = entry;
		*type = entry->type;
		*value = entry->value;
		return TRUE;
	}
	return FALSE;
}

/**
 * destroy function for item_enumerator_t
 */
static void entry_enumerator_destroy(entry_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of auth_cfg_t.create_enumerator.
 */
static enumerator_t* create_enumerator(private_auth_cfg_t *this)
{
	entry_enumerator_t *enumerator;
	
	enumerator = malloc_thing(entry_enumerator_t);
	enumerator->inner = this->entries->create_enumerator(this->entries);
	enumerator->public.enumerate = (void*)enumerate;
	enumerator->public.destroy = (void*)entry_enumerator_destroy;
	enumerator->current = NULL;
	return &enumerator->public;
}

/**
 * Destroy the value associated with an entry
 */
static void destroy_entry_value(entry_t *entry)
{
	switch (entry->type)
	{
		case AUTH_RULE_IDENTITY:
		case AUTH_RULE_EAP_IDENTITY:
		case AUTH_RULE_AC_GROUP:
		{
			identification_t *id = (identification_t*)entry->value;
			id->destroy(id);
			break;
		}
		case AUTH_RULE_CA_CERT:
		case AUTH_RULE_IM_CERT:
		case AUTH_RULE_SUBJECT_CERT:
		case AUTH_HELPER_IM_CERT:
		case AUTH_HELPER_SUBJECT_CERT:
		{
			certificate_t *cert = (certificate_t*)entry->value;
			cert->destroy(cert);
			break;
		}
		case AUTH_HELPER_IM_HASH_URL:
		case AUTH_HELPER_SUBJECT_HASH_URL:
		{
			free(entry->value);
			break;
		}
		case AUTH_RULE_AUTH_CLASS:
		case AUTH_RULE_EAP_TYPE:
		case AUTH_RULE_EAP_VENDOR:
		case AUTH_RULE_CRL_VALIDATION:
		case AUTH_RULE_OCSP_VALIDATION:
			break;
	}
}

/**
 * Implementation of auth_cfg_t.replace.
 */
static void replace(auth_cfg_t *this, entry_enumerator_t *enumerator,
					auth_rule_t type, ...)
{
	if (enumerator->current)
	{
		va_list args;
		
		va_start(args, type);
		
		destroy_entry_value(enumerator->current);
		enumerator->current->type = type;
		switch (type)
		{
			case AUTH_RULE_AUTH_CLASS:
			case AUTH_RULE_EAP_TYPE:
			case AUTH_RULE_EAP_VENDOR:
			case AUTH_RULE_CRL_VALIDATION:
			case AUTH_RULE_OCSP_VALIDATION:
				/* integer type */
				enumerator->current->value = (void*)va_arg(args, u_int);
				break;
			case AUTH_RULE_IDENTITY:
			case AUTH_RULE_EAP_IDENTITY:
			case AUTH_RULE_AC_GROUP:
			case AUTH_RULE_CA_CERT:
			case AUTH_RULE_IM_CERT:
			case AUTH_RULE_SUBJECT_CERT:
			case AUTH_HELPER_IM_CERT:
			case AUTH_HELPER_SUBJECT_CERT:
			case AUTH_HELPER_IM_HASH_URL:
			case AUTH_HELPER_SUBJECT_HASH_URL:
				/* pointer type */
				enumerator->current->value = va_arg(args, void*);
				break;
		}
		va_end(args);
	}
}

/**
 * Implementation of auth_cfg_t.get.
 */
static void* get(private_auth_cfg_t *this, auth_rule_t type)
{
	enumerator_t *enumerator;
	void *current_value, *best_value = NULL;
	auth_rule_t current_type;
	bool found = FALSE;
	
	enumerator = create_enumerator(this);
	while (enumerator->enumerate(enumerator, &current_type, &current_value))
	{
		if (type == current_type)
		{
			if (type == AUTH_RULE_CRL_VALIDATION ||
				type == AUTH_RULE_OCSP_VALIDATION)
			{	/* for CRL/OCSP validation, always get() the highest value */
				if (!found || current_value > best_value)
				{
					best_value = current_value;
				}
				found = TRUE;
				continue;
			}
			best_value = current_value;
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (found)
	{
		return best_value;
	}
	switch (type)
	{
		/* use some sane defaults if we don't find an entry */
		case AUTH_RULE_AUTH_CLASS:
			return (void*)AUTH_CLASS_ANY;
		case AUTH_RULE_EAP_TYPE:
			return (void*)EAP_NAK;
		case AUTH_RULE_EAP_VENDOR:
			return (void*)0;
		case AUTH_RULE_CRL_VALIDATION:
		case AUTH_RULE_OCSP_VALIDATION:
			return (void*)VALIDATION_FAILED;
		case AUTH_RULE_IDENTITY:
		case AUTH_RULE_EAP_IDENTITY:
		case AUTH_RULE_AC_GROUP:
		case AUTH_RULE_CA_CERT:
		case AUTH_RULE_IM_CERT:
		case AUTH_RULE_SUBJECT_CERT:
		case AUTH_HELPER_IM_CERT:
		case AUTH_HELPER_SUBJECT_CERT:
		case AUTH_HELPER_IM_HASH_URL:
		case AUTH_HELPER_SUBJECT_HASH_URL:
		default:
			return NULL;
	}
}

/**
 * Implementation of auth_cfg_t.add.
 */
static void add(private_auth_cfg_t *this, auth_rule_t type, ...)
{
	entry_t *entry = malloc_thing(entry_t);
	va_list args;
	
	va_start(args, type);
	entry->type = type;
	switch (type)
	{
		case AUTH_RULE_AUTH_CLASS:
		case AUTH_RULE_EAP_TYPE:
		case AUTH_RULE_EAP_VENDOR:
		case AUTH_RULE_CRL_VALIDATION:
		case AUTH_RULE_OCSP_VALIDATION:
			/* integer type */
			entry->value = (void*)va_arg(args, u_int);
			break;
		case AUTH_RULE_IDENTITY:
		case AUTH_RULE_EAP_IDENTITY:
		case AUTH_RULE_AC_GROUP:
		case AUTH_RULE_CA_CERT:
		case AUTH_RULE_IM_CERT:
		case AUTH_RULE_SUBJECT_CERT:
		case AUTH_HELPER_IM_CERT:
		case AUTH_HELPER_SUBJECT_CERT:
		case AUTH_HELPER_IM_HASH_URL:
		case AUTH_HELPER_SUBJECT_HASH_URL:
			/* pointer type */
			entry->value = va_arg(args, void*);
			break;
	}
	va_end(args);
	this->entries->insert_last(this->entries, entry);
}

/**
 * Implementation of auth_cfg_t.complies.
 */
static bool complies(private_auth_cfg_t *this, auth_cfg_t *constraints,
					 bool log_error)
{
	enumerator_t *e1, *e2;
	bool success = TRUE;
	auth_rule_t t1, t2;
	void *value;
	
	e1 = constraints->create_enumerator(constraints);
	while (e1->enumerate(e1, &t1, &value))
	{
		switch (t1)
		{
			case AUTH_RULE_CA_CERT:
			case AUTH_RULE_IM_CERT:
			{
				certificate_t *c1, *c2;
				
				c1 = (certificate_t*)value;
				
				success = FALSE;
				e2 = create_enumerator(this);
				while (e2->enumerate(e2, &t2, &c2))
				{
					if ((t2 == AUTH_RULE_CA_CERT || t2 == AUTH_RULE_IM_CERT) &&
						c1->equals(c1, c2))
					{
						success = TRUE;
					}
				}
				e2->destroy(e2);
				if (!success && log_error)
				{
					DBG1(DBG_CFG, "constraint check failed: peer not "
						 "authenticated by CA '%D'.", c1->get_subject(c1));
				}
				break;
			}
			case AUTH_RULE_SUBJECT_CERT:
			{
				certificate_t *c1, *c2;
				
				c1 = (certificate_t*)value;
				c2 = get(this, AUTH_RULE_SUBJECT_CERT);
				if (!c2 || !c1->equals(c1, c2))
				{
					success = FALSE;
					if (log_error)
					{
						DBG1(DBG_CFG, "constraint check failed: peer not "
							 "authenticated with peer cert '%D'.",
							 c1->get_subject(c1));
					}
				}
				break;
			}
			case AUTH_RULE_CRL_VALIDATION:
			case AUTH_RULE_OCSP_VALIDATION:
			{
				cert_validation_t validated, required;
				
				required = (uintptr_t)value;
				validated = (uintptr_t)get(this, t1);
				switch (required)
				{
					case VALIDATION_FAILED:
						/* no constraint */
						break;
					case VALIDATION_SKIPPED:
						if (validated == VALIDATION_SKIPPED)
						{
							break;
						}
						/* FALL */
					case VALIDATION_GOOD:
						if (validated == VALIDATION_GOOD)
						{
							break;
						}
						/* FALL */
					default:
						success = FALSE;
						if (log_error)
						{
							DBG1(DBG_CFG, "constraint check failed: %N is %N, "
								 "but requires at least %N", auth_rule_names,
								 t1, cert_validation_names, validated,
								 cert_validation_names, required);
						}
						break;
				}
				break;
			}
			case AUTH_RULE_IDENTITY:
			case AUTH_RULE_EAP_IDENTITY:
			{
				identification_t *id1, *id2;
				
				id1 = (identification_t*)value;
				id2 = get(this, t1);
				if (!id2 || !id2->matches(id2, id1))
				{
					success = FALSE;
					if (log_error)
					{
						DBG1(DBG_CFG, "constraint check failed: %sidentity '%D'"
							 " required ", t1 == AUTH_RULE_IDENTITY ? "" :
							 "EAP ", id1);
					}
				}
				break;
			}
			case AUTH_RULE_AUTH_CLASS:
			{
				if ((uintptr_t)value != AUTH_CLASS_ANY &&
					(uintptr_t)value != (uintptr_t)get(this, t1))
				{
					success = FALSE;
					if (log_error)
					{
						DBG1(DBG_CFG, "constraint requires %N authentication, "
							 "but %N was used", auth_class_names, (uintptr_t)value,
							 auth_class_names, (uintptr_t)get(this, t1));
					}
				}
				break;
			}
			case AUTH_RULE_EAP_TYPE:
			{
				if ((uintptr_t)value != (uintptr_t)get(this, t1))
				{
					success = FALSE;
					if (log_error)
					{
						DBG1(DBG_CFG, "constraint requires %N, "
							 "but %N was used", eap_type_names, (uintptr_t)value,
							 eap_type_names,  (uintptr_t)get(this, t1));
					}
				}
				break;
			}
			case AUTH_RULE_EAP_VENDOR:
			{
				if ((uintptr_t)value != (uintptr_t)get(this, t1))
				{
					success = FALSE;
					if (log_error)
					{
						DBG1(DBG_CFG, "constraint requires EAP vendor %d, "
							 "but %d was used", (uintptr_t)value,
							 (uintptr_t)get(this, t1));
					}
				}
				break;
			}
			case AUTH_RULE_AC_GROUP:
			{
				success = FALSE;
				if (log_error)
				{
					DBG1(DBG_CFG, "constraint check %N not implemented!",
						 auth_rule_names, t1);
				}
				break;
			}
			case AUTH_HELPER_IM_CERT:
			case AUTH_HELPER_SUBJECT_CERT:
			case AUTH_HELPER_IM_HASH_URL:
			case AUTH_HELPER_SUBJECT_HASH_URL:
				/* skip helpers */
				continue;
		}
		if (!success)
		{
			break;
		}
	}
	e1->destroy(e1);
	return success;
}

/**
 * Implementation of auth_cfg_t.merge.
 */
static void merge(private_auth_cfg_t *this, private_auth_cfg_t *other, bool copy)
{
	if (!other)
	{	/* nothing to merge */
		return;
	}
	if (copy)
	{
		enumerator_t *enumerator;
		auth_rule_t type;
		void *value;
		
		enumerator = create_enumerator(other);
		while (enumerator->enumerate(enumerator, &type, &value))
		{
			switch (type)
			{
				case AUTH_RULE_CA_CERT:
				case AUTH_RULE_IM_CERT:
				case AUTH_RULE_SUBJECT_CERT:
				case AUTH_HELPER_IM_CERT:
				case AUTH_HELPER_SUBJECT_CERT:
				{
					certificate_t *cert = (certificate_t*)value;
					
					add(this, type, cert->get_ref(cert));
					break;
				}
				case AUTH_RULE_CRL_VALIDATION:
				case AUTH_RULE_OCSP_VALIDATION:
				case AUTH_RULE_AUTH_CLASS:
				case AUTH_RULE_EAP_TYPE:
				case AUTH_RULE_EAP_VENDOR:
				{
					add(this, type, (uintptr_t)value);
					break;
				}
				case AUTH_RULE_IDENTITY:
				case AUTH_RULE_EAP_IDENTITY:
				case AUTH_RULE_AC_GROUP:
				{
					identification_t *id = (identification_t*)value;
					
					add(this, type, id->clone(id));
					break;
				}
				case AUTH_HELPER_IM_HASH_URL:
				case AUTH_HELPER_SUBJECT_HASH_URL:
				{
					add(this, type, strdup((char*)value));
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		entry_t *entry;
		
		while (other->entries->remove_first(other->entries,
											(void**)&entry) == SUCCESS)
		{
			this->entries->insert_last(this->entries, entry);
		}
	}
}

/**
 * Implementation of auth_cfg_t.equals.
 */
static bool equals(private_auth_cfg_t *this, private_auth_cfg_t *other)
{
	enumerator_t *e1, *e2;
	entry_t *i1, *i2;
	bool equal = TRUE, found;
	
	if (this->entries->get_count(this->entries) !=
		other->entries->get_count(other->entries))
	{
		return FALSE;
	}
	e1 = this->entries->create_enumerator(this->entries);
	while (e1->enumerate(e1, &i1))
	{
		found = FALSE;
		e2 = other->entries->create_enumerator(other->entries);
		while (e2->enumerate(e2, &i2))
		{
			if (i1->type == i2->type)
			{
				switch (i1->type)
				{
					case AUTH_RULE_AUTH_CLASS:
					case AUTH_RULE_EAP_TYPE:
					case AUTH_RULE_EAP_VENDOR:
					case AUTH_RULE_CRL_VALIDATION:
					case AUTH_RULE_OCSP_VALIDATION:
					{
						if (i1->value == i2->value)
						{
							found = TRUE;
							break;
						}
						continue;
					}
					case AUTH_RULE_CA_CERT:
					case AUTH_RULE_IM_CERT:
					case AUTH_RULE_SUBJECT_CERT:
					case AUTH_HELPER_IM_CERT:
					case AUTH_HELPER_SUBJECT_CERT:
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
					case AUTH_RULE_IDENTITY:
					case AUTH_RULE_EAP_IDENTITY:
					case AUTH_RULE_AC_GROUP:
					{
						identification_t *id1, *id2;
						
						id1 = (identification_t*)i1->value;
						id2 = (identification_t*)i2->value;
						
						if (id1->equals(id1, id2))
						{
							found = TRUE;
							break;
						}
						continue;
					}
					case AUTH_HELPER_IM_HASH_URL:
					case AUTH_HELPER_SUBJECT_HASH_URL:
					{
						if (streq(i1->value, i2->value))
						{
							found = TRUE;
							break;
						}
						continue;
					}
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
 * Implementation of auth_cfg_t.purge
 */
static void purge(private_auth_cfg_t *this, bool keep_ca)
{
	entry_t *entry;
	linked_list_t *cas;
	
	cas = linked_list_create();
	while (this->entries->remove_last(this->entries, (void**)&entry) == SUCCESS)
	{
		if (keep_ca && entry->type == AUTH_RULE_CA_CERT)
		{
			cas->insert_first(cas, entry);
		}
		else
		{
			destroy_entry_value(entry);
			free(entry);
		}
	}
	while (cas->remove_last(cas, (void**)&entry) == SUCCESS)
	{
		this->entries->insert_first(this->entries, entry);
	}
	cas->destroy(cas);
}

/**
 * Implementation of auth_cfg_t.clone
 */
static auth_cfg_t* clone_(private_auth_cfg_t *this)
{
	enumerator_t *enumerator;
	auth_cfg_t *clone;
	entry_t *entry;
	
	clone = auth_cfg_create();
	enumerator = this->entries->create_enumerator(this->entries);
	while (enumerator->enumerate(enumerator, &entry))
	{
		switch (entry->type)
		{
			case AUTH_RULE_IDENTITY:
			case AUTH_RULE_EAP_IDENTITY:
			case AUTH_RULE_AC_GROUP:
			{
				identification_t *id = (identification_t*)entry->value;
				clone->add(clone, entry->type, id->clone(id));
				break;
			}
			case AUTH_RULE_CA_CERT:
			case AUTH_RULE_IM_CERT:
			case AUTH_RULE_SUBJECT_CERT:
			case AUTH_HELPER_IM_CERT:
			case AUTH_HELPER_SUBJECT_CERT:
			{
				certificate_t *cert = (certificate_t*)entry->value;
				clone->add(clone, entry->type, cert->get_ref(cert));
				break;
			}
			case AUTH_HELPER_IM_HASH_URL:
			case AUTH_HELPER_SUBJECT_HASH_URL:
			{
				clone->add(clone, entry->type, strdup(entry->value));
				break;
			}
			case AUTH_RULE_AUTH_CLASS:
			case AUTH_RULE_EAP_TYPE:
			case AUTH_RULE_EAP_VENDOR:
			case AUTH_RULE_CRL_VALIDATION:
			case AUTH_RULE_OCSP_VALIDATION:
				clone->add(clone, entry->type, (uintptr_t)entry->value);
				break;
		}
	}
	enumerator->destroy(enumerator);
	return clone;
}

/**
 * Implementation of auth_cfg_t.destroy
 */
static void destroy(private_auth_cfg_t *this)
{
	purge(this, FALSE);
	this->entries->destroy(this->entries);
	free(this);
}

/*
 * see header file
 */
auth_cfg_t *auth_cfg_create()
{
	private_auth_cfg_t *this = malloc_thing(private_auth_cfg_t);
	
	this->public.add = (void(*)(auth_cfg_t*, auth_rule_t type, ...))add;
	this->public.get = (void*(*)(auth_cfg_t*, auth_rule_t type))get;
	this->public.create_enumerator = (enumerator_t*(*)(auth_cfg_t*))create_enumerator;
	this->public.replace = (void(*)(auth_cfg_t*,enumerator_t*,auth_rule_t,...))replace;
	this->public.complies = (bool(*)(auth_cfg_t*, auth_cfg_t *,bool))complies;
	this->public.merge = (void(*)(auth_cfg_t*, auth_cfg_t *other,bool))merge;
	this->public.purge = (void(*)(auth_cfg_t*,bool))purge;
	this->public.equals = (bool(*)(auth_cfg_t*, auth_cfg_t *other))equals;
	this->public.clone = (auth_cfg_t*(*)(auth_cfg_t*))clone_;
	this->public.destroy = (void(*)(auth_cfg_t*))destroy;
	
	this->entries = linked_list_create();
	
	return &this->public;
}

