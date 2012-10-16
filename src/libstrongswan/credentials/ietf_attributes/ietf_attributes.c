/*
 * Copyright (C) 2007-2009 Andreas Steffen
 *
 * HSR Hochschule fuer Technik Rapperswil
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

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <collections/linked_list.h>
#include <utils/lexparser.h>

#include "ietf_attributes.h"

/**
 * Private definition of IETF attribute types
 */
typedef enum {
	IETF_ATTRIBUTE_OCTETS =	0,
	IETF_ATTRIBUTE_OID =	1,
	IETF_ATTRIBUTE_STRING =	2
} ietf_attribute_type_t;

typedef struct ietf_attr_t ietf_attr_t;

/**
 * Private definition of an IETF attribute
 */
struct ietf_attr_t {
	/**
	 * IETF attribute type
	 */
	ietf_attribute_type_t type;

	/**
	 * IETF attribute value
	 */
	chunk_t value;

	/**
	 * Compares two IETF attributes
	 *
	 * return -1 if this is earlier in the alphabet than other
	 * return  0 if this equals other
	 * return +1 if this is later in the alphabet than other
	 *
	 * @param other		other object
	 */
	int (*compare) (ietf_attr_t *this, ietf_attr_t *other);

	/**
	 * Destroys an ietf_attr_t object.
	 */
	void (*destroy) (ietf_attr_t *this);
};

/**
 * Implements ietf_attr_t.compare.
 */
static int ietf_attr_compare(ietf_attr_t *this, ietf_attr_t *other)
{
	int cmp_len, len, cmp_value;

	/* OID attributes are appended after STRING and OCTETS attributes */
	if (this->type != IETF_ATTRIBUTE_OID && other->type == IETF_ATTRIBUTE_OID)
	{
		return -1;
	}
	if (this->type == IETF_ATTRIBUTE_OID && other->type != IETF_ATTRIBUTE_OID)
	{
		return 1;
	}

	cmp_len = this->value.len - other->value.len;
	len = (cmp_len < 0) ? this->value.len : other->value.len;
	cmp_value = memcmp(this->value.ptr, other->value.ptr, len);

	return (cmp_value == 0) ? cmp_len : cmp_value;
}

/**
 * Implements ietf_attr_t.destroy.
 */
static void ietf_attr_destroy(ietf_attr_t *this)
{
	free(this->value.ptr);
	free(this);
}

/**
 * Creates an ietf_attr_t object.
 */
static ietf_attr_t* ietf_attr_create(ietf_attribute_type_t type, chunk_t value)
{
	ietf_attr_t *this;

	INIT(this,
		.compare = ietf_attr_compare,
		.destroy = ietf_attr_destroy,
		.type = type,
		.value = chunk_clone(value),
	);

	return this;
}

typedef struct private_ietf_attributes_t private_ietf_attributes_t;

/**
 * Private data of an ietf_attributes_t object.
 */
struct private_ietf_attributes_t {
	/**
	 * Public interface.
	 */
	ietf_attributes_t public;

	/**
	 * Printable representation of the IETF attributes
	 */
	char *string;

	/**
	 * Linked list of IETF attributes.
	 */
	linked_list_t *list;

	/**
	 * reference count
	 */
	refcount_t ref;
};

METHOD(ietf_attributes_t, get_string, char*,
	private_ietf_attributes_t *this)
{
	if (this->string == NULL)
	{
		char buf[BUF_LEN];
		char *pos = buf;
		int len = BUF_LEN;
		bool first = TRUE;
		ietf_attr_t *attr;
		enumerator_t *enumerator;

		enumerator = this->list->create_enumerator(this->list);
		while (enumerator->enumerate(enumerator, &attr))
		{
			int written;

			if (first)
			{
				first = FALSE;
			}
			else
			{
				written = snprintf(pos, len, ", ");
				if (written < 0 || written >= len)
				{
					break;
				}
				pos += written;
				len -= written;
			}

			switch (attr->type)
			{
				case IETF_ATTRIBUTE_OCTETS:
				case IETF_ATTRIBUTE_STRING:
					written = snprintf(pos, len, "%.*s", (int)attr->value.len,
														 attr->value.ptr);
					break;
				case IETF_ATTRIBUTE_OID:
				{
					int oid = asn1_known_oid(attr->value);

					if (oid == OID_UNKNOWN)
					{
						written = snprintf(pos, len, "0x%#B", &attr->value);
					}
					else
					{
						written = snprintf(pos, len, "%s", oid_names[oid].name);
					}
					break;
				}
				default:
					written = 0;
					break;
			}
			if (written < 0 || written >= len)
			{
				break;
			}
			pos += written;
			len -= written;
		}
		enumerator->destroy(enumerator);
		if (len < BUF_LEN)
		{
			this->string = strdup(buf);
		}
	}
	return this->string;
}

METHOD(ietf_attributes_t, get_encoding, chunk_t,
	private_ietf_attributes_t *this)
{
	chunk_t values;
	size_t size = 0;
	u_char *pos;
	ietf_attr_t *attr;
	enumerator_t *enumerator;

	/* precalculate the total size of all values */
	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &attr))
	{
		size_t len = attr->value.len;

		size += 1 + (len > 0) + (len >= 128) + (len >= 256) + (len >= 65536) + len;
	}
	enumerator->destroy(enumerator);

	pos = asn1_build_object(&values, ASN1_SEQUENCE, size);

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &attr))
	{
		chunk_t ietfAttribute;
		asn1_t type = ASN1_NULL;

		switch (attr->type)
		{
			case IETF_ATTRIBUTE_OCTETS:
				type = ASN1_OCTET_STRING;
				break;
			case IETF_ATTRIBUTE_STRING:
				type = ASN1_UTF8STRING;
				break;
			case IETF_ATTRIBUTE_OID:
				type = ASN1_OID;
				break;
		}
		ietfAttribute = asn1_simple_object(type, attr->value);

		/* copy ietfAttribute into values chunk */
		memcpy(pos, ietfAttribute.ptr, ietfAttribute.len);
		pos += ietfAttribute.len;
		free(ietfAttribute.ptr);
	}
	enumerator->destroy(enumerator);

	return asn1_wrap(ASN1_SEQUENCE, "m", values);
}

/**
 * Implementation of ietf_attributes_t.equals.
 */
static bool equals(private_ietf_attributes_t *this,
				   private_ietf_attributes_t *other)
{
	 bool result = TRUE;

	/* lists must have the same number of attributes */
	if (other == NULL ||
		this->list->get_count(this->list) != other->list->get_count(other->list))
	{
		return FALSE;
	}

	/* compare two alphabetically-sorted lists */
	{
		ietf_attr_t *attr_a, *attr_b;
		enumerator_t *enum_a, *enum_b;

		enum_a = this->list->create_enumerator(this->list);
		enum_b = other->list->create_enumerator(other->list);
		while (enum_a->enumerate(enum_a, &attr_a) &&
			   enum_b->enumerate(enum_b, &attr_b))
		{
			if (attr_a->compare(attr_a, attr_b) != 0)
			{
				/* we have a mismatch */
				result = FALSE;
				break;
			}
		}
		enum_a->destroy(enum_a);
		enum_b->destroy(enum_b);
	}
	return result;
}

/**
 * Implementation of ietf_attributes_t.matches.
 */
static bool matches(private_ietf_attributes_t *this,
					private_ietf_attributes_t *other)
{
	bool result = FALSE;
	ietf_attr_t *attr_a, *attr_b;
	enumerator_t *enum_a, *enum_b;

	/* always match if this->list does not contain any attributes */
	if (this->list->get_count(this->list) == 0)
	{
		return TRUE;
	}

	/* never match if other->list does not contain any attributes */
	if (other == NULL || other->list->get_count(other->list) == 0)
	{
		return FALSE;
	}

	/* get first attribute from both lists */
	enum_a = this->list->create_enumerator(this->list);
	enum_a->enumerate(enum_a, &attr_a);
	enum_b = other->list->create_enumerator(other->list);
	enum_b->enumerate(enum_b, &attr_b);

	/* look for at least one common attribute */
	while (TRUE)
	{
		int cmp = attr_a->compare(attr_a, attr_b);

		if (cmp == 0)
		{
			/* we have a match */
			result = TRUE;
			break;
		}
		if (cmp == -1)
		{
			/* attr_a is earlier in the alphabet, get next attr_a */
			if (!enum_a->enumerate(enum_a, &attr_a))
			{
				/* we have reached the end of enum_a */
				break;
			}
		}
		else
		{
			/* attr_a is later in the alphabet, get next attr_b */
			if (!enum_b->enumerate(enum_b, &attr_b))
			{
				/* we have reached the end of enum_b */
				break;
			}
		}
	}
	enum_a->destroy(enum_a);
	enum_b->destroy(enum_b);

	return result;
}

METHOD(ietf_attributes_t, get_ref, ietf_attributes_t*,
	private_ietf_attributes_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(ietf_attributes_t, destroy, void,
	private_ietf_attributes_t *this)
{
	if (ref_put(&this->ref))
	{
		this->list->destroy_offset(this->list, offsetof(ietf_attr_t, destroy));
		free(this->string);
		free(this);
	}
}

static private_ietf_attributes_t* create_empty(void)
{
	private_ietf_attributes_t *this;

	INIT(this,
		.public = {
			.get_string = _get_string,
			.get_encoding = _get_encoding,
			.equals = (bool (*)(ietf_attributes_t*,ietf_attributes_t*))equals,
			.matches = (bool (*)(ietf_attributes_t*,ietf_attributes_t*))matches,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
		.ref = 1,
	);

	return this;
}

/**
 * Adds an ietf_attr_t object to a sorted linked list
 */
static void ietf_attributes_add(private_ietf_attributes_t *this,
								ietf_attr_t *attr)
{
	ietf_attr_t *current_attr;
	enumerator_t *enumerator;
	int cmp = -1;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, (void **)&current_attr) &&
		  (cmp = attr->compare(attr, current_attr)) > 0)
	{
		continue;
	}
	if (cmp == 0)
	{
		attr->destroy(attr);
	}
	else
	{	/* the enumerator either points to the end or to the attribute > attr */
		this->list->insert_before(this->list, enumerator, attr);
	}
	enumerator->destroy(enumerator);
}

/*
 * Described in header.
 */
ietf_attributes_t *ietf_attributes_create_from_string(char *string)
{
	private_ietf_attributes_t *this = create_empty();

	chunk_t line = { string, strlen(string) };

	while (eat_whitespace(&line))
	{
		chunk_t group;

		/* extract the next comma-separated group attribute */
		if (!extract_token(&group, ',', &line))
		{
			group = line;
			line.len = 0;
		}

		/* remove any trailing spaces */
		while (group.len > 0 && *(group.ptr + group.len - 1) == ' ')
		{
			group.len--;
		}

		/* add the group attribute to the list */
		if (group.len > 0)
		{
			ietf_attr_t *attr = ietf_attr_create(IETF_ATTRIBUTE_STRING, group);

			ietf_attributes_add(this, attr);
		}
	}

	return &(this->public);
}

/**
 * ASN.1 definition of ietfAttrSyntax
 */
static const asn1Object_t ietfAttrSyntaxObjects[] =
{
	{ 0, "ietfAttrSyntax",		ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "policyAuthority",	ASN1_CONTEXT_C_0,	ASN1_OPT |
													ASN1_BODY }, /*  1 */
	{ 1,   "end opt",			ASN1_EOC,			ASN1_END  }, /*  2 */
	{ 1,   "values",			ASN1_SEQUENCE,		ASN1_LOOP }, /*  3 */
	{ 2,     "octets",			ASN1_OCTET_STRING,	ASN1_OPT |
													ASN1_BODY }, /*  4 */
	{ 2,     "end choice",		ASN1_EOC,			ASN1_END  }, /*  5 */
	{ 2,     "oid",				ASN1_OID,			ASN1_OPT |
													ASN1_BODY }, /*  6 */
	{ 2,     "end choice",		ASN1_EOC,			ASN1_END  }, /*  7 */
	{ 2,     "string",			ASN1_UTF8STRING,	ASN1_OPT |
													ASN1_BODY }, /*  8 */
	{ 2,     "end choice",		ASN1_EOC,			ASN1_END  }, /*  9 */
	{ 1,   "end loop",			ASN1_EOC,			ASN1_END  }, /* 10 */
	{ 0, "exit",				ASN1_EOC,			ASN1_EXIT }
};
#define IETF_ATTR_OCTETS	 4
#define IETF_ATTR_OID		 6
#define IETF_ATTR_STRING	 8

/*
 * Described in header.
 */
ietf_attributes_t *ietf_attributes_create_from_encoding(chunk_t encoded)
{
	private_ietf_attributes_t *this = create_empty();
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;

	parser = asn1_parser_create(ietfAttrSyntaxObjects, encoded);
	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case IETF_ATTR_OCTETS:
			case IETF_ATTR_OID:
			case IETF_ATTR_STRING:
				{
					ietf_attribute_type_t type;
					ietf_attr_t *attr;

					type = (objectID - IETF_ATTR_OCTETS) / 2;
					attr = ietf_attr_create(type, object);
					ietf_attributes_add(this, attr);
				}
				break;
			default:
				break;
		}
	}
	parser->destroy(parser);

	return &(this->public);
}

