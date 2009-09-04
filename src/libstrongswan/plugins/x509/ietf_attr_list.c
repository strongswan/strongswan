/*
 * Copyright (C) 2007 Andreas Steffen, Hochschule fuer Technik Rapperswil
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

#include <string.h>
#include <stdio.h>

#include <debug.h>
#include <library.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <utils/lexparser.h>

#include "ietf_attr_list.h"

/**
 * Private definition of ietfAttribute kinds
 */
typedef enum {
	IETF_ATTRIBUTE_OCTETS =	0,
	IETF_ATTRIBUTE_OID =	1,
	IETF_ATTRIBUTE_STRING =	2
} ietfAttribute_t;

typedef struct ietfAttr_t ietfAttr_t;

/**
 * Private definition of an ietfAttribute
 */
struct ietfAttr_t {
	/**
	 * IETF attribute kind
	 */
	ietfAttribute_t kind;

	/**
	 * IETF attribute valuse
	 */
	chunk_t value;

	/**
	 * Compares two ietfAttributes
	 *
	 * return -1 if this is earlier in the alphabet than other
	 * return  0 if this equals other
	 * return +1 if this is later in the alphabet than other
	 *
	 * @param this		calling object
	 * @param other		other object
	 */
	int (*compare) (const ietfAttr_t *this ,const ietfAttr_t *other);

	/**
	 * Destroys the ietfAttr_t object.
	 *
	 * @param this			ietfAttr_t to destroy
	 */
	void (*destroy) (ietfAttr_t *this);
};

/**
 * Implements ietfAttr_t.compare.
 */
static int ietfAttr_compare(const ietfAttr_t *this ,const ietfAttr_t *other)
{
	int cmp_len, len, cmp_value;

	/* OID attributes are appended after STRING and OCTETS attributes */
	if (this->kind != IETF_ATTRIBUTE_OID && other->kind == IETF_ATTRIBUTE_OID)
	{
		return -1;
	}
	if (this->kind == IETF_ATTRIBUTE_OID && other->kind != IETF_ATTRIBUTE_OID)
	{
		return 1;
	}

	cmp_len = this->value.len - other->value.len;
	len = (cmp_len < 0)? this->value.len : other->value.len;
	cmp_value = memcmp(this->value.ptr, other->value.ptr, len);

	return (cmp_value == 0)? cmp_len : cmp_value;
}

/**
 * Implements ietfAttr_t.destroy.
 */
static void ietfAttr_destroy(ietfAttr_t *this)
{
	free(this->value.ptr);
	free(this);
}

/**
 * Creates an ietfAttr_t object.
 */
static ietfAttr_t *ietfAttr_create(ietfAttribute_t kind, chunk_t value)
{
	ietfAttr_t *this = malloc_thing(ietfAttr_t);

	/* initialize */
	this->kind = kind;
	this->value = chunk_clone(value);

	/* function */
	this->compare = ietfAttr_compare;
	this->destroy = ietfAttr_destroy;

	return this;
}

/**
 * Adds an ietfAttr_t object to a sorted linked list
 */
static void ietfAttr_add(linked_list_t *list, ietfAttr_t *attr)
{
	iterator_t *iterator = list->create_iterator(list, TRUE);
	ietfAttr_t *current_attr;
	bool found = FALSE;

	while (iterator->iterate(iterator, (void **)&current_attr))
	{
		int cmp = attr->compare(attr, current_attr);

		if (cmp > 0)
		{
			 continue;
		}
		if (cmp == 0)
		{
			attr->destroy(attr);
		}
		else
		{
			iterator->insert_before(iterator, attr);
		}
		found = TRUE;
		break;
	}
	iterator->destroy(iterator);
	if (!found)
	{
		list->insert_last(list, attr);
	}
}

/*
 * Described in header.
 */
bool ietfAttr_list_equals(linked_list_t *list_a, linked_list_t *list_b)
{
	 bool result = TRUE;

	/* lists must have the same number of attributes */
	if (list_a->get_count(list_a) != list_b->get_count(list_b))
	{
		return FALSE;
	}
	/* empty lists - no attributes */
	if (list_a->get_count(list_a) == 0)
	{
		return TRUE;
	}

	/* compare two alphabetically-sorted lists */
	{
		iterator_t *iterator_a = list_a->create_iterator(list_a, TRUE);
		iterator_t *iterator_b = list_b->create_iterator(list_b, TRUE);
		ietfAttr_t *attr_a, *attr_b;

		while (iterator_a->iterate(iterator_a, (void **)&attr_a) &&
			   iterator_b->iterate(iterator_b, (void **)&attr_b))
		{
			if (attr_a->compare(attr_a, attr_b) != 0)
			{
				/* we have a mismatch */
				result = FALSE;
				break;
			}
		}
		iterator_a->destroy(iterator_a);
		iterator_b->destroy(iterator_b);
	}
	return result;
}

/*
 * Described in header.
 */
void ietfAttr_list_list(linked_list_t *list, FILE *out)
{
	iterator_t *iterator = list->create_iterator(list, TRUE);
	ietfAttr_t *attr;
	bool first = TRUE;

	while (iterator->iterate(iterator, (void **)&attr))
	{
		if (first)
		{
			first = FALSE;
		}
		else
		{
			fprintf(out, ", ");
		}

		switch (attr->kind)
		{
			case IETF_ATTRIBUTE_OCTETS:
			case IETF_ATTRIBUTE_STRING:
				fprintf(out, "%.*s", (int)attr->value.len, attr->value.ptr);
				break;
			case IETF_ATTRIBUTE_OID:
				{
					int oid = asn1_known_oid(attr->value);

					if (oid == OID_UNKNOWN)
					{
						fprintf(out, "0x#B", &attr->value);
					}
					else
					{
						fprintf(out, "%s", oid_names[oid]);
					}
				}
				break;
			default:
				break;
		}
	}
	iterator->destroy(iterator);
}

/*
 * Described in header.
 */
void ietfAttr_list_create_from_string(char *msg, linked_list_t *list)
{
	chunk_t line = { msg, strlen(msg) };

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
			ietfAttr_t *attr = ietfAttr_create(IETF_ATTRIBUTE_STRING, group);

			ietfAttr_add(list, attr);
		}
	}
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
void ietfAttr_list_create_from_chunk(chunk_t chunk, linked_list_t *list, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;

	parser = asn1_parser_create(ietfAttrSyntaxObjects, chunk);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case IETF_ATTR_OCTETS:
			case IETF_ATTR_OID:
			case IETF_ATTR_STRING:
				{
					ietfAttribute_t kind = (objectID - IETF_ATTR_OCTETS) / 2;
					ietfAttr_t *attr   = ietfAttr_create(kind, object);
					ietfAttr_add(list, attr);
				}
				break;
			default:
				break;
		}
	}
	parser->destroy(parser);
}

/*
 * Described in header.
 */
chunk_t ietfAttr_list_encode(linked_list_t *list)
{
	chunk_t ietfAttributes;
	size_t size = 0;
	u_char *pos;
	iterator_t *iterator = list->create_iterator(list, TRUE);
	ietfAttr_t *attr;

	/* precalculate the total size of all values */
	while (iterator->iterate(iterator, (void **)&attr))
	{
		size_t len = attr->value.len;

		size += 1 + (len > 0) + (len >= 128) + (len >= 256) + (len >= 65536) + len;
	}
	iterator->destroy(iterator);

	pos = asn1_build_object(&ietfAttributes, ASN1_SEQUENCE, size);

	iterator = list->create_iterator(list, TRUE);
	while (iterator->iterate(iterator, (void **)&attr))
	{
		chunk_t ietfAttribute;
		asn1_t type = ASN1_NULL;

		switch (attr->kind)
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

		/* copy ietfAttribute into ietfAttributes chunk */
		memcpy(pos, ietfAttribute.ptr, ietfAttribute.len);
		pos += ietfAttribute.len;
		free(ietfAttribute.ptr);
	}
	iterator->destroy(iterator);

	return asn1_wrap(ASN1_SEQUENCE, "m", ietfAttributes);
}

/*
 * Described in header.
 */
void ietfAttr_list_destroy(linked_list_t *list)
{
	list->destroy_offset(list, offsetof(ietfAttr_t, destroy));
}
