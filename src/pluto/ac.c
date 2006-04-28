/* Support of X.509 attribute certificates
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
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
 * RCSID $Id: ac.c,v 1.12 2005/12/06 22:49:32 as Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "asn1.h"
#include "oid.h"
#include "ac.h"
#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certs.h"
#include "log.h"
#include "whack.h"
#include "fetch.h"

/* chained list of X.509 attribute certificates */

static x509acert_t *x509acerts   = NULL;

/* chained list of ietfAttributes */

static ietfAttrList_t *ietfAttributes = NULL;

/* ASN.1 definition of ietfAttrSyntax */

static const asn1Object_t ietfAttrSyntaxObjects[] =
{
  { 0, "ietfAttrSyntax",		ASN1_SEQUENCE,        ASN1_NONE }, /*  0 */
  { 1,   "policyAuthority",		ASN1_CONTEXT_C_0,     ASN1_OPT |
							      ASN1_BODY }, /*  1 */
  { 1,   "end opt",			ASN1_EOC,             ASN1_END  }, /*  2 */
  { 1,   "values",			ASN1_SEQUENCE,        ASN1_LOOP }, /*  3 */
  { 2,     "octets",			ASN1_OCTET_STRING,    ASN1_OPT |
							      ASN1_BODY }, /*  4 */
  { 2,     "end choice",		ASN1_EOC,             ASN1_END  }, /*  5 */
  { 2,     "oid",			ASN1_OID,	      ASN1_OPT |
							      ASN1_BODY }, /*  6 */
  { 2,     "end choice",		ASN1_EOC,             ASN1_END  }, /*  7 */
  { 2,     "string",			ASN1_UTF8STRING,      ASN1_OPT |
							      ASN1_BODY }, /*  8 */
  { 2,     "end choice",		ASN1_EOC,             ASN1_END  }, /*  9 */
  { 1,   "end loop",			ASN1_EOC,	      ASN1_END  }  /* 10 */
};

#define IETF_ATTR_OCTETS	 4
#define IETF_ATTR_OID		 6
#define IETF_ATTR_STRING	 8
#define IETF_ATTR_ROOF		11

/* ASN.1 definition of roleSyntax */

static const asn1Object_t roleSyntaxObjects[] =
{
  { 0, "roleSyntax",			ASN1_SEQUENCE,        ASN1_NONE }, /*  0 */
  { 1,   "roleAuthority",		ASN1_CONTEXT_C_0,     ASN1_OPT |
							      ASN1_OBJ  }, /*  1 */
  { 1,   "end opt",			ASN1_EOC,             ASN1_END  }, /*  2 */
  { 1,   "roleName",			ASN1_CONTEXT_C_1,     ASN1_OBJ  }  /*  3 */
};

#define ROLE_ROOF		4

/* ASN.1 definition of an X509 attribute certificate */

static const asn1Object_t acObjects[] =
{
  { 0, "AttributeCertificate",		ASN1_SEQUENCE,        ASN1_OBJ  }, /*  0 */
  { 1,   "AttributeCertificateInfo",    ASN1_SEQUENCE,        ASN1_OBJ  }, /*  1 */
  { 2,	   "version",			ASN1_INTEGER,	      ASN1_DEF |
							      ASN1_BODY }, /*  2 */
  { 2,	   "holder",                    ASN1_SEQUENCE,	      ASN1_NONE }, /*  3 */
  { 3,	     "baseCertificateID",	ASN1_CONTEXT_C_0,     ASN1_OPT  }, /*  4 */
  { 4,	       "issuer",		ASN1_SEQUENCE,	      ASN1_OBJ  }, /*  5 */
  { 4,	       "serial",		ASN1_INTEGER,	      ASN1_BODY }, /*  6 */
  { 4,         "issuerUID",		ASN1_BIT_STRING,      ASN1_OPT |
                                                              ASN1_BODY }, /*  7 */
  { 4,         "end opt",		ASN1_EOC,             ASN1_END  }, /*  8 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /*  9 */
  { 3,	     "entityName",		ASN1_CONTEXT_C_1,     ASN1_OPT |
							      ASN1_OBJ  }, /* 10 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 11 */
  { 3,	     "objectDigestInfo",	ASN1_CONTEXT_C_2,     ASN1_OPT  }, /* 12 */
  { 4,	       "digestedObjectType",	ASN1_ENUMERATED,      ASN1_BODY }, /* 13*/
  { 4,	       "otherObjectTypeID",	ASN1_OID,    	      ASN1_OPT |
							      ASN1_BODY }, /* 14 */
  { 4,         "end opt",		ASN1_EOC,             ASN1_END  }, /* 15*/
  { 4,         "digestAlgorithm",	ASN1_EOC,             ASN1_RAW  }, /* 16 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 17 */
  { 2,	   "v2Form",			ASN1_CONTEXT_C_0,     ASN1_NONE }, /* 18 */
  { 3,	     "issuerName",		ASN1_SEQUENCE,        ASN1_OPT |
                                                              ASN1_OBJ  }, /* 19 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 20 */
  { 3,	     "baseCertificateID",	ASN1_CONTEXT_C_0,     ASN1_OPT  }, /* 21 */
  { 4,	       "issuerSerial",		ASN1_SEQUENCE,        ASN1_NONE }, /* 22 */
  { 5,	         "issuer",		ASN1_SEQUENCE,	      ASN1_OBJ  }, /* 23 */
  { 5,	  	 "serial",		ASN1_INTEGER,	      ASN1_BODY }, /* 24 */
  { 5,           "issuerUID",		ASN1_BIT_STRING,      ASN1_OPT |
                                                              ASN1_BODY }, /* 25 */
  { 5,           "end opt",		ASN1_EOC,             ASN1_END  }, /* 26 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 27 */
  { 3,       "objectDigestInfo",	ASN1_CONTEXT_C_1,     ASN1_OPT  }, /* 28 */
  { 4,	       "digestInfo",		ASN1_SEQUENCE,        ASN1_OBJ  }, /* 29 */
  { 5,  	 "digestedObjectType",	ASN1_ENUMERATED,      ASN1_BODY }, /* 30 */
  { 5,	  	 "otherObjectTypeID",	ASN1_OID,    	      ASN1_OPT |
							      ASN1_BODY }, /* 31 */
  { 5,           "end opt",		ASN1_EOC,             ASN1_END  }, /* 32 */
  { 5,           "digestAlgorithm",	ASN1_EOC,             ASN1_RAW  }, /* 33 */
  { 3,       "end opt",			ASN1_EOC,             ASN1_END  }, /* 34 */
  { 2,	   "signature",                 ASN1_EOC,             ASN1_RAW  }, /* 35 */
  { 2,	   "serialNumber",              ASN1_INTEGER,         ASN1_BODY }, /* 36 */
  { 2,	   "attrCertValidityPeriod",    ASN1_SEQUENCE,        ASN1_NONE }, /* 37 */
  { 3,	     "notBeforeTime",           ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 38 */
  { 3,	     "notAfterTime",            ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 39 */
  { 2,	   "attributes",                ASN1_SEQUENCE,        ASN1_LOOP }, /* 40 */
  { 3,       "attribute",		ASN1_SEQUENCE,        ASN1_NONE }, /* 41 */
  { 4,         "type",			ASN1_OID,             ASN1_BODY }, /* 42 */
  { 4,         "values",		ASN1_SET, 	      ASN1_LOOP }, /* 43 */
  { 5,           "value",		ASN1_EOC, 	      ASN1_RAW  }, /* 44 */
  { 4, 	       "end loop",		ASN1_EOC,	      ASN1_END  }, /* 45 */
  { 2,     "end loop",			ASN1_EOC,             ASN1_END  }, /* 46 */
  { 2,     "extensions",		ASN1_SEQUENCE,        ASN1_LOOP }, /* 47 */
  { 3,       "extension",		ASN1_SEQUENCE,        ASN1_NONE }, /* 48 */
  { 4,         "extnID",		ASN1_OID,             ASN1_BODY }, /* 49 */
  { 4,         "critical",		ASN1_BOOLEAN,         ASN1_DEF |
							      ASN1_BODY }, /* 50 */
  { 4,         "extnValue",		ASN1_OCTET_STRING,    ASN1_BODY }, /* 51 */
  { 2,     "end loop",			ASN1_EOC,             ASN1_END  }, /* 52 */
  { 1,   "signatureAlgorithm",		ASN1_EOC,             ASN1_RAW  }, /* 53 */
  { 1,   "signatureValue",		ASN1_BIT_STRING,      ASN1_BODY }  /* 54 */
};

#define AC_OBJ_CERTIFICATE		 0
#define AC_OBJ_CERTIFICATE_INFO		 1
#define AC_OBJ_VERSION			 2
#define AC_OBJ_HOLDER_ISSUER		 5
#define AC_OBJ_HOLDER_SERIAL		 6
#define AC_OBJ_ENTITY_NAME		10
#define AC_OBJ_ISSUER_NAME		19
#define AC_OBJ_ISSUER			23
#define AC_OBJ_SIG_ALG			35
#define AC_OBJ_SERIAL_NUMBER		36
#define AC_OBJ_NOT_BEFORE		38
#define AC_OBJ_NOT_AFTER		39
#define AC_OBJ_ATTRIBUTE_TYPE		42
#define AC_OBJ_ATTRIBUTE_VALUE		44
#define AC_OBJ_EXTN_ID			49
#define AC_OBJ_CRITICAL			50
#define AC_OBJ_EXTN_VALUE		51
#define AC_OBJ_ALGORITHM		53
#define AC_OBJ_SIGNATURE		54
#define AC_OBJ_ROOF			55

const x509acert_t empty_ac = {
      NULL     , /* *next */
            0  , /* installed */
    { NULL, 0 }, /* certificate */
    { NULL, 0 }, /*   certificateInfo */
            1  , /*     version */
		 /*     holder */
		 /*       baseCertificateID */
    { NULL, 0 }, /*         holderIssuer */
    { NULL, 0 }, /*         holderSerial */
		 /*       entityName */
    { NULL, 0 }, /*         generalNames */
		 /*     v2Form */
    { NULL, 0 }, /*       issuerName */
                 /*     signature */
    OID_UNKNOWN, /*       sigAlg */
    { NULL, 0 }, /*     serialNumber */
                 /*     attrCertValidityPeriod */
            0  , /*       notBefore */
            0  , /*       notAfter */
		 /*     attributes */
      NULL     , /*       charging */
      NULL     , /*       groups */
		 /*     extensions */
    { NULL, 0 }, /*       authKeyID */
    { NULL, 0 }, /*       authKeySerialNumber */
      FALSE    , /*       noRevAvail */
		 /*   signatureAlgorithm */
    OID_UNKNOWN, /*     algorithm */
    { NULL, 0 }, /*   signature */
};


/*  compare two ietfAttributes, returns zero if a equals b
 *  negative/positive if a is earlier/later in the alphabet than b
 */
static int
cmp_ietfAttr(ietfAttr_t *a,ietfAttr_t *b)
{
    int cmp_len, len, cmp_value;

    /* cannot compare OID with STRING or OCTETS attributes */
    if (a->kind == IETF_ATTRIBUTE_OID && b->kind != IETF_ATTRIBUTE_OID)
	return 1;
	
    cmp_len = a->value.len - b->value.len;
    len = (cmp_len < 0)? a->value.len : b->value.len;
    cmp_value = memcmp(a->value.ptr, b->value.ptr, len);

    return (cmp_value == 0)? cmp_len : cmp_value;
}

/*
 *  add an ietfAttribute to the chained list
 */
static ietfAttr_t*
add_ietfAttr(ietfAttr_t *attr)
{
    ietfAttrList_t **listp = &ietfAttributes;
    ietfAttrList_t *list = *listp;
    int cmp = -1;

    while (list != NULL)
    {
	cmp = cmp_ietfAttr(attr, list->attr);
	if (cmp <= 0)
	    break;
	listp = &list->next;
	list = *listp;
    }

    if (cmp == 0)
    {
	/* attribute already exists, increase count */
	pfree(attr);
	list->attr->count++;
	return list->attr;
    }
    else
    {
	ietfAttrList_t *el = alloc_thing(ietfAttrList_t, "ietfAttrList");

	/* new attribute, unshare value */
	attr->value.ptr = clone_bytes(attr->value.ptr, attr->value.len
	    , "attr value");
	attr->count = 1;
	time(&attr->installed);

	el->attr = attr;
	el->next = list;
	*listp = el;

	return attr;
    }
}

/*
 * decodes a comma separated list of group attributes
 */
void
decode_groups(char *groups, ietfAttrList_t **listp)
{
    if (groups == NULL)
	return;

    while (strlen(groups) > 0)
    {
	char *end;
	char *next = strchr(groups, ',');

	if (next == NULL)
	   end = next = groups + strlen(groups);
	else
	   end = next++;

	/* eat preceeding whitespace */
	while (groups < end && *groups == ' ')
	    groups++;

	/* eat trailing whitespace */
	while (end > groups && *(end-1) == ' ')
	    end--;

	if (groups < end)
	{
	    ietfAttr_t *attr   = alloc_thing(ietfAttr_t, "ietfAttr");
	    ietfAttrList_t *el = alloc_thing(ietfAttrList_t, "ietfAttrList");

	    attr->kind  = IETF_ATTRIBUTE_STRING;
	    attr->value.ptr = groups;
	    attr->value.len = end - groups;
	    attr->count = 0;

	    el->attr = add_ietfAttr(attr);
	    el->next = *listp;
	    *listp = el;
	}

	groups = next;
    }
}

static bool
same_attribute(const ietfAttr_t *a, const ietfAttr_t *b)
{
    return (a->kind == b->kind && a->value.len == b->value.len
	   && memcmp(a->value.ptr, b->value.ptr, b->value.len) == 0);
}

bool
group_membership(const ietfAttrList_t *peer_list
	       , const char *conn
	       , const ietfAttrList_t *conn_list)
{
    if (conn_list == NULL)
	return TRUE;

    while (peer_list != NULL)
    {
	const ietfAttr_t *peer_attr = peer_list->attr;
	const ietfAttrList_t *list = conn_list;

	while (list != NULL)
	{
	    ietfAttr_t *conn_attr = list->attr;

	    if (same_attribute(conn_attr, peer_attr))
	    {
		DBG(DBG_CONTROL,
		    DBG_log("%s: peer matches group '%.*s'"
			, conn
			, (int)peer_attr->value.len, peer_attr->value.ptr)
		)
		return TRUE;
	    }
	    list = list->next;
	}
	peer_list = peer_list->next;
    }
	DBG(DBG_CONTROL,
	    DBG_log("%s: peer doesn't match any group", conn)
	)
    return FALSE;
}


void
unshare_ietfAttrList(ietfAttrList_t **listp)
{
    ietfAttrList_t *list = *listp;

    while (list != NULL)
    {
	ietfAttrList_t *el = alloc_thing(ietfAttrList_t, "ietfAttrList");

	el->attr = list->attr;
	el->attr->count++;
	el->next = NULL;
	*listp = el;
	listp = &el->next;
	list = list->next;
    }
}

/*
 * parses ietfAttrSyntax
 */
static ietfAttrList_t*
parse_ietfAttrSyntax(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    ietfAttrList_t *list = NULL;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < IETF_ATTR_ROOF)
    {
	if (!extract_object(ietfAttrSyntaxObjects, &objectID, &object, &level, &ctx))
	     return NULL;

	switch (objectID)
	{
	case IETF_ATTR_OCTETS:
	case IETF_ATTR_OID:
	case IETF_ATTR_STRING:
	    {
		ietfAttr_t *attr   = alloc_thing(ietfAttr_t, "ietfAttr");
		ietfAttrList_t *el = alloc_thing(ietfAttrList_t, "ietfAttrList");

		attr->kind  = (objectID - IETF_ATTR_OCTETS) / 2;
		attr->value = object;
		attr->count = 0;

		el->attr = add_ietfAttr(attr);
		el->next = list;
		list = el;
	    }
	    break;
	default:
	    break;
	}
	objectID++;
    }
    return list;
}
/*
 * parses roleSyntax
 */
static void
parse_roleSyntax(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < ROLE_ROOF)
    {
	if (!extract_object(roleSyntaxObjects, &objectID, &object, &level, &ctx))
	     return;

	switch (objectID) {
	default:
	    break;
	}
	objectID++;
    }
}

/*
 *  Parses an X.509 attribute certificate
 */
bool
parse_ac(chunk_t blob, x509acert_t *ac)
{
    asn1_ctx_t ctx;
    bool critical;
    chunk_t object;
    u_int level;
    u_int type = OID_UNKNOWN;
    u_int extn_oid = OID_UNKNOWN;
    int objectID = 0;

    asn1_init(&ctx, blob, 0, FALSE, DBG_RAW);

    while (objectID < AC_OBJ_ROOF) {

	if (!extract_object(acObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	/* those objects which will parsed further need the next higher level */
	level++;

	switch (objectID)
	{
	case AC_OBJ_CERTIFICATE:
	    ac->certificate = object;
	    break;
	case AC_OBJ_CERTIFICATE_INFO:
	    ac->certificateInfo = object;
	    break;
	case AC_OBJ_VERSION:
	    ac->version = (object.len) ? (1 + (u_int)*object.ptr) : 1;
	    DBG(DBG_PARSING,
		DBG_log("  v%d", ac->version);
	    )
	    if (ac->version != 2)
	    {
		plog("v%d attribute certificates are not supported"
		    , ac->version);
		return FALSE;
	    }
	    break;
	case AC_OBJ_HOLDER_ISSUER:
	    ac->holderIssuer = get_directoryName(object, level, FALSE);
	    break;
	case AC_OBJ_HOLDER_SERIAL:
	    ac->holderSerial = object;
	    break;
	case AC_OBJ_ENTITY_NAME:
	    ac->entityName = get_directoryName(object, level, TRUE);
	    break;
	case AC_OBJ_ISSUER_NAME:
	    ac->issuerName = get_directoryName(object, level, FALSE);
	    break;
	case AC_OBJ_SIG_ALG:
	    ac->sigAlg = parse_algorithmIdentifier(object, level, NULL);
	    break;
	case AC_OBJ_SERIAL_NUMBER:
	    ac->serialNumber = object;
	    break;
	case AC_OBJ_NOT_BEFORE:
	    ac->notBefore = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case AC_OBJ_NOT_AFTER:
	    ac->notAfter = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case AC_OBJ_ATTRIBUTE_TYPE:
	    type = known_oid(object);
	    break;
	case AC_OBJ_ATTRIBUTE_VALUE:
	    {
		switch (type) {
		case OID_AUTHENTICATION_INFO:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse authenticationInfo")
		    )
		    break;
		case OID_ACCESS_IDENTITY:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse accessIdentity")
		    )
		    break;
		case OID_CHARGING_IDENTITY:
		    ac->charging = parse_ietfAttrSyntax(object, level);
		    break;
		case OID_GROUP:
		    ac->groups = parse_ietfAttrSyntax(object, level);
		    break;
		case OID_ROLE:
		    parse_roleSyntax(object, level);
		    break;
		default:
		    break;
		}
	    }
	    break;
	case AC_OBJ_EXTN_ID:
	    extn_oid = known_oid(object);
	    break;
	case AC_OBJ_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case AC_OBJ_EXTN_VALUE:
	    {
		switch (extn_oid) {
		case OID_CRL_DISTRIBUTION_POINTS:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse crlDistributionPoints")
		    )
		    break;
		case OID_AUTHORITY_KEY_ID:
		    parse_authorityKeyIdentifier(object, level
			, &ac->authKeyID, &ac->authKeySerialNumber);
		    break;
		case OID_TARGET_INFORMATION:
		    DBG(DBG_PARSING,
			DBG_log("  need to parse targetInformation")
		    )
		    break;
		case OID_NO_REV_AVAIL:
		    ac->noRevAvail = TRUE;
		    break;
		default:
		    break;
		}
	    }
	    break;
	case AC_OBJ_ALGORITHM:
	    ac->algorithm = parse_algorithmIdentifier(object, level, NULL);
	    break;
	case AC_OBJ_SIGNATURE:
	    ac->signature = object;
	    break;

	default:
	    break;
	}
	objectID++;
    }
    time(&ac->installed);
    return TRUE;
}

/*
 *  compare two X.509 attribute certificates by comparing their signatures
 */
static bool
same_x509acert(x509acert_t *a, x509acert_t *b)
{
    return a->signature.len == b->signature.len &&
	memcmp(a->signature.ptr, b->signature.ptr, b->signature.len) == 0;
}

/*
 *  release an ietfAttribute, free it if count reaches zero
 */
static void
release_ietfAttr(ietfAttr_t* attr)
{
    if (--attr->count == 0)
    {
	ietfAttrList_t **plist = &ietfAttributes;
	ietfAttrList_t *list = *plist;

	while (list->attr != attr)
	{
	    plist = &list->next;
	    list = *plist;
	}
        *plist = list->next;
	
	pfree(attr->value.ptr);
	pfree(attr);
	pfree(list);
    }
}

/*
 *  free an ietfAttrList
 */
void
free_ietfAttrList(ietfAttrList_t* list)
{
    while (list != NULL)
    {
	ietfAttrList_t *el = list;

	release_ietfAttr(el->attr);
	list = list->next;
	pfree(el);
    }
}

/*
 *  free a X.509 attribute certificate
 */
void
free_acert(x509acert_t *ac)
{
    if (ac != NULL)
    {
	free_ietfAttrList(ac->charging);
	free_ietfAttrList(ac->groups);
	pfreeany(ac->certificate.ptr);
	pfree(ac);
    }
}

/*
 *  free first X.509 attribute certificate in the chained list
 */
static void
free_first_acert(void)
{
    x509acert_t *first = x509acerts;
    x509acerts = first->next;
    free_acert(first);
}

/*
 * Free all attribute certificates in the chained list
 */
void
free_acerts(void)
{
    while (x509acerts != NULL)
	free_first_acert();
}

/*
 *  get a X.509 attribute certificate for a given holder
 */
x509acert_t*
get_x509acert(chunk_t issuer, chunk_t serial)
{
    x509acert_t *ac = x509acerts;
    x509acert_t *prev_ac = NULL;

    while (ac != NULL)
    {
	if (same_dn(issuer, ac->holderIssuer)
	&&  same_serial(serial, ac->holderSerial))
	{
	    if (ac!= x509acerts)
	    {
		/* bring the certificate up front */
		prev_ac->next = ac->next;
		ac->next = x509acerts;
		x509acerts = ac;
	    }
	    return ac;
	}
	prev_ac = ac;
	ac = ac->next;
    }
    return NULL;
}

/*
 *  add a X.509 attribute certificate to the chained list
 */
static void
add_acert(x509acert_t *ac)
{
    x509acert_t *old_ac = get_x509acert(ac->holderIssuer, ac->holderSerial);

    if (old_ac != NULL)
    {
	if (ac->notBefore >old_ac->notBefore)
	{
	    /* delete the old attribute cert */
	    free_first_acert();
	    DBG(DBG_CONTROL,
		DBG_log("attribute cert is newer - existing cert deleted")
	    )
	}
	else
	{
	    DBG(DBG_CONTROL,
		DBG_log("attribute cert is not newer - existing cert kept");
	    )
	    free_acert(ac);
	    return;
	}
    }
    plog("attribute cert added");

    /* insert new attribute cert at the root of the chain */
    ac->next = x509acerts;
    x509acerts = ac;
}

/* verify the validity of an attribute certificate by
 * checking the notBefore and notAfter dates
 */
static err_t
check_ac_validity(const x509acert_t *ac)
{
    time_t current_time;

    time(&current_time);
    DBG(DBG_CONTROL | DBG_PARSING,
	DBG_log("  not before  : %s", timetoa(&ac->notBefore, TRUE));
	DBG_log("  current time: %s", timetoa(&current_time, TRUE));
	DBG_log("  not after   : %s", timetoa(&ac->notAfter, TRUE));
    )

    if (current_time < ac->notBefore)
	return "attribute certificate is not valid yet";
    if (current_time > ac->notAfter)
	return "attribute certificate has expired";
    else
	return NULL;
}

/*
 * verifies a X.509 attribute certificate
 */
bool
verify_x509acert(x509acert_t *ac, bool strict)
{
    u_char buf[BUF_LEN];
    x509cert_t *aacert;
    err_t ugh = NULL;
    time_t valid_until = ac->notAfter;

    DBG(DBG_CONTROL,
	dntoa(buf, BUF_LEN, ac->entityName);
	DBG_log("holder: '%s'",buf);
	dntoa(buf, BUF_LEN, ac->issuerName);
	DBG_log("issuer: '%s'",buf);
    )
    
    ugh = check_ac_validity(ac);

    if (ugh != NULL)
    {
	plog("%s", ugh);
	return FALSE;
    }
    DBG(DBG_CONTROL,
	DBG_log("attribute certificate is valid")
    )

    lock_authcert_list("verify_x509acert");
    aacert = get_authcert(ac->issuerName, ac->authKeySerialNumber
	, ac->authKeyID, AUTH_AA);
    unlock_authcert_list("verify_x509acert");

    if (aacert == NULL)
    {
	plog("issuer aacert not found");
	return FALSE;
    }
    DBG(DBG_CONTROL,
	DBG_log("issuer aacert found")
    )

    if (!check_signature(ac->certificateInfo, ac->signature
			 , ac->algorithm, ac->algorithm, aacert))
    {
	plog("attribute certificate signature is invalid");
	return FALSE;
    }
    DBG(DBG_CONTROL,
	DBG_log("attribute certificate signature is valid");
    )

    return verify_x509cert(aacert, strict, &valid_until);
}

/*
 * Loads X.509 attribute certificates
 */
void
load_acerts(void)
{
    u_char buf[BUF_LEN];

    /* change directory to specified path */
    u_char *save_dir = getcwd(buf, BUF_LEN);

    if (!chdir(A_CERT_PATH))
    {
	struct dirent **filelist;
	int n;

	plog("Changing to directory '%s'",A_CERT_PATH);
	n = scandir(A_CERT_PATH, &filelist, file_select, alphasort);

	if (n > 0)
	{
	    while (n--)
	    {
		chunk_t blob = empty_chunk;
		bool pgp = FALSE;

		if (load_coded_file(filelist[n]->d_name, NULL, "acert", &blob, &pgp))
		{
		    x509acert_t *ac = alloc_thing(x509acert_t, "x509acert");
		    
		    *ac = empty_ac;

		    if (parse_ac(blob, ac)
		    && verify_x509acert(ac, FALSE))
			add_acert(ac);
		    else
			free_acert(ac);
		}
		free(filelist[n]);
	    }
	    free(filelist);
	}
    }
    /* restore directory path */
    chdir(save_dir);
}

/*
 * lists group attributes separated by commas on a single line
 */
void
format_groups(const ietfAttrList_t *list, char *buf, int len)
{
    bool first_group = TRUE;

    while (list != NULL && len > 0)
    {
	ietfAttr_t *attr = list->attr;

	if (attr->kind == IETF_ATTRIBUTE_OCTETS
	||  attr->kind == IETF_ATTRIBUTE_STRING)
	{
	    int written = snprintf(buf, len, "%s%.*s"
			    , (first_group)? "" : ", "
			    , (int)attr->value.len, attr->value.ptr);

	    first_group = FALSE;
	    
	    /* return value of snprintf() up to glibc 2.0.6 */
	    if (written < 0)
		break;

	    buf += written;
	    len -= written;
	}
	list = list->next;
    }
}

/*
 *  list all X.509 attribute certificates in the chained list
 */
void
list_acerts(bool utc)
{
    x509acert_t *ac = x509acerts;
    time_t now;

    /* determine the current time */
    time(&now);

    if (ac != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 Attribute Certificates:");
	whack_log(RC_COMMENT, " ");
    }

    while (ac != NULL)
    {
	u_char buf[BUF_LEN];

	whack_log(RC_COMMENT, "%s",timetoa(&ac->installed, utc));
	if (ac->entityName.ptr != NULL)
	{
	    dntoa(buf, BUF_LEN, ac->entityName);
	    whack_log(RC_COMMENT, "       holder:   '%s'", buf);
	}
	if (ac->holderIssuer.ptr != NULL)
	{
	    dntoa(buf, BUF_LEN, ac->holderIssuer);
	    whack_log(RC_COMMENT, "       hissuer:  '%s'", buf);
	}
	if (ac->holderSerial.ptr != NULL)
	{
	    datatot(ac->holderSerial.ptr, ac->holderSerial.len, ':'
		, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       hserial:   %s", buf);
	}
	if (ac->groups != NULL)
	{
	    format_groups(ac->groups, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       groups:    %s", buf);
	}
	dntoa(buf, BUF_LEN, ac->issuerName);
	whack_log(RC_COMMENT, "       issuer:   '%s'", buf);
	datatot(ac->serialNumber.ptr, ac->serialNumber.len, ':'
	    , buf, BUF_LEN);
	whack_log(RC_COMMENT, "       serial:    %s", buf);
	whack_log(RC_COMMENT, "       validity:  not before %s %s",
		timetoa(&ac->notBefore, utc),
		(ac->notBefore < now)?"ok":"fatal (not valid yet)");
	whack_log(RC_COMMENT, "                  not after  %s %s",
		timetoa(&ac->notAfter, utc),
		check_expiry(ac->notAfter, ACERT_WARNING_INTERVAL, TRUE));
	if (ac->authKeyID.ptr != NULL)
	{
	    datatot(ac->authKeyID.ptr, ac->authKeyID.len, ':'
		, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       authkey:   %s", buf);
	}
	if (ac->authKeySerialNumber.ptr != NULL)
	{
	    datatot(ac->authKeySerialNumber.ptr, ac->authKeySerialNumber.len, ':'
		, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       aserial:   %s", buf);
	}

	ac = ac->next;
    }
}

/*
 *  list all group attributes in alphabetical order
 */
void
list_groups(bool utc)
{
    ietfAttrList_t *list = ietfAttributes;
    
    if (list != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of Group Attributes:");
	whack_log(RC_COMMENT, " ");
    }

    while (list != NULL)
    {
	ietfAttr_t *attr = list->attr;

	whack_log(RC_COMMENT, "%s, count: %d", timetoa(&attr->installed, utc),
		attr->count);
	
	switch (attr->kind)
	{
	case IETF_ATTRIBUTE_OCTETS:
	case IETF_ATTRIBUTE_STRING:
	    whack_log(RC_COMMENT, "       %.*s", (int)attr->value.len, attr->value.ptr);
	    break;
	case IETF_ATTRIBUTE_OID:
	    whack_log(RC_COMMENT, "       OID");
	    break;
	default:
	    break;
        }

	list = list->next;
    }
}
