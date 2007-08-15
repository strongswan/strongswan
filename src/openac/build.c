/* Build a X.509 attribute certificate
 * Copyright (C) 2002  Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2004  Andreas Steffen
 * Zuercher Hochschule Winterthur, Switzerland
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
 * RCSID $Id: build.c,v 1.14 2005/09/06 11:47:57 as Exp $
 */

#include <stdlib.h>
#include <string.h>

#include <freeswan.h>

#include <asn1/oid.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/asn1.h"
#include "../pluto/x509.h"
#include "../pluto/log.h"

#include "build.h"

static u_char ASN1_group_oid_str[] = {
	0x06, 0x08,
		  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0a ,0x04
};

static const chunk_t ASN1_group_oid = strchunk(ASN1_group_oid_str);

static u_char ASN1_authorityKeyIdentifier_oid_str[] = {
	0x06, 0x03,
		  0x55, 0x1d, 0x23
};

static const chunk_t ASN1_authorityKeyIdentifier_oid
	  = strchunk(ASN1_authorityKeyIdentifier_oid_str);

static u_char ASN1_noRevAvail_ext_str[] = {
	0x30, 0x09,
		  0x06, 0x03,
				0x55, 0x1d, 0x38,
		  0x04, 0x02,
				0x05, 0x00
};

static const chunk_t ASN1_noRevAvail_ext = strchunk(ASN1_noRevAvail_ext_str);

/**
 * build directoryName
 */
static chunk_t build_directoryName(asn1_t tag, chunk_t name)
{
	return asn1_wrap(tag, "m",
				asn1_simple_object(ASN1_CONTEXT_C_4, name));
}

/**
 * build holder
 */
static chunk_t build_holder(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
				asn1_wrap(ASN1_CONTEXT_C_0, "mm",
					build_directoryName(ASN1_SEQUENCE, user->issuer),
					asn1_simple_object(ASN1_INTEGER, user->serialNumber)
				),
				build_directoryName(ASN1_CONTEXT_C_1, user->subject));
}

/**
 * build v2Form
 */
static chunk_t build_v2_form(void)
{
	return asn1_wrap(ASN1_CONTEXT_C_0, "m",
				build_directoryName(ASN1_SEQUENCE, signer->subject));
}

/**
 * build attrCertValidityPeriod
 */
static chunk_t build_attr_cert_validity(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
				timetoasn1(&notBefore, ASN1_GENERALIZEDTIME),
				timetoasn1(&notAfter,  ASN1_GENERALIZEDTIME));
}

/**
 * build attributes
 */
static chunk_t build_ietfAttributes(ietfAttrList_t *list)
{
	chunk_t ietfAttributes;
	ietfAttrList_t *item = list;
	size_t size = 0;
	u_char *pos;

	/* precalculate the total size of all values */
	while (item != NULL)
	{
		size_t len = item->attr->value.len;

		size += 1 + (len > 0) + (len >= 128) + (len >= 256) + (len >= 65536) + len;
		item = item->next;
	}
	pos = build_asn1_object(&ietfAttributes, ASN1_SEQUENCE, size);

	while (list != NULL)
	{
		ietfAttr_t *attr = list->attr;
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
		mv_chunk(&pos, asn1_simple_object(type, attr->value));

		list = list->next;
	}

	return asn1_wrap(ASN1_SEQUENCE, "m", ietfAttributes);
}

/**
 * build attribute type
 */
static chunk_t build_attribute_type(const chunk_t type, chunk_t content)
{
	return asn1_wrap(ASN1_SEQUENCE, "cm",
				type,
				asn1_wrap(ASN1_SET, "m", content));
}

/**
 * build attributes
 */
static chunk_t build_attributes(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "m",
				build_attribute_type(ASN1_group_oid,
					build_ietfAttributes(groups)));
}

/**
 * build authorityKeyIdentifier
 */
static chunk_t build_authorityKeyID(x509cert_t *signer)
{
	chunk_t keyIdentifier = (signer->subjectKeyID.ptr == NULL)
				? empty_chunk
				: asn1_simple_object(ASN1_CONTEXT_S_0,
						signer->subjectKeyID);

	chunk_t authorityCertIssuer = build_directoryName(ASN1_CONTEXT_C_1,
						signer->issuer);

	chunk_t authorityCertSerialNumber = asn1_simple_object(ASN1_CONTEXT_S_2,
						signer->serialNumber);

	return asn1_wrap(ASN1_SEQUENCE, "cm",
				ASN1_authorityKeyIdentifier_oid,
				asn1_wrap(ASN1_OCTET_STRING, "m",
					asn1_wrap(ASN1_SEQUENCE, "mmm",
						keyIdentifier,
						authorityCertIssuer,
						authorityCertSerialNumber
					)
				)
		   );
}

/**
 * build extensions
 */
static chunk_t build_extensions(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "mc",
				build_authorityKeyID(signer),
				ASN1_noRevAvail_ext);
}

/**
 * build attributeCertificateInfo
 */
static chunk_t build_attr_cert_info(void)
{
	return asn1_wrap(ASN1_SEQUENCE, "cmmcmmmm",
				ASN1_INTEGER_1,
				build_holder(),
				build_v2_form(),
				ASN1_sha1WithRSA_id,
				asn1_simple_object(ASN1_INTEGER, serial),
				build_attr_cert_validity(),
				build_attributes(),
				build_extensions());
}

/**
 * build an X.509 attribute certificate
 */
chunk_t build_attr_cert(void)
{
	chunk_t attributeCertificateInfo = build_attr_cert_info();
	chunk_t signatureValue = pkcs1_build_signature(attributeCertificateInfo,
								OID_SHA1, signerkey, TRUE);

	return asn1_wrap(ASN1_SEQUENCE, "mcm",
				attributeCertificateInfo,
				ASN1_sha1WithRSA_id,
				signatureValue);
}
