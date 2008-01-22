/* Build a X.509 attribute certificate
 * Copyright (C) 2002  Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2004,2007  Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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
 * RCSID $Id$
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <crypto/ietf_attr_list.h>
#include <utils/identification.h>

#include "build.h"

static u_char ASN1_group_oid_str[] = {
	0x06, 0x08,
		  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0a ,0x04
};

static const chunk_t ASN1_group_oid = chunk_from_buf(ASN1_group_oid_str);

static u_char ASN1_authorityKeyIdentifier_oid_str[] = {
	0x06, 0x03,
		  0x55, 0x1d, 0x23
};

static const chunk_t ASN1_authorityKeyIdentifier_oid =
	 			 	 	chunk_from_buf(ASN1_authorityKeyIdentifier_oid_str);

static u_char ASN1_noRevAvail_ext_str[] = {
	0x30, 0x09,
		  0x06, 0x03,
				0x55, 0x1d, 0x38,
		  0x04, 0x02,
				0x05, 0x00
};

static const chunk_t ASN1_noRevAvail_ext = chunk_from_buf(ASN1_noRevAvail_ext_str);

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
	identification_t *issuer = usercert->get_issuer(usercert);
	identification_t *subject = usercert->get_subject(usercert);

	return asn1_wrap(ASN1_SEQUENCE, "mm",
		asn1_wrap(ASN1_CONTEXT_C_0, "mm",
			build_directoryName(ASN1_SEQUENCE, issuer->get_encoding(issuer)),
			asn1_simple_object(ASN1_INTEGER, usercert->get_serialNumber(usercert))
		),
		build_directoryName(ASN1_CONTEXT_C_1, subject->get_encoding(subject)));
}

/**
 * build v2Form
 */
static chunk_t build_v2_form(void)
{
	identification_t *subject = signercert->get_subject(signercert);

	return asn1_wrap(ASN1_CONTEXT_C_0, "m",
		build_directoryName(ASN1_SEQUENCE, subject->get_encoding(subject)));
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
		build_attribute_type(ASN1_group_oid, ietfAttr_list_encode(groups)));
}

/**
 * build authorityKeyIdentifier
 */
static chunk_t build_authorityKeyID(x509_t *signer)
{
	identification_t *issuer = signer->get_issuer(signer);
	chunk_t subjectKeyID = signer->get_subjectKeyID(signer);

	chunk_t keyIdentifier = (subjectKeyID.ptr == NULL)
				? chunk_empty
				: asn1_simple_object(ASN1_CONTEXT_S_0, subjectKeyID);

	chunk_t authorityCertIssuer = build_directoryName(ASN1_CONTEXT_C_1,
				issuer->get_encoding(issuer));

	chunk_t authorityCertSerialNumber = asn1_simple_object(ASN1_CONTEXT_S_2,
				signer->get_serialNumber(signer));

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
				build_authorityKeyID(signercert),
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
				asn1_algorithmIdentifier(OID_SHA1_WITH_RSA),
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
	chunk_t signatureValue;
	chunk_t attributeCertificateInfo = build_attr_cert_info();

	signerkey->build_emsa_pkcs1_signature(signerkey, HASH_SHA1,
					 attributeCertificateInfo, &signatureValue);

	return asn1_wrap(ASN1_SEQUENCE, "mcm",
				attributeCertificateInfo,
				asn1_algorithmIdentifier(OID_SHA1_WITH_RSA),
				asn1_bitstring("m", signatureValue));
}
