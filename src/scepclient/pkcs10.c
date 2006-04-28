/**
 * @file pkcs10.c
 * @brief Functions to build PKCS#10 requests
 *
 * Contains functions to build DER encoded pkcs#10 certificate requests
 */

/* Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/oid.h"
#include "../pluto/asn1.h"
#include "../pluto/pkcs1.h"
#include "../pluto/log.h"
#include "../pluto/x509.h"

#include "pkcs10.h"

/* some pre-coded OIDs */

static u_char ASN1_challengePassword_oid_str[] = {
    0x06,0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07
};

static const chunk_t ASN1_challengePassword_oid = strchunk(ASN1_challengePassword_oid_str);

static u_char ASN1_extensionRequest_oid_str[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E
};

static const chunk_t ASN1_extensionRequest_oid = strchunk(ASN1_extensionRequest_oid_str);

/** 
 * @brief Adds a subjectAltName in DER-coded form to a linked list
 * 
 * @param[in,out]	subjectAltNames	head of the linked list of subjectAltNames
 * @param[in]		kind		type of the subjectAltName (which is a generalName)
 * @param[in]		value		value of the subjectAltName as an ASCII string
 */
void
pkcs10_add_subjectAltName(generalName_t **subjectAltNames, generalNames_t kind
, char *value) 
{
    generalName_t *gn;
    asn1_t asn1_type = ASN1_EOC;
    chunk_t name = { value, strlen(value) };

    switch (kind)
    {
    case GN_RFC822_NAME:
	asn1_type = ASN1_CONTEXT_S_1;
	break;
    case GN_DNS_NAME:
	asn1_type = ASN1_CONTEXT_S_2;
	break;
    case GN_IP_ADDRESS:
	{
	    struct in_addr addr;

	    /* convert an ASCII dotted IPv4 address (e.g. 123.456.78.90)
             * to a byte representation in network order
             */
	    if (!inet_aton(value, &addr))
	    {
		fprintf(stderr, "error in IPv4 subjectAltName\n");
		return;
	    }
	    asn1_type = ASN1_CONTEXT_S_7;
	    name.ptr = (u_char *) &addr.s_addr;
            name.len = sizeof(addr.s_addr);
	    break;
        }
    default:
	break;
    }

    gn = alloc_thing(generalName_t, "subjectAltName");
    gn->kind = kind;
    gn->name = asn1_simple_object(asn1_type, name);
    gn->next = *subjectAltNames;
    *subjectAltNames = gn;
}

/**
 * @brief Builds the requestInfoAttributes of the certificationRequestInfo-field 
 * 
 * challenge password ans subjectAltNames are only included,
 * when avaiable in given #pkcs10_t structure
 *
 * @param[in]	pkcs10		Pointer to a #pkcs10_t structure
 * @return					1 if succeeded, 0 otherwise
 */
static chunk_t
build_req_info_attributes(pkcs10_t* pkcs10)
{

    chunk_t subjectAltNames   = empty_chunk;
    chunk_t challengePassword = empty_chunk;

    if (pkcs10->subjectAltNames != NULL) 
    {

	subjectAltNames = asn1_wrap(ASN1_SEQUENCE, "cm"
		, ASN1_extensionRequest_oid
		, asn1_wrap(ASN1_SET, "m"
		    , asn1_wrap(ASN1_SEQUENCE, "m"
			, build_subjectAltNames(pkcs10->subjectAltNames)
		      )
		  )
	    );
    }

    if (pkcs10->challengePassword.len > 0)
    {
	asn1_t type = is_printablestring(pkcs10->challengePassword)
		      ? ASN1_PRINTABLESTRING : ASN1_T61STRING;

	challengePassword = asn1_wrap(ASN1_SEQUENCE, "cm"
		, ASN1_challengePassword_oid
		, asn1_wrap(ASN1_SET, "m"
		    , asn1_simple_object(type, pkcs10->challengePassword)
		  )
	    );
    }

    return asn1_wrap(ASN1_CONTEXT_C_0, "mm"
		, subjectAltNames
	    	, challengePassword);
}

/**
 * @brief Builds a DER-code pkcs#10 certificate request
 *
 * @param[in]	pkcs10		pointer to a pkcs10_t struct
 * @return 			DER-code pkcs10 request
 */
static chunk_t
pkcs10_build_request(pkcs10_t *pkcs10, int signature_alg)
{
    RSA_public_key_t *rsak = (RSA_public_key_t *) pkcs10->private_key;

    chunk_t cert_req_info = asn1_wrap(ASN1_SEQUENCE, "ccmm"
		, ASN1_INTEGER_0
		, pkcs10->subject
		, pkcs1_build_publicKeyInfo(rsak)
		, build_req_info_attributes(pkcs10));

    chunk_t signature = pkcs1_build_signature(cert_req_info
		, signature_alg, pkcs10->private_key, TRUE);

    return asn1_wrap(ASN1_SEQUENCE, "mcm"
		, cert_req_info
		, asn1_algorithmIdentifier(signature_alg)
		, signature);
}

/**
 * @brief Creates a pkcs#10 certificate request object
 *
 * To create a certificate request, the RSA key and the
 * names to be included as subject in the certificate request
 * (e.g. commonName, organization) are needed. An optional challenge
 * password or some subjectAltNames may be included.
 *
 * @param[in]	key			rsakey of type #rsakey_t
 * @param[in]	subject			DER-coded subject distinguished name
 * @param[in]	challengePassword	challenge password or empty_chunk
 * @param[in]	subjectAltNames		linked list of subjectAltNames or NULL
 * @return 				pointer to a #pkcs10_t object
 */
pkcs10_t*
pkcs10_build(RSA_private_key_t *key, chunk_t subject, chunk_t challengePassword
, generalName_t *subjectAltNames, int signature_alg)
{
    pkcs10_t *pkcs10 = alloc_thing(pkcs10_t, "pkcs10_t");

    pkcs10->subject = subject;
    pkcs10->private_key = key;
    pkcs10->challengePassword = challengePassword;
    pkcs10->subjectAltNames = subjectAltNames;

    pkcs10->request = pkcs10_build_request(pkcs10, signature_alg);
    return pkcs10;
}

/**
 * @brief Frees the resources used by an #pkcs10_t object
 *
 * @param[in]	pkcs10		#pkcs10_t to free
 */
void
pkcs10_free(pkcs10_t *pkcs10)
{
    if (pkcs10 != NULL)
    {
	freeanychunk(pkcs10->request);
	pfree(pkcs10);
    }
}
