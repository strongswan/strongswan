/*
 * Copyright (C) 2026 Andrei-Alexandru Bleortu
 *
 * Copyright (C) secunet Security Networks AG
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

#include "test_suite.h"

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <credentials/certificates/crl.h>

#define IDP_URI "http://crl.strongswan.org/test.crl"

/**
 * Build a CRL carrying the given critical issuingDistributionPoint value (or
 * none, if empty).  Parsing does not verify the signature, so it is a dummy.
 */
static chunk_t build_crl(chunk_t idp)
{
	identification_t *issuer;
	chunk_t extensions = chunk_empty, tbs;
	time_t this_update = 1767225600, next_update = this_update + 86400;

	issuer = identification_create_from_string("CN=CRL Test CA");
	if (idp.len)
	{
		extensions = asn1_wrap(ASN1_CONTEXT_C_0, "m",
						asn1_wrap(ASN1_SEQUENCE, "m",
							asn1_wrap(ASN1_SEQUENCE, "mcm",
								asn1_build_known_oid(OID_ISSUING_DIST_POINT),
								chunk_from_chars(ASN1_BOOLEAN, 0x01, 0xff),
								asn1_wrap(ASN1_OCTET_STRING, "c", idp))));
	}
	tbs = asn1_wrap(ASN1_SEQUENCE, "cmcmmm",
					chunk_from_chars(ASN1_INTEGER, 0x01, 0x01),
					asn1_algorithmIdentifier(OID_SHA256_WITH_RSA),
					issuer->get_encoding(issuer),
					asn1_from_time(&this_update, ASN1_UTCTIME),
					asn1_from_time(&next_update, ASN1_UTCTIME),
					extensions);
	issuer->destroy(issuer);

	return asn1_wrap(ASN1_SEQUENCE, "mmc", tbs,
					 asn1_algorithmIdentifier(OID_SHA256_WITH_RSA),
					 chunk_from_chars(ASN1_BIT_STRING, 0x02, 0x00, 0x00));
}

/**
 * The distributionPoint field naming IDP_URI as its fullName
 */
static chunk_t build_dp_fullname()
{
	return asn1_wrap(ASN1_CONTEXT_C_0, "m",
				asn1_wrap(ASN1_CONTEXT_C_0, "m",
					asn1_wrap(ASN1_CONTEXT_S_6, "c",
							  chunk_from_str(IDP_URI))));
}

typedef struct {
	/** description of the case */
	char *name;
	/** the IDP fields following the distributionPoint, DER encoded */
	chunk_t scope;
	/** whether the distributionPoint field names IDP_URI */
	bool fullname;
	/** whether an IDP extension is added at all */
	bool idp;
	/** whether the CRL is expected to parse */
	bool accepted;
} idp_test_t;

static idp_test_t idp_tests[] = {
	{ "no issuingDistributionPoint", { NULL, 0 }, FALSE, FALSE, TRUE },
	{ "full scope with a distribution point", { NULL, 0 }, TRUE, TRUE, TRUE },
	{ "full scope without a distribution point", { NULL, 0 }, FALSE, TRUE, TRUE },
	{ "explicitly encoded DEFAULT FALSE",
	  chunk_from_chars(0x81, 0x01, 0x00), TRUE, TRUE, TRUE },
	{ "onlyContainsUserCerts",
	  chunk_from_chars(0x81, 0x01, 0xff), TRUE, TRUE, FALSE },
	{ "onlyContainsCACerts",
	  chunk_from_chars(0x82, 0x01, 0xff), TRUE, TRUE, FALSE },
	{ "onlySomeReasons",
	  chunk_from_chars(0x83, 0x02, 0x06, 0x40), TRUE, TRUE, FALSE },
	{ "indirectCRL",
	  chunk_from_chars(0x84, 0x01, 0xff), TRUE, TRUE, FALSE },
	{ "onlyContainsAttributeCerts",
	  chunk_from_chars(0x85, 0x01, 0xff), TRUE, TRUE, FALSE },
};

START_TEST(test_parse_idp)
{
	idp_test_t *t = &idp_tests[_i];
	certificate_t *cert;
	enumerator_t *enumerator;
	chunk_t idp = chunk_empty, encoding;
	char *uri;
	int count = 0;

	if (t->idp)
	{
		idp = asn1_wrap(ASN1_SEQUENCE, "mc",
						t->fullname ? build_dp_fullname() : chunk_empty,
						t->scope);
	}
	encoding = build_crl(idp);
	chunk_free(&idp);

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL,
							  BUILD_BLOB_ASN1_DER, encoding, BUILD_END);
	chunk_free(&encoding);

	if (!t->accepted)
	{
		ck_assert_msg(!cert, "CRL with %s accepted", t->name);
		return;
	}
	ck_assert_msg(cert, "CRL with %s rejected", t->name);

	enumerator = ((crl_t*)cert)->create_idp_uri_enumerator((crl_t*)cert);
	while (enumerator->enumerate(enumerator, &uri))
	{
		ck_assert_str_eq(uri, IDP_URI);
		count++;
	}
	enumerator->destroy(enumerator);
	ck_assert_int_eq(count, t->fullname ? 1 : 0);
	cert->destroy(cert);
}
END_TEST

START_TEST(test_parse_idp_relative_name)
{
	certificate_t *cert;
	chunk_t encoding;

	/* distributionPoint [0] { nameRelativeToCRLIssuer [1] { CN=crl } } */
	encoding = build_crl(chunk_from_chars(
						0x30, 0x10, 0xa0, 0x0e, 0xa1, 0x0c,
						0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03,
						0x0c, 0x03, 0x63, 0x72, 0x6c));
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL,
							  BUILD_BLOB_ASN1_DER, encoding, BUILD_END);
	chunk_free(&encoding);
	ck_assert_msg(!cert, "CRL with nameRelativeToCRLIssuer accepted");
}
END_TEST

Suite *crl_idp_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("crl_idp");

	tc = tcase_create("parse issuingDistributionPoint");
	tcase_add_loop_test(tc, test_parse_idp, 0, countof(idp_tests));
	tcase_add_test(tc, test_parse_idp_relative_name);
	suite_add_tcase(s, tc);

	return s;
}
