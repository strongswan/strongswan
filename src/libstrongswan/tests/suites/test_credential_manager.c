/*
 * Copyright (C) 2026 SHIMAYOSHI, Takao
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

#include <credentials/sets/mem_cred.h>
#include <credentials/certificates/x509.h>

static mem_cred_t *creds;

/**
 * CA1 issues the certificates a and b, CA2 issues c. The private key of a is
 * not available.
 */
static certificate_t *ca1, *ca2, *a, *b, *c;

/**
 * Generate a key and issue a certificate for it, self-signed if ca is NULL
 */
static certificate_t *create_cert(certificate_t *ca, private_key_t *cakey,
								  char *subject, x509_flag_t flags,
								  private_key_t **key)
{
	private_key_t *privkey;
	public_key_t *pubkey;
	certificate_t *cert;
	identification_t *id;

	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ED25519,
								 BUILD_END);
	ck_assert(privkey);
	pubkey = privkey->get_public_key(privkey);
	ck_assert(pubkey);
	id = identification_create_from_string(subject);
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
						BUILD_SIGNING_KEY, ca ? cakey : privkey,
						BUILD_SIGNING_CERT, ca,
						BUILD_PUBLIC_KEY, pubkey,
						BUILD_SUBJECT, id,
						BUILD_X509_FLAG, flags,
						BUILD_DIGEST_ALG, HASH_IDENTITY,
						BUILD_END);
	ck_assert(cert);
	id->destroy(id);
	pubkey->destroy(pubkey);
	*key = privkey;
	return cert;
}

START_SETUP(setup)
{
	private_key_t *ca1key, *ca2key, *akey, *bkey, *ckey;

	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);

	ca1 = create_cert(NULL, NULL, "CN=CA1", X509_CA, &ca1key);
	ca2 = create_cert(NULL, NULL, "CN=CA2", X509_CA, &ca2key);
	a = create_cert(ca1, ca1key, "CN=a", 0, &akey);
	b = create_cert(ca1, ca1key, "CN=b", 0, &bkey);
	c = create_cert(ca2, ca2key, "CN=c", 0, &ckey);

	creds->add_cert(creds, TRUE, ca1->get_ref(ca1));
	creds->add_cert(creds, TRUE, ca2->get_ref(ca2));
	creds->add_cert(creds, FALSE, a->get_ref(a));
	creds->add_cert(creds, FALSE, b->get_ref(b));
	creds->add_cert(creds, FALSE, c->get_ref(c));
	creds->add_key(creds, bkey);
	creds->add_key(creds, ckey);

	ca1key->destroy(ca1key);
	ca2key->destroy(ca2key);
	akey->destroy(akey);
}
END_SETUP

START_TEARDOWN(teardown)
{
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	lib->credmgr->flush_cache(lib->credmgr, CERT_ANY);
	ca1->destroy(ca1);
	ca2->destroy(ca2);
	a->destroy(a);
	b->destroy(b);
	c->destroy(c);
}
END_TEARDOWN

/**
 * Create an auth config with the given subject certificates and anchor
 */
static auth_cfg_t *create_auth(certificate_t *anchor, certificate_t *first,
							   certificate_t *second)
{
	auth_cfg_t *auth;

	auth = auth_cfg_create();
	if (first)
	{
		auth->add(auth, AUTH_RULE_SUBJECT_CERT, first->get_ref(first));
	}
	if (second)
	{
		auth->add(auth, AUTH_RULE_SUBJECT_CERT, second->get_ref(second));
	}
	if (anchor)
	{
		auth->add(auth, AUTH_RULE_CA_CERT, anchor->get_ref(anchor));
	}
	return auth;
}

/**
 * Get a private key and verify that it and the subject certificate in the
 * auth config both match the expected certificate
 */
static void assert_private(identification_t *id, auth_cfg_t *auth,
						   certificate_t *expected)
{
	private_key_t *private;
	public_key_t *public, *expected_public;
	certificate_t *cert;

	private = lib->credmgr->get_private(lib->credmgr, KEY_ANY, id, auth);
	ck_assert(private);
	public = private->get_public_key(private);
	expected_public = expected->get_public_key(expected);
	ck_assert(public_key_equals(public, expected_public));
	public->destroy(public);
	expected_public->destroy(expected_public);
	private->destroy(private);

	cert = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
	ck_assert(cert);
	ck_assert(cert->equals(cert, expected));
	auth->destroy(auth);
}

START_TEST(test_configured)
{
	assert_private(NULL, create_auth(NULL, a, b), b);
}
END_TEST

START_TEST(test_configured_anchor)
{
	assert_private(NULL, create_auth(ca1, a, b), b);
}
END_TEST

START_TEST(test_configured_anchor_preferred)
{
	assert_private(NULL, create_auth(ca2, b, c), c);
}
END_TEST

START_TEST(test_configured_anchor_fallback)
{
	assert_private(NULL, create_auth(ca2, a, b), b);
}
END_TEST

START_TEST(test_id)
{
	assert_private(b->get_subject(b), create_auth(NULL, NULL, NULL), b);
}
END_TEST

START_TEST(test_id_anchor_fallback)
{
	assert_private(b->get_subject(b), create_auth(ca2, NULL, NULL), b);
}
END_TEST

START_TEST(test_id_configured_anchor_fallback)
{
	assert_private(b->get_subject(b), create_auth(ca2, a, NULL), b);
}
END_TEST

Suite *credential_manager_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("credential manager");

	tc = tcase_create("get_private configured");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_configured);
	tcase_add_test(tc, test_configured_anchor);
	tcase_add_test(tc, test_configured_anchor_preferred);
	tcase_add_test(tc, test_configured_anchor_fallback);
	suite_add_tcase(s, tc);

	tc = tcase_create("get_private identity");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_id);
	tcase_add_test(tc, test_id_anchor_fallback);
	tcase_add_test(tc, test_id_configured_anchor_fallback);
	suite_add_tcase(s, tc);

	return s;
}
