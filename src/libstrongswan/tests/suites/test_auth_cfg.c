/*
 * Copyright (C) 2016 Tobias Brunner
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

#include <credentials/auth_cfg.h>

struct {
	char *constraints;
	signature_scheme_t sig[5];
	signature_scheme_t ike[5];
} sig_constraints_tests[] = {
	{ "rsa-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }, {0}},
	{ "rsa-sha256-sha512", { SIGN_RSA_EMSA_PKCS1_SHA2_256, SIGN_RSA_EMSA_PKCS1_SHA2_512, 0 }, {0}},
	{ "ecdsa-sha256", { SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {0}},
	{ "rsa-sha256-ecdsa-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {0}},
	{ "pubkey-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {0}},
	{ "ike:rsa-sha256", {0}, { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }},
	{ "ike:rsa-sha256-rsa-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }, { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }},
	{ "rsa-sha256-ike:rsa-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }, { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }},
	{ "ike:pubkey-sha256", {0}, { SIGN_RSA_EMSA_PKCS1_SHA2_256, SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }},
	{ "rsa-ecdsa-sha256", { SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {0}},
	{ "rsa-4096-ecdsa-sha256", { SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {0}},
	{ "rsa-4096-ecdsa-256-sha256", { SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {0}},
	{ "rsa-ecdsa256-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }, {0}},
	{ "rsa4096-sha256", {0}, {0}},
	{ "sha256", {0}, {0}},
	{ "ike:sha256", {0}, {0}},
};

static void check_sig_constraints(auth_cfg_t *cfg, auth_rule_t type,
								  signature_scheme_t expected[])
{
	enumerator_t *enumerator;
	auth_rule_t t;
	signature_params_t *value;
	int i = 0;

	enumerator = cfg->create_enumerator(cfg);
	while (enumerator->enumerate(enumerator, &t, &value))
	{
		if (t == type)
		{
			ck_assert(expected[i]);
			ck_assert_int_eq(expected[i], value->scheme);
			i++;
		}
	}
	enumerator->destroy(enumerator);
	ck_assert(!expected[i]);
}

START_TEST(test_sig_constraints)
{
	auth_cfg_t *cfg;
	signature_scheme_t none[] = {0};

	cfg = auth_cfg_create();
	cfg->add_pubkey_constraints(cfg, sig_constraints_tests[_i].constraints, FALSE);
	check_sig_constraints(cfg, AUTH_RULE_SIGNATURE_SCHEME, sig_constraints_tests[_i].sig);
	check_sig_constraints(cfg, AUTH_RULE_IKE_SIGNATURE_SCHEME, none);
	cfg->destroy(cfg);

	lib->settings->set_bool(lib->settings, "%s.signature_authentication_constraints",
							FALSE, lib->ns);

	cfg = auth_cfg_create();
	cfg->add_pubkey_constraints(cfg, sig_constraints_tests[_i].constraints, TRUE);
	check_sig_constraints(cfg, AUTH_RULE_SIGNATURE_SCHEME, sig_constraints_tests[_i].sig);
	check_sig_constraints(cfg, AUTH_RULE_IKE_SIGNATURE_SCHEME, sig_constraints_tests[_i].ike);
	cfg->destroy(cfg);
}
END_TEST

START_TEST(test_ike_constraints_fallback)
{
	auth_cfg_t *cfg;

	lib->settings->set_bool(lib->settings, "%s.signature_authentication_constraints",
							TRUE, lib->ns);

	cfg = auth_cfg_create();
	cfg->add_pubkey_constraints(cfg, sig_constraints_tests[_i].constraints, TRUE);
	check_sig_constraints(cfg, AUTH_RULE_SIGNATURE_SCHEME, sig_constraints_tests[_i].sig);
	if (sig_constraints_tests[_i].ike[0])
	{
		check_sig_constraints(cfg, AUTH_RULE_IKE_SIGNATURE_SCHEME, sig_constraints_tests[_i].ike);
	}
	else
	{
		check_sig_constraints(cfg, AUTH_RULE_IKE_SIGNATURE_SCHEME, sig_constraints_tests[_i].sig);
	}
	cfg->destroy(cfg);
}
END_TEST

typedef union {
	rsa_pss_params_t pss;
} signature_param_types_t;

struct {
	char *constraints;
	signature_scheme_t sig[5];
	signature_param_types_t p[5];
} sig_constraints_params_tests[] = {
	{ "rsa/pss-sha256", { SIGN_RSA_EMSA_PSS, 0 }, {
		{ .pss = { .hash = HASH_SHA256, .mgf1_hash = HASH_SHA256, .salt_len = HASH_SIZE_SHA256, }}}},
	{ "rsa/pss-sha256-sha384", { SIGN_RSA_EMSA_PSS, SIGN_RSA_EMSA_PSS, 0 }, {
		{ .pss = { .hash = HASH_SHA256, .mgf1_hash = HASH_SHA256, .salt_len = HASH_SIZE_SHA256, }},
		{ .pss = { .hash = HASH_SHA384, .mgf1_hash = HASH_SHA384, .salt_len = HASH_SIZE_SHA384, }}}},
	{ "rsa/pss-sha256-rsa-sha256", { SIGN_RSA_EMSA_PSS, SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }, {
		{ .pss = { .hash = HASH_SHA256, .mgf1_hash = HASH_SHA256, .salt_len = HASH_SIZE_SHA256, }}}},
	{ "rsa-sha256-rsa/pss-sha256", { SIGN_RSA_EMSA_PKCS1_SHA2_256, SIGN_RSA_EMSA_PSS, 0 }, {
		{},
		{ .pss = { .hash = HASH_SHA256, .mgf1_hash = HASH_SHA256, .salt_len = HASH_SIZE_SHA256, }}}},
	{ "rsa/pss", { 0 }, {}},
};

static void check_sig_constraints_params(auth_cfg_t *cfg, auth_rule_t type,
										 signature_scheme_t scheme[],
										 signature_param_types_t p[])
{
	enumerator_t *enumerator;
	auth_rule_t t;
	signature_params_t *value;
	int i = 0;

	enumerator = cfg->create_enumerator(cfg);
	while (enumerator->enumerate(enumerator, &t, &value))
	{
		if (t == type)
		{
			if (scheme[i] == SIGN_RSA_EMSA_PSS)
			{
				signature_params_t expected = {
					.scheme = scheme[i],
					.params = &p[i].pss,
				};
				ck_assert(signature_params_equal(value, &expected));
			}
			else
			{
				ck_assert(scheme[i]);
				ck_assert(!value->params);
				ck_assert_int_eq(scheme[i], value->scheme);
			}
			i++;
		}
	}
	enumerator->destroy(enumerator);
	ck_assert(!scheme[i]);
}

START_TEST(test_sig_constraints_params)
{
	auth_cfg_t *cfg;

	cfg = auth_cfg_create();
	cfg->add_pubkey_constraints(cfg, sig_constraints_params_tests[_i].constraints, TRUE);
	check_sig_constraints_params(cfg, AUTH_RULE_IKE_SIGNATURE_SCHEME,
								 sig_constraints_params_tests[_i].sig,
								 sig_constraints_params_tests[_i].p);
	cfg->destroy(cfg);
}
END_TEST

struct {
	char *constraints;
	signature_scheme_t sig[6];
	signature_param_types_t p[6];
} sig_constraints_rsa_pss_tests[] = {
	{ "pubkey-sha256", { SIGN_RSA_EMSA_PSS, SIGN_RSA_EMSA_PKCS1_SHA2_256, SIGN_ECDSA_WITH_SHA256_DER, SIGN_ECDSA_256, 0 }, {
		{ .pss = { .hash = HASH_SHA256, .mgf1_hash = HASH_SHA256, .salt_len = HASH_SIZE_SHA256, }}, {}, {}, {}, {}}},
	{ "rsa-sha256", { SIGN_RSA_EMSA_PSS, SIGN_RSA_EMSA_PKCS1_SHA2_256, 0 }, {
		{ .pss = { .hash = HASH_SHA256, .mgf1_hash = HASH_SHA256, .salt_len = HASH_SIZE_SHA256, }}, {}}},
};

START_TEST(test_sig_constraints_rsa_pss)
{
	auth_cfg_t *cfg;

	lib->settings->set_bool(lib->settings, "%s.rsa_pss", TRUE, lib->ns);

	cfg = auth_cfg_create();
	cfg->add_pubkey_constraints(cfg, sig_constraints_rsa_pss_tests[_i].constraints, TRUE);
	check_sig_constraints_params(cfg, AUTH_RULE_IKE_SIGNATURE_SCHEME,
								 sig_constraints_rsa_pss_tests[_i].sig,
								 sig_constraints_rsa_pss_tests[_i].p);
	cfg->destroy(cfg);
}
END_TEST

struct {
	char *constraints;
	char *curves[3];
} curve_constraints_tests[] = {
	{ "ecdsa-p256", { "prime256v1" }},
	{ "ecdsa-bp384", { "brainpoolP384r1" }},
	{ "ecdsa-brainpoolP256r1", { "brainpoolP256r1" }},
	{ "ecdsa-1.3.36.3.3.2.8.1.1.7", { "brainpoolP256r1" }},
	{ "ecdsa-1.3.6.1.4.1.36906.15", { "1.3.6.1.4.1.36906.15" }},
	{ "ecdsa-p256-bp384", { "prime256v1", "brainpoolP384r1" }},
	{ "ecdsa-384-brainpoolP384r1-sha384", { "brainpoolP384r1" }},
	{ "pubkey-p256", {}},
	{ "rsa-p256", {}},
};

static void check_curve_constraints(auth_cfg_t *cfg, char *curves[])
{
	enumerator_t *enumerator;
	auth_rule_t t;
	char *value;
	int i = 0;

	enumerator = cfg->create_enumerator(cfg);
	while (enumerator->enumerate(enumerator, &t, &value))
	{
		if (t == AUTH_RULE_ECDSA_CURVE)
		{
			ck_assert_str_eq(curves[i], value);
			i++;
		}
	}
	enumerator->destroy(enumerator);
	ck_assert(!curves[i]);
}

START_TEST(test_curve_constraints)
{
	auth_cfg_t *cfg;

	cfg = auth_cfg_create();
	cfg->add_pubkey_constraints(cfg, curve_constraints_tests[_i].constraints, TRUE);
	check_curve_constraints(cfg, curve_constraints_tests[_i].curves);
	cfg->destroy(cfg);
}
END_TEST

struct {
	bool compliant;
	char *constraints;
	struct {
		auth_rule_t type;
		void *value;
	} rules[5];
} complies_curves_tests[] = {
	{ TRUE, "ecdsa-p256", {}},
	{ TRUE, "rsa-2048-ecdsa-p256", {}},
	{ FALSE, "ecdsa-p256", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 }, }},
	{ TRUE, "ecdsa-256", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 }, }},
	{ TRUE, "ecdsa-256", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 },
		{ AUTH_RULE_ECDSA_CURVE, "prime256v1" }, }},
	{ TRUE, "ecdsa-p256", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 },
		{ AUTH_RULE_ECDSA_CURVE, "prime256v1" }, }},
	{ TRUE, "ecdsa-256-p256", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 },
		{ AUTH_RULE_ECDSA_CURVE, "prime256v1" }, }},
	{ FALSE, "ecdsa-p384", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 },
		{ AUTH_RULE_ECDSA_CURVE, "prime256v1" }, }},
	{ TRUE, "ecdsa-p256-p384", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 },
		{ AUTH_RULE_ECDSA_CURVE, "prime256v1" }, }},
	{ TRUE, "ecdsa-p256-p384", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)384 },
		{ AUTH_RULE_ECDSA_CURVE, "secp384r1" }, }},
	{ TRUE, "ecdsa-p256-p384", {
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)384 },
		{ AUTH_RULE_ECDSA_CURVE, "secp384r1" },
		{ AUTH_RULE_ECDSA_STRENGTH, (void*)(uintptr_t)256 },
		{ AUTH_RULE_ECDSA_CURVE, "prime256v1" }, }},
};

START_TEST(test_complies_curves)
{
	auth_cfg_t *constraints, *cfg;
	int i;

	constraints = auth_cfg_create();
	constraints->add_pubkey_constraints(constraints,
										complies_curves_tests[_i].constraints,
										TRUE);

	cfg = auth_cfg_create();
	for (i = 0; i < countof(complies_curves_tests[_i].rules); i++)
	{
		if (!complies_curves_tests[_i].rules[i].value)
		{
			break;
		}
		cfg->add(cfg, complies_curves_tests[_i].rules[i].type,
				 auth_cfg_clone_value(complies_curves_tests[_i].rules[i].type,
									  complies_curves_tests[_i].rules[i].value));
	}
	ck_assert(complies_curves_tests[_i].compliant ==
				cfg->complies(cfg, constraints, TRUE));
	cfg->destroy(cfg);
	constraints->destroy(constraints);
}
END_TEST

Suite *auth_cfg_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("auth_cfg");

	tc = tcase_create("add_pubkey_constraints");
	tcase_add_loop_test(tc, test_sig_constraints, 0, countof(sig_constraints_tests));
	tcase_add_loop_test(tc, test_ike_constraints_fallback, 0, countof(sig_constraints_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("add_pubkey_constraints parameters");
	tcase_add_loop_test(tc, test_sig_constraints_params, 0, countof(sig_constraints_params_tests));
	tcase_add_loop_test(tc, test_sig_constraints_rsa_pss, 0, countof(sig_constraints_rsa_pss_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("add_pubkey_constraints curves");
	tcase_add_loop_test(tc, test_curve_constraints, 0, countof(curve_constraints_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("complies");
	tcase_add_loop_test(tc, test_complies_curves, 0, countof(complies_curves_tests));
	suite_add_tcase(s, tc);

	return s;
}
