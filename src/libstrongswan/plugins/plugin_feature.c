/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#define _GNU_SOURCE
#include <stdio.h>

#include "plugin_feature.h"

ENUM(plugin_feature_names, FEATURE_NONE, FEATURE_CUSTOM,
	"NONE",
	"CRYPTER",
	"SIGNER",
	"HASHER",
	"PRF",
	"DH",
	"RNG",
	"PRIVKEY",
	"PRIVKEY_GEN",
	"PRIVKEY_SIGN",
	"PRIVKEY_DECRYPT",
	"PUBKEY",
	"PUBKEY_VERIFY",
	"PUBKEY_ENCRYPT",
	"CERT_DECODE",
	"CERT_ENCODE",
	"EAP_SERVER",
	"EAP_CLIENT",
	"DATABASE",
	"CUSTOM",
);

/**
 * See header.
 */
bool plugin_feature_matches(plugin_feature_t *a, plugin_feature_t *b)
{
	if (a->type == b->type)
	{
		switch (a->type)
		{
			case FEATURE_NONE:
				return FALSE;
			case FEATURE_CRYPTER:
				return a->crypter.alg == b->crypter.alg &&
					   a->crypter.key_size == b->crypter.key_size;
			case FEATURE_SIGNER:
				return a->signer == b->signer;
			case FEATURE_HASHER:
				return a->hasher == b->hasher;
			case FEATURE_PRF:
				return a->prf == b->prf;
			case FEATURE_DH:
				return a->dh_group == b->dh_group;
			case FEATURE_RNG:
				return a->rng_quality <= b->rng_quality;
			case FEATURE_DATABASE:
				return a->database == b->database;
			case FEATURE_PRIVKEY:
			case FEATURE_PRIVKEY_GEN:
			case FEATURE_PUBKEY:
				return a->privkey == b->privkey;
			case FEATURE_PRIVKEY_SIGN:
			case FEATURE_PUBKEY_VERIFY:
				return a->privkey_sign == b->privkey_sign;
			case FEATURE_PRIVKEY_DECRYPT:
			case FEATURE_PUBKEY_ENCRYPT:
				return a->privkey_decrypt == b->privkey_decrypt;
			case FEATURE_CERT_DECODE:
			case FEATURE_CERT_ENCODE:
				return a->cert == b->cert;
			case FEATURE_EAP_SERVER:
			case FEATURE_EAP_PEER:
				return a->eap == b->eap;
			case FEATURE_CUSTOM:
				return streq(a->custom, b->custom);
		}
	}
	return FALSE;
}

/**
 * See header.
 */
char* plugin_feature_get_string(plugin_feature_t *feature)
{
	char *str = NULL;

	if (feature->kind == FEATURE_REGISTER)
	{
		return strdup("(register function)");
	}
	switch (feature->type)
	{
		case FEATURE_NONE:
			return strdup("NONE");
		case FEATURE_CRYPTER:
			if (asprintf(&str, "%N:%N-%d", plugin_feature_names, feature->type,
					encryption_algorithm_names, feature->crypter.alg,
					feature->crypter.key_size) > 0)
			{
				return str;
			}
			break;
		case FEATURE_SIGNER:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					integrity_algorithm_names, feature->signer) > 0)
			{
				return str;
			}
			break;
		case FEATURE_HASHER:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					hash_algorithm_names, feature->hasher) > 0)
			{
				return str;
			}
			break;
		case FEATURE_PRF:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					pseudo_random_function_names, feature->prf) > 0)
			{
				return str;
			}
			break;
		case FEATURE_DH:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					diffie_hellman_group_names, feature->dh_group) > 0)
			{
				return str;
			}
			break;
		case FEATURE_RNG:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					rng_quality_names, feature->rng_quality) > 0)
			{
				return str;
			}
			break;
		case FEATURE_DATABASE:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					db_driver_names, feature->database) > 0)
			{
				return str;
			}
			break;
		case FEATURE_PRIVKEY:
		case FEATURE_PRIVKEY_GEN:
		case FEATURE_PUBKEY:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					key_type_names, feature->privkey) > 0)
			{
				return str;
			}
			break;
		case FEATURE_PRIVKEY_SIGN:
		case FEATURE_PUBKEY_VERIFY:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					signature_scheme_names, feature->privkey_sign) > 0)
			{
				return str;
			}
			break;
		case FEATURE_PRIVKEY_DECRYPT:
		case FEATURE_PUBKEY_ENCRYPT:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					encryption_scheme_names, feature->privkey_decrypt) > 0)
			{
				return str;
			}
			break;
		case FEATURE_CERT_DECODE:
		case FEATURE_CERT_ENCODE:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					certificate_type_names, feature->cert) > 0)
			{
				return str;
			}
			break;
		case FEATURE_EAP_SERVER:
		case FEATURE_EAP_PEER:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					eap_type_short_names, feature->eap) > 0)
			{
				return str;
			}
			break;
		case FEATURE_CUSTOM:
			if (asprintf(&str, "%N:%N", plugin_feature_names, feature->type,
					db_driver_names, feature->database) > 0)
			{
				return str;
			}
			break;
	}
	if (!str)
	{
		str = strdup("(invalid)");
	}
	return str;
}
