/*
 * Copyright (C) 2016 Codrut Cristian Grosu (codrut.cristian.grosu@gmail.com)
 * Copyright (C) 2016 IXIA (http://www.ixiacom.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE

#include "save_keys_listener.h"

#include <stdio.h>
#include <inttypes.h>
#include <errno.h>

#include <daemon.h>

typedef struct private_save_keys_listener_t private_save_keys_listener_t;
typedef struct algo_map_t algo_map_t;

/**
 * Name for IKEv1 decryption table file
 */
static char *ikev1_name = "ikev1_decryption_table";

/**
 * Name for IKEv2 decryption table file
 */
static char *ikev2_name = "ikev2_decryption_table";

/**
 * Private data.
 */
struct private_save_keys_listener_t {

	/**
	 * Public interface.
	 */
	save_keys_listener_t public;

	/**
	 * Path to the directory where the decryption tables will be stored.
	 */
	char *path;
};

METHOD(save_keys_listener_t, destroy, void,
	private_save_keys_listener_t *this)
{
	free(this);
}

/**
 * Mapping strongSwan identifiers to Wireshark names
 */
struct algo_map_t {

	/**
	 * IKE identifier
	 */
	const uint16_t ike;

	/**
	 * Optional key length
	 */
	const int key_len;

	/**
	 * Name of the algorithm in wireshark
	 */
	const char *name;
};

/**
 * Map an algorithm identifier to a name
 */
static inline const char *algo_name(algo_map_t *map, int count,
									uint16_t alg, int key_len)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (map[i].ike == alg)
		{
			if (map[i].key_len == -1 || map[i].key_len == key_len)
			{
				return map[i].name;
			}
		}
	}
	return NULL;
}

/**
 * Wireshark IKE algorithm identifiers for encryption
 */
static algo_map_t ike_encr[] = {
	{ ENCR_3DES,           -1, "3DES [RFC2451]"                          },
	{ ENCR_NULL,           -1, "NULL [RFC2410]"                          },
	{ ENCR_AES_CBC,       128, "AES-CBC-128 [RFC3602]"                   },
	{ ENCR_AES_CBC,       192, "AES-CBC-192 [RFC3602]"                   },
	{ ENCR_AES_CBC,       256, "AES-CBC-256 [RFC3602]"                   },
	{ ENCR_AES_CTR,       128, "AES-CTR-128 [RFC5930]"                   },
	{ ENCR_AES_CTR,       192, "AES-CTR-192 [RFC5930]"                   },
	{ ENCR_AES_CTR,       256, "AES-CTR-256 [RFC5930]"                   },
	{ ENCR_AES_GCM_ICV8,  128, "AES-GCM-128 with 8 octet ICV [RFC5282]"  },
	{ ENCR_AES_GCM_ICV8,  192, "AES-GCM-192 with 8 octet ICV [RFC5282]"  },
	{ ENCR_AES_GCM_ICV8,  256, "AES-GCM-256 with 8 octet ICV [RFC5282]"  },
	{ ENCR_AES_GCM_ICV12, 128, "AES-GCM-128 with 12 octet ICV [RFC5282]" },
	{ ENCR_AES_GCM_ICV12, 192, "AES-GCM-192 with 12 octet ICV [RFC5282]" },
	{ ENCR_AES_GCM_ICV12, 256, "AES-GCM-256 with 12 octet ICV [RFC5282]" },
	{ ENCR_AES_GCM_ICV16, 128, "AES-GCM-128 with 16 octet ICV [RFC5282]" },
	{ ENCR_AES_GCM_ICV16, 192, "AES-GCM-192 with 16 octet ICV [RFC5282]" },
	{ ENCR_AES_GCM_ICV16, 256, "AES-GCM-256 with 16 octet ICV [RFC5282]" },
	{ ENCR_AES_CCM_ICV8,  128, "AES-CCM-128 with 8 octet ICV [RFC5282]"  },
	{ ENCR_AES_CCM_ICV8,  192, "AES-CCM-192 with 8 octet ICV [RFC5282]"  },
	{ ENCR_AES_CCM_ICV8,  256, "AES-CCM-256 with 8 octet ICV [RFC5282]"  },
	{ ENCR_AES_CCM_ICV12, 128, "AES-CCM-128 with 12 octet ICV [RFC5282]" },
	{ ENCR_AES_CCM_ICV12, 192, "AES-CCM-192 with 12 octet ICV [RFC5282]" },
	{ ENCR_AES_CCM_ICV12, 256, "AES-CCM-256 with 12 octet ICV [RFC5282]" },
	{ ENCR_AES_CCM_ICV16, 128, "AES-CCM-128 with 16 octet ICV [RFC5282]" },
	{ ENCR_AES_CCM_ICV16, 192, "AES-CCM-192 with 16 octet ICV [RFC5282]" },
	{ ENCR_AES_CCM_ICV16, 256, "AES-CCM-256 with 16 octet ICV [RFC5282]" },
};

/**
 * Wireshark IKE algorithms for integrity
 */
static algo_map_t ike_integ[] = {
	{ AUTH_HMAC_MD5_96,       -1, "HMAC_MD5_96 [RFC2403]"       },
	{ AUTH_HMAC_SHA1_96,      -1, "HMAC_SHA1_96 [RFC2404]"      },
	{ AUTH_HMAC_MD5_128,      -1, "HMAC_MD5_128 [RFC4595]"      },
	{ AUTH_HMAC_SHA1_160,     -1, "HMAC_SHA1_160 [RFC4595]"     },
	{ AUTH_HMAC_SHA2_256_128, -1, "HMAC_SHA2_256_128 [RFC4868]" },
	{ AUTH_HMAC_SHA2_384_192, -1, "HMAC_SHA2_384_192 [RFC4868]" },
	{ AUTH_HMAC_SHA2_512_256, -1, "HMAC_SHA2_512_256 [RFC4868]" },
	{ AUTH_HMAC_SHA2_256_96,  -1, "HMAC_SHA2_256_96 [draft-ietf-ipsec-ciph-sha-256-00]" },
	{ AUTH_UNDEFINED,         -1, "NONE [RFC4306]"              },
};

/**
 * Map an IKE proposal
 */
static inline void ike_names(proposal_t *proposal, const char **enc,
							 const char **integ)
{
	uint16_t alg, len;

	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &len))
	{
		*enc = algo_name(ike_encr, countof(ike_encr), alg, len);
	}
	if (encryption_algorithm_is_aead(alg))
	{
		alg = AUTH_UNDEFINED;
	}
	else if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
		return;
	}
	*integ = algo_name(ike_integ, countof(ike_integ), alg, -1);
}


METHOD(listener_t, ike_derived_keys, bool,
	private_save_keys_listener_t *this, ike_sa_t *ike_sa, chunk_t sk_ei,
	chunk_t sk_er, chunk_t sk_ai, chunk_t sk_ar)
{
	ike_version_t version;
	ike_sa_id_t *id;
	const char *enc = NULL, *integ = NULL;
	char *path, *name;
	FILE *file;

	if (!this->path)
	{
		return TRUE;
	}

	version = ike_sa->get_version(ike_sa);
	name = version == IKEV2 ? ikev2_name : ikev1_name;
	if (asprintf(&path, "%s/%s", this->path, name) < 0)
	{
		DBG1(DBG_IKE, "failed to build path to IKE key table");
		return TRUE;
	}

	file = fopen(path, "a");
	if (file)
	{
		id = ike_sa->get_id(ike_sa);
		if (version == IKEV2)
		{
			ike_names(ike_sa->get_proposal(ike_sa), &enc, &integ);
			if (enc && integ)
			{
				fprintf(file, "%.16"PRIx64",%.16"PRIx64",%+B,%+B,\"%s\","
						"%+B,%+B,\"%s\"\n", be64toh(id->get_initiator_spi(id)),
						be64toh(id->get_responder_spi(id)), &sk_ei, &sk_er,
						enc, &sk_ai, &sk_ar, integ);
			}
		}
		else
		{
			fprintf(file, "%.16"PRIx64",%+B\n",
					be64toh(id->get_initiator_spi(id)), &sk_ei);
		}
		fclose(file);
	}
	else
	{
		DBG1(DBG_IKE, "failed to open IKE key table '%s': %s", path,
			 strerror(errno));
	}
	free(path);
	return TRUE;
}

/**
 * See header.
 */
save_keys_listener_t *save_keys_listener_create()
{
	private_save_keys_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_derived_keys = _ike_derived_keys,
			},
			.destroy = _destroy,
		},
		.path = lib->settings->get_str(lib->settings,
									   "%s.plugins.save-keys.wireshark_keys",
									   NULL, lib->ns),
	);

	return &this->public;
}
