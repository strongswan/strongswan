/* IKE modular algorithm handling interface
 * Copyright (C) JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>

#include <freeswan.h>
#include <ipsec_policy.h>

#include <library.h>
#include <debug.h>
#include <crypto/hashers/hasher.h>
#include <crypto/crypters/crypter.h>
#include <crypto/prfs/prf.h>

#include "constants.h"
#include "defs.h"
#include "crypto.h"

#include "state.h"
#include "packet.h"
#include "log.h"
#include "whack.h"
#include "spdb.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "connections.h"
#include "kernel.h"

#define return_on(var, val) do { var=val;goto return_out; } while(0);

/**
 * IKE algorithm list handling - registration and lookup
 */

/* Modular IKE algorithm storage structure */

static struct ike_alg *ike_alg_base[IKE_ALG_MAX+1] = {NULL, NULL};

/**
 * Return ike_algo object by {type, id}
 */
static struct ike_alg *ike_alg_find(u_int algo_type, u_int algo_id,
									u_int keysize __attribute__((unused)))
{
	struct ike_alg *e = ike_alg_base[algo_type];

	while (e != NULL && algo_id > e->algo_id)
	{
		e = e->algo_next;
	}
	return (e != NULL && e->algo_id == algo_id) ? e : NULL;
}

/**
 * "raw" ike_alg list adding function
 */
int ike_alg_add(struct ike_alg* a)
{
	if (a->algo_type > IKE_ALG_MAX)
	{
		plog("ike_alg: Not added, invalid algorithm type");
		return -EINVAL;
	}

	if (ike_alg_find(a->algo_type, a->algo_id, 0) != NULL)
	{
		plog("ike_alg: Not added, algorithm already exists");
		return -EEXIST;
	}

	{
		struct ike_alg **ep = &ike_alg_base[a->algo_type];
		struct ike_alg *e = *ep;

		while (e != NULL && a->algo_id > e->algo_id)
		{
			ep = &e->algo_next;
			e = *ep;
		}
		*ep = a;
		a->algo_next = e;
		return 0;
	}
}

/**
 * Get IKE hash algorithm
 */
struct hash_desc *ike_alg_get_hasher(u_int alg)
{
	return (struct hash_desc *) ike_alg_find(IKE_ALG_HASH, alg, 0);
}

/**
 * Get IKE encryption algorithm
 */
struct encrypt_desc *ike_alg_get_crypter(u_int alg)
{
	return (struct encrypt_desc *) ike_alg_find(IKE_ALG_ENCRYPT, alg, 0);
}

/**
 * Get IKE dh group
 */
struct dh_desc *ike_alg_get_dh_group(u_int alg)
{
	return (struct dh_desc *) ike_alg_find(IKE_ALG_DH_GROUP, alg, 0);
}

/**
 * Get pfsgroup for this connection
 */
const struct dh_desc *ike_alg_pfsgroup(struct connection *c, lset_t policy)
{
	const struct dh_desc *ret = NULL;

	if ((policy & POLICY_PFS) &&
		c->alg_info_esp && c->alg_info_esp->esp_pfsgroup)
	{
		ret = ike_alg_get_dh_group(c->alg_info_esp->esp_pfsgroup);
	}
	return ret;
}

/**
 * Create an OAKLEY proposal based on alg_info and policy
 */
struct db_context *ike_alg_db_new(struct alg_info_ike *ai , lset_t policy)
{
	struct db_context *db_ctx = NULL;
	struct ike_info *ike_info;
	struct encrypt_desc *enc_desc;
	u_int ealg, halg, modp, eklen = 0;
	int i;

	bool is_xauth_server = (policy & POLICY_XAUTH_SERVER) != LEMPTY;

	if (!ai)
	{
		whack_log(RC_LOG_SERIOUS, "no IKE algorithms "
								  "for this connection "
								  "(check ike algorithm string)");
		goto fail;
	}
	policy &= POLICY_ID_AUTH_MASK;
	db_ctx = db_prop_new(PROTO_ISAKMP, 8, 8 * 5);

	/* for each group */
	ALG_INFO_IKE_FOREACH(ai, ike_info, i)
	{
		ealg = ike_info->ike_ealg;
		halg = ike_info->ike_halg;
		modp = ike_info->ike_modp;
		eklen= ike_info->ike_eklen;

		if (!ike_alg_get_crypter(ealg))
		{
			DBG_log("ike_alg: ike crypter %s not present",
					enum_show(&oakley_enc_names, ealg));
			continue;
		}
		if (!ike_alg_get_hasher(halg)) 
		{
			DBG_log("ike_alg: ike hasher %s not present",
					enum_show(&oakley_hash_names, halg));
			continue;
		}
		if (!ike_alg_get_dh_group(modp)) 
		{
			DBG_log("ike_alg: ike dh group %s not present",
					enum_show(&oakley_group_names, modp));
			continue;
		}
		enc_desc = ike_alg_get_crypter(ealg);

		if (policy & POLICY_RSASIG)
		{
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, OAKLEY_HASH_ALGORITHM, halg);
			if (eklen)
				db_attr_add_values(db_ctx, OAKLEY_KEY_LENGTH, eklen);
			db_attr_add_values(db_ctx, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG);
			db_attr_add_values(db_ctx, OAKLEY_GROUP_DESCRIPTION, modp);
		}

		if (policy & POLICY_PSK)
		{
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, OAKLEY_HASH_ALGORITHM, halg);
			if (eklen)
				db_attr_add_values(db_ctx, OAKLEY_KEY_LENGTH, eklen);
			db_attr_add_values(db_ctx, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY);
			db_attr_add_values(db_ctx, OAKLEY_GROUP_DESCRIPTION, modp);
		}

		if (policy & POLICY_XAUTH_RSASIG)
		{
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, OAKLEY_HASH_ALGORITHM, halg);
			if (eklen)
				db_attr_add_values(db_ctx, OAKLEY_KEY_LENGTH, eklen);
			db_attr_add_values(db_ctx, OAKLEY_AUTHENTICATION_METHOD
				, is_xauth_server ? XAUTHRespRSA : XAUTHInitRSA);
			db_attr_add_values(db_ctx, OAKLEY_GROUP_DESCRIPTION, modp);
		}

		if (policy & POLICY_XAUTH_PSK)
		{
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, OAKLEY_HASH_ALGORITHM, halg);
			if (eklen)
				db_attr_add_values(db_ctx, OAKLEY_KEY_LENGTH, eklen);
			db_attr_add_values(db_ctx, OAKLEY_AUTHENTICATION_METHOD
				, is_xauth_server ? XAUTHRespPreShared : XAUTHInitPreShared);
			db_attr_add_values(db_ctx, OAKLEY_GROUP_DESCRIPTION, modp);
		}
	}
fail:
	return db_ctx;
}

/**
 * Show registered IKE algorithms
 */
void ike_alg_list(void)
{
	char buf[BUF_LEN];
	char *pos;
	int n, len;
	struct ike_alg *a;

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of registered IKEv1 Algorithms:");
	whack_log(RC_COMMENT, " ");

	pos = buf;
	*pos = '\0';
	len = BUF_LEN;
	for (a = ike_alg_base[IKE_ALG_ENCRYPT]; a != NULL; a = a->algo_next)
	{
	    n = snprintf(pos, len, " %s", enum_name(&oakley_enc_names, a->algo_id));
		pos += n;
		len -= n;
		if (len <= 0)
		{
			break;
		}
	}
	whack_log(RC_COMMENT, "  encryption:%s", buf);

	pos = buf;
	*pos = '\0';
	len = BUF_LEN;
	for (a = ike_alg_base[IKE_ALG_HASH]; a != NULL; a = a->algo_next)
	{
	    n = snprintf(pos, len, " %s", enum_name(&oakley_hash_names, a->algo_id));
		pos += n;
		len -= n;
		if (len <= 0)
		{
			break;
		}
	}
	whack_log(RC_COMMENT, "  hasher:    %s", buf);

	pos = buf;
	*pos = '\0';
	len = BUF_LEN;
	for (a = ike_alg_base[IKE_ALG_DH_GROUP]; a != NULL; a = a->algo_next)
	{
	    n = snprintf(pos, len, " %s", enum_name(&oakley_group_names, a->algo_id));
		pos += n;
		len -= n;
		if (len <= 0)
		{
			break;
		}
	}
	whack_log(RC_COMMENT, "  dh-group:  %s", buf);
}

/**
 * Show IKE algorithms for this connection (result from ike= string)
 * and newest SA
 */
void ike_alg_show_connection(struct connection *c, const char *instance)
{
	struct state *st = state_with_serialno(c->newest_isakmp_sa);

	if (st)
	{
		if (st->st_oakley.encrypt == OAKLEY_3DES_CBC)
		{
			whack_log(RC_COMMENT,
					"\"%s\"%s:   IKE proposal: %s/%s/%s",
					c->name, instance,
					enum_show(&oakley_enc_names, st->st_oakley.encrypt),
					enum_show(&oakley_hash_names, st->st_oakley.hash),
					enum_show(&oakley_group_names, st->st_oakley.group->algo_id)
			);
		}
		else
		{
			whack_log(RC_COMMENT,
					"\"%s\"%s:   IKE proposal: %s_%u/%s/%s",
					c->name, instance,
					enum_show(&oakley_enc_names, st->st_oakley.encrypt),
					st->st_oakley.enckeylen,
					enum_show(&oakley_hash_names, st->st_oakley.hash),
					enum_show(&oakley_group_names, st->st_oakley.group->algo_id)
			);
		}
	}
}

/**
 * Apply a suite of testvectors to an encryption algorithm
 */
static bool ike_encrypt_test(const struct encrypt_desc *desc)
{
	bool encrypt_results = TRUE;

	if (desc->enc_testvectors == NULL)
	{
		plog("  %s encryption self-test not available",
			 enum_name(&oakley_enc_names, desc->algo_id));
	}
	else
	{
		int i;
		encryption_algorithm_t enc_alg;

		enc_alg = oakley_to_encryption_algorithm(desc->algo_id);
	
		for (i = 0; desc->enc_testvectors[i].key != NULL; i++)
		{
			bool result;
			crypter_t *crypter;
			chunk_t key =    { (u_char*)desc->enc_testvectors[i].key,
									    desc->enc_testvectors[i].key_size };
			chunk_t plain =  { (u_char*)desc->enc_testvectors[i].plain,
									    desc->enc_testvectors[i].data_size};
			chunk_t cipher = { (u_char*)desc->enc_testvectors[i].cipher,
									    desc->enc_testvectors[i].data_size};
			chunk_t encrypted = chunk_empty;
			chunk_t decrypted = chunk_empty;
			chunk_t iv;

			crypter = lib->crypto->create_crypter(lib->crypto, enc_alg, key.len);
			if (crypter == NULL)
			{
				plog("  %s encryption function not available",
					 enum_name(&oakley_enc_names, desc->algo_id));
				return FALSE;
			}
			iv = chunk_create((u_char*)desc->enc_testvectors[i].iv,
							  crypter->get_block_size(crypter));
			crypter->set_key(crypter, key);
			crypter->decrypt(crypter, cipher, iv, &decrypted);
			result = chunk_equals(decrypted, plain);
			crypter->encrypt(crypter, plain, iv, &encrypted);
			result &= chunk_equals(encrypted, cipher);
			DBG(DBG_CRYPT,
				DBG_log("  enc testvector %d: %s", i, result ? "ok":"failed")
			)
			encrypt_results &= result;
			crypter->destroy(crypter);
			free(encrypted.ptr);
			free(decrypted.ptr);
		}
		plog("  %s encryption self-test %s",
			 enum_name(&oakley_enc_names, desc->algo_id),
			 encrypt_results ? "passed":"failed");
	}
	return encrypt_results;
}

/**
 * Apply a suite of testvectors to a hash algorithm
 */
static bool ike_hash_test(const struct hash_desc *desc)
{
	bool hash_results = TRUE;
	bool hmac_results = TRUE;

	if (desc->hash_testvectors == NULL)
	{
		plog("  %s hash self-test not available",
			 enum_name(&oakley_hash_names, desc->algo_id));
	}
	else
	{
		int i;
		hash_algorithm_t hash_alg;
		hasher_t *hasher;

		hash_alg = oakley_to_hash_algorithm(desc->algo_id);
		hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
		if (hasher == NULL)
		{
			plog("  %s hash function not available",
				 enum_name(&oakley_hash_names, desc->algo_id));
			return FALSE;
		}
			
		for (i = 0; desc->hash_testvectors[i].msg_digest != NULL; i++)
		{
			u_char digest[MAX_DIGEST_LEN];
			chunk_t msg = { (u_char*)desc->hash_testvectors[i].msg,
							desc->hash_testvectors[i].msg_size };
			bool result;

			hasher->get_hash(hasher, msg, digest);
			result = memeq(digest, desc->hash_testvectors[i].msg_digest
								  , desc->hash_digest_size);
			DBG(DBG_CRYPT,
				DBG_log("  hash testvector %d: %s", i, result ? "ok":"failed")
			)
			hash_results &= result;
		}
		hasher->destroy(hasher);
		plog("  %s hash self-test %s", enum_name(&oakley_hash_names, desc->algo_id),
									   hash_results ? "passed":"failed");
	}

	if (desc->hmac_testvectors == NULL)
	{
		plog("  %s hmac self-test not available", enum_name(&oakley_hash_names, desc->algo_id));
	}
	else
	{
		int i;
		pseudo_random_function_t prf_alg;

		prf_alg = oakley_to_prf(desc->algo_id);

		for (i = 0; desc->hmac_testvectors[i].hmac != NULL; i++)
		{
			u_char digest[MAX_DIGEST_LEN];
			chunk_t key = { (u_char*)desc->hmac_testvectors[i].key,
							desc->hmac_testvectors[i].key_size };
			chunk_t msg = { (u_char*)desc->hmac_testvectors[i].msg,
							desc->hmac_testvectors[i].msg_size };
			prf_t *prf;
			bool result;

			prf = lib->crypto->create_prf(lib->crypto, prf_alg);
			if (prf == NULL)
			{
				plog("  %s hmac function not available",
					 enum_name(&oakley_hash_names, desc->algo_id));
				return FALSE;
			}
			prf->set_key(prf, key);
			prf->get_bytes(prf, msg, digest);
			prf->destroy(prf);
			result = memeq(digest, desc->hmac_testvectors[i].hmac,
								   desc->hash_digest_size);
			DBG(DBG_CRYPT,
				DBG_log("  hmac testvector %d: %s", i, result ? "ok":"failed")
			)
			hmac_results &= result;
		}
		plog("  %s hmac self-test %s", enum_name(&oakley_hash_names, desc->algo_id)
								, hmac_results ? "passed":"failed");
	}
	return hash_results && hmac_results;
}

/**
 * Apply test vectors to registered encryption and hash algorithms
 */
bool ike_alg_test(void)
{
	bool all_results = TRUE;
	struct ike_alg *a;
	
	plog("Testing registered IKE crypto algorithms:");

	for (a = ike_alg_base[IKE_ALG_ENCRYPT]; a != NULL; a = a->algo_next)
	{
		struct encrypt_desc *desc = (struct encrypt_desc*)a;

		all_results &= ike_encrypt_test(desc);
	}

	for (a = ike_alg_base[IKE_ALG_HASH]; a != NULL; a = a->algo_next)
	{
		struct hash_desc *desc = (struct hash_desc*)a;

		all_results &= ike_hash_test(desc);
	}

	if (all_results)
		plog("All crypto self-tests passed");
	else
		plog("Some crypto self-tests failed");
	return all_results;
}

/**
 * ML: make F_STRICT logic consider enc,hash/auth,modp algorithms
 */
bool ike_alg_ok_final(u_int ealg, u_int key_len, u_int aalg, u_int group,
					  struct alg_info_ike *alg_info_ike)
{
	/*
	 * simple test to discard low key_len, will accept it only
	 * if specified in "esp" string
	 */
	bool ealg_insecure = (key_len < 128);

	if (ealg_insecure
	|| (alg_info_ike && alg_info_ike->alg_info_flags & ALG_INFO_F_STRICT))
	{
		int i;
		struct ike_info *ike_info;

		if (alg_info_ike)
		{
			ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i)
			{
				if (ike_info->ike_ealg == ealg
				&& (ike_info->ike_eklen == 0 || key_len == 0 || ike_info->ike_eklen == key_len)
				&& ike_info->ike_halg == aalg
				&& ike_info->ike_modp == group)
				{
					if (ealg_insecure)
						loglog(RC_LOG_SERIOUS, "You should NOT use insecure IKE algorithms (%s)!"
								, enum_name(&oakley_enc_names, ealg));
					return TRUE;
				}
			}
		}
		plog("Oakley Transform [%s (%d), %s, %s] refused due to %s"
				, enum_name(&oakley_enc_names, ealg), key_len
				, enum_name(&oakley_hash_names, aalg)
				, enum_name(&oakley_group_names, group)
				, ealg_insecure ?
					"insecure key_len and enc. alg. not listed in \"ike\" string" : "strict flag"
		);
		return FALSE;
	}
	return TRUE;
}

