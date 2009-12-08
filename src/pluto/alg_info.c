/*
 * Algorithm info parsing and creation functions
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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <freeswan.h>
#include <pfkeyv2.h>

#include <utils.h>
#include <utils/lexparser.h>
#include <crypto/diffie_hellman.h>
#include <crypto/transform.h>
#include <crypto/proposal/proposal_keywords.h>


#include "alg_info.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"
#include "crypto.h"
#include "kernel_alg.h"
#include "ike_alg.h"

/*
 * sadb/ESP aa attrib converters
 */
int alg_info_esp_aa2sadb(int auth)
{
	int sadb_aalg = 0;

	switch(auth) {
		case AUTH_ALGORITHM_HMAC_MD5:
		case AUTH_ALGORITHM_HMAC_SHA1:
			sadb_aalg = auth + 1;
			break;
		case AUTH_ALGORITHM_HMAC_SHA2_256:
		case AUTH_ALGORITHM_HMAC_SHA2_384:
		case AUTH_ALGORITHM_HMAC_SHA2_512:
		case AUTH_ALGORITHM_HMAC_RIPEMD:
		case AUTH_ALGORITHM_AES_XCBC_MAC:
			sadb_aalg = auth;
			break;
		default:
			/* loose ... */
			sadb_aalg = auth;
	}
	return sadb_aalg;
}

int alg_info_esp_sadb2aa(int sadb_aalg)
{
	int auth = 0;

	switch(sadb_aalg) {
		case SADB_AALG_MD5HMAC:
		case SADB_AALG_SHA1HMAC:
			auth = sadb_aalg - 1;
			break;
		case SADB_X_AALG_SHA2_256HMAC:
		case SADB_X_AALG_SHA2_384HMAC:
		case SADB_X_AALG_SHA2_512HMAC:
		case SADB_X_AALG_RIPEMD160HMAC:
		case SADB_X_AALG_AES_XCBC_MAC:
			auth = sadb_aalg;
			break;
		default:
			/* loose ... */
			auth = sadb_aalg;
	}
	return auth;
}

void alg_info_free(struct alg_info *alg_info)
{
	free(alg_info);
}

/*
 * Raw add routine: only checks for no duplicates
 */
static void __alg_info_esp_add(struct alg_info_esp *alg_info, int ealg_id,
							   unsigned ek_bits, int aalg_id, unsigned ak_bits)
{
	struct esp_info *esp_info = alg_info->esp;
	unsigned cnt = alg_info->alg_info_cnt, i;

	/* check for overflows */
	passert(cnt < countof(alg_info->esp));

	/* dont add duplicates */
	for (i = 0; i < cnt; i++)
	{
		if (esp_info[i].esp_ealg_id == ealg_id
		&& (!ek_bits || esp_info[i].esp_ealg_keylen == ek_bits)
		&& esp_info[i].esp_aalg_id == aalg_id
		&& (!ak_bits || esp_info[i].esp_aalg_keylen == ak_bits))
		{
			return;
		}
	}

	esp_info[cnt].esp_ealg_id = ealg_id;
	esp_info[cnt].esp_ealg_keylen = ek_bits;
	esp_info[cnt].esp_aalg_id = aalg_id;
	esp_info[cnt].esp_aalg_keylen = ak_bits;

	/* sadb values */
	esp_info[cnt].encryptalg = ealg_id;
	esp_info[cnt].authalg = alg_info_esp_aa2sadb(aalg_id);
	alg_info->alg_info_cnt++;

	DBG(DBG_CRYPT,
		DBG_log("esp alg added: %s_%d/%s, cnt=%d",
				enum_show(&esp_transform_names, ealg_id), ek_bits,
				enum_show(&auth_alg_names, aalg_id),
				alg_info->alg_info_cnt)
	)
}

/**
 * Returns true if the given alg is an authenticated encryption algorithm
 */
static bool is_authenticated_encryption(int ealg_id)
{
	switch (ealg_id)
	{
		case ESP_AES_CCM_8:
		case ESP_AES_CCM_12:
		case ESP_AES_CCM_16:
		case ESP_AES_GCM_8:
		case ESP_AES_GCM_12:
		case ESP_AES_GCM_16:
			return TRUE;
	}
	return FALSE;
}

/*
 * Add ESP alg info _with_ logic (policy):
 */
static void alg_info_esp_add(struct alg_info *alg_info, int ealg_id,
							 int ek_bits, int aalg_id, int ak_bits)
{
	/* Policy: default to 3DES */
	if (ealg_id == 0)
	{
		ealg_id = ESP_3DES;
	}
	if (ealg_id > 0)
	{
		if (is_authenticated_encryption(ealg_id))
		{
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								AUTH_ALGORITHM_NONE, 0);
		}
		else if (aalg_id > 0)
		{
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								aalg_id, ak_bits);
		}
		else
		{
			/* Policy: default to SHA-1 and MD5 */
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								AUTH_ALGORITHM_HMAC_SHA1, ak_bits);
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								AUTH_ALGORITHM_HMAC_MD5, ak_bits);
		}
	}
}

static void __alg_info_ike_add (struct alg_info_ike *alg_info, int ealg_id,
								unsigned ek_bits, int aalg_id, unsigned ak_bits,
								int modp_id)
{
	struct ike_info *ike_info = alg_info->ike;
	unsigned cnt = alg_info->alg_info_cnt;
	unsigned i;

	/* check for overflows */
	passert(cnt < countof(alg_info->ike));

	/* dont add duplicates */
   for (i = 0; i < cnt; i++)
   {
		if (ike_info[i].ike_ealg == ealg_id
		&& (!ek_bits || ike_info[i].ike_eklen == ek_bits)
		&&  ike_info[i].ike_halg == aalg_id
		&& (!ak_bits || ike_info[i].ike_hklen == ak_bits)
		&&  ike_info[i].ike_modp==modp_id)
			return;
	}

	ike_info[cnt].ike_ealg = ealg_id;
	ike_info[cnt].ike_eklen = ek_bits;
	ike_info[cnt].ike_halg = aalg_id;
	ike_info[cnt].ike_hklen = ak_bits;
	ike_info[cnt].ike_modp = modp_id;
	alg_info->alg_info_cnt++;

	DBG(DBG_CRYPT,
		DBG_log("ikg alg added: %s_%d/%s/%s, cnt=%d",
				enum_show(&oakley_enc_names, ealg_id), ek_bits,
				enum_show(&oakley_hash_names, aalg_id),
				enum_show(&oakley_group_names, modp_id),
				alg_info->alg_info_cnt)
	)
}

/*
 * Proposals will be built by looping over default_ike_groups array and
 * merging alg_info (ike_info) contents
 */

static int default_ike_groups[] = {
	MODP_1536_BIT,
	MODP_1024_BIT
};

/*
 *      Add IKE alg info _with_ logic (policy):
 */
static void alg_info_ike_add (struct alg_info *alg_info, int ealg_id,
							  int ek_bits, int aalg_id, int ak_bits, int modp_id)
{
	int i = 0;
	int n_groups = countof(default_ike_groups);

	/* if specified modp_id avoid loop over default_ike_groups */
	if (modp_id)
	{
		n_groups=0;
		goto in_loop;
	}

	for (; n_groups--; i++)
	{
		modp_id = default_ike_groups[i];
in_loop:
		/* Policy: default to 3DES */
		if (ealg_id == 0)
		{
			ealg_id = OAKLEY_3DES_CBC;
		}
		if (ealg_id > 0)
		{
			if (aalg_id > 0)
			{
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
								   ealg_id, ek_bits,
								   aalg_id, ak_bits,
								   modp_id);
			}
			else
			{
				/* Policy: default to MD5 and SHA */
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
								   ealg_id, ek_bits,
								   OAKLEY_MD5, ak_bits,
								   modp_id);
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
								   ealg_id, ek_bits,
								   OAKLEY_SHA, ak_bits,
								   modp_id);
			}
		}
	}
}

static status_t alg_info_add(chunk_t alg, unsigned protoid,
							 int *ealg, size_t *ealg_keysize,
							 int *aalg, size_t *aalg_keysize, int *dh_group)
{
	const proposal_token_t *token = proposal_get_token(alg.ptr, alg.len);

	if (token == NULL)
	{
		return FAILED;
	}
	switch (token->type)
	{
		case ENCRYPTION_ALGORITHM:
			if (*ealg != 0)
			{
				return FAILED;
			}
			*ealg = (protoid == PROTO_ISAKMP) ?
					 oakley_from_encryption_algorithm(token->algorithm) :
					 esp_from_encryption_algorithm(token->algorithm);
			if (*ealg == 0)
			{
				return FAILED;
			}
			*ealg_keysize = token->keysize;
			break;
		case INTEGRITY_ALGORITHM:
			if (*aalg != 0)
			{
				return FAILED;
			}
			*aalg = (protoid == PROTO_ISAKMP) ?
					 oakley_from_integrity_algorithm(token->algorithm) :
					 esp_from_integrity_algorithm(token->algorithm);
			if (*aalg == 0)
			{
				return FAILED;
			}
			*aalg_keysize = token->keysize;
			break;
		case DIFFIE_HELLMAN_GROUP:
			if (protoid == PROTO_ISAKMP)
			{
				if (*dh_group != 0)
				{
					return FAILED;
				}
				*dh_group = token->algorithm;
			}
			break;
		default:
			return FAILED;
	}
	return SUCCESS;
}


static status_t alg_info_parse_str(struct alg_info *alg_info, char *alg_str)
{
	char *strict, *single;
	status_t status = SUCCESS;

	strict = alg_str + strlen(alg_str) - 1;
	if (*strict == '!')
	{
		alg_info->alg_info_flags |= ALG_INFO_F_STRICT;
		*strict = '\0';
	}
	while ((single = strsep(&alg_str, ",")))
	{
		chunk_t string = { (u_char *)single, strlen(single) };
		int ealg = 0;
		int aalg = 0;
		int dh_group = 0;
		size_t ealg_keysize = 0;
		size_t aalg_keysize = 0;

		eat_whitespace(&string);

		if (string.len > 0)
		{
			chunk_t alg;

			/* get all token, separated by '-' */
			while (extract_token(&alg, '-', &string))
			{
				status |= alg_info_add(alg, alg_info->alg_info_protoid,
									   &ealg, &ealg_keysize,
									   &aalg, &aalg_keysize, &dh_group);
			}
			if (string.len)
			{
				status |= alg_info_add(string, alg_info->alg_info_protoid,
									   &ealg, &ealg_keysize,
									   &aalg, &aalg_keysize, &dh_group);
			}
		}
		if (status == SUCCESS)

		{
			switch (alg_info->alg_info_protoid)
			{
				case PROTO_IPSEC_ESP:
					alg_info_esp_add(alg_info, ealg, ealg_keysize,
											   aalg, aalg_keysize);
					break;
				case PROTO_ISAKMP:
					alg_info_ike_add(alg_info, ealg, ealg_keysize,
											   aalg, aalg_keysize,
											   dh_group);
					break;
				default:
					break;
			}
		}
	}
	return status;
}

struct alg_info_esp *alg_info_esp_create_from_str(char *alg_str)
{
	struct alg_info_esp *alg_info_esp;
	char esp_buf[BUF_LEN];
	char *pfs_name;
	status_t status = SUCCESS;
	/*
	 * alg_info storage should be sized dynamically
	 * but this may require 2passes to know
	 * transform count in advance.
	 */
	alg_info_esp = malloc_thing (struct alg_info_esp);
	zero(alg_info_esp);

	pfs_name=index (alg_str, ';');
	if (pfs_name)
	{
		memcpy(esp_buf, alg_str, pfs_name-alg_str);
		esp_buf[pfs_name-alg_str] = 0;
		alg_str = esp_buf;
		pfs_name++;

		/* if pfs strings AND first char is not '0' */
		if (*pfs_name && pfs_name[0] != '0')
		{
			const proposal_token_t *token;

			token = proposal_get_token(pfs_name, strlen(pfs_name));
			if (token == NULL || token->type != DIFFIE_HELLMAN_GROUP)
			{
				/* Bomb if pfsgroup not found */
				DBG(DBG_CRYPT,
					DBG_log("alg_info_esp_create_from_str(): pfsgroup \"%s\" not found"
						, pfs_name)
				)
				status = FAILED;
				goto out;
			}
			alg_info_esp->esp_pfsgroup = token->algorithm;
		}
	}
	else
	{
		alg_info_esp->esp_pfsgroup = 0;
	}
	alg_info_esp->alg_info_protoid = PROTO_IPSEC_ESP;
	status = alg_info_parse_str((struct alg_info *)alg_info_esp, alg_str);

out:
	if (status == SUCCESS)
	{
		alg_info_esp->ref_cnt = 1;
		return alg_info_esp;
	}
	else
	{
		free(alg_info_esp);
		return NULL;
	}
}

struct alg_info_ike *alg_info_ike_create_from_str(char *alg_str)
{
	struct alg_info_ike *alg_info_ike;
	/*
	 * alg_info storage should be sized dynamically
	 * but this may require 2passes to know
	 * transform count in advance.
	 */
	alg_info_ike = malloc_thing (struct alg_info_ike);
	zero(alg_info_ike);
	alg_info_ike->alg_info_protoid = PROTO_ISAKMP;

	if (alg_info_parse_str((struct alg_info *)alg_info_ike, alg_str) == SUCCESS)
	{
		alg_info_ike->ref_cnt = 1;	
		return alg_info_ike;
	}
	else
	{
		free(alg_info_ike);
		return NULL;
	}
}

/*
 *      alg_info struct can be shared by
 *      several connections instances,
 *      handle free() with ref_cnts
 */
void
alg_info_addref(struct alg_info *alg_info)
{
	if (alg_info != NULL)
	{
		alg_info->ref_cnt++;
	}
}

void
alg_info_delref(struct alg_info **alg_info_p)
{
	struct alg_info *alg_info = *alg_info_p;

	if (alg_info != NULL)
	{
		passert(alg_info->ref_cnt != 0);
		alg_info->ref_cnt--;
		if (alg_info->ref_cnt == 0)
		{
			alg_info_free(alg_info);
		}
		*alg_info_p = NULL;
	}
}

/* snprint already parsed transform list (alg_info) */
int
alg_info_snprint(char *buf, int buflen, struct alg_info *alg_info)
{
	char *ptr = buf;
	int np = 0;
	struct esp_info *esp_info;
	struct ike_info *ike_info;
	int cnt;

	switch (alg_info->alg_info_protoid) {
	case PROTO_IPSEC_ESP:
		{
			struct alg_info_esp *alg_info_esp = (struct alg_info_esp *)alg_info;

			ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt)
			{
				np = snprintf(ptr, buflen, "%s",
						enum_show(&esp_transform_names, esp_info->esp_ealg_id));
				ptr += np;
				buflen -= np;
				if (esp_info->esp_ealg_keylen)
				{
					np = snprintf(ptr, buflen, "_%u", esp_info->esp_ealg_keylen);
					ptr += np;
					buflen -= np;
				}
				np = snprintf(ptr, buflen, "/%s, ",
						enum_show(&auth_alg_names, esp_info->esp_aalg_id));
				ptr += np;
				buflen -= np;
				if (buflen < 0)
					goto out;
			}
			if (alg_info_esp->esp_pfsgroup)
			{
				np = snprintf(ptr, buflen, "; pfsgroup=%s; ",
						enum_show(&oakley_group_names, alg_info_esp->esp_pfsgroup));
				ptr += np;
				buflen -= np;
				if (buflen < 0)
					goto out;
			}
			break;
		}

	case PROTO_ISAKMP:
		ALG_INFO_IKE_FOREACH((struct alg_info_ike *)alg_info, ike_info, cnt)
		{
			np = snprintf(ptr, buflen, "%s",
					enum_show(&oakley_enc_names, ike_info->ike_ealg));
			ptr += np;
			buflen -= np;
			if (ike_info->ike_eklen)
			{
				np = snprintf(ptr, buflen, "_%u", ike_info->ike_eklen);
				ptr += np;
				buflen -= np;
			}
			np = snprintf(ptr, buflen, "/%s/%s, ",
					enum_show(&oakley_hash_names, ike_info->ike_halg),
					enum_show(&oakley_group_names, ike_info->ike_modp));
			ptr += np;
			buflen -= np;
			if (buflen < 0)
				goto out;
		}
		break;
	default:
		np = snprintf(buf, buflen, "INVALID protoid=%d\n"
				, alg_info->alg_info_protoid);
		ptr += np;
		buflen -= np;
		goto out;
   }

   np = snprintf(ptr, buflen, "%s"
			, alg_info->alg_info_flags & ALG_INFO_F_STRICT?
			"strict":"");
   ptr += np;
   buflen -= np;
out:
	if (buflen < 0)
	{
		loglog(RC_LOG_SERIOUS
			, "buffer space exhausted in alg_info_snprint_ike(), buflen=%d"
			, buflen);
	}

	return ptr - buf;
}

int alg_info_snprint_esp(char *buf, int buflen, struct alg_info_esp *alg_info)
{
	char *ptr = buf;

	int cnt = alg_info->alg_info_cnt;
	struct esp_info *esp_info = alg_info->esp;

	while (cnt--)
	{
		if (kernel_alg_esp_enc_ok(esp_info->esp_ealg_id, 0, NULL)
		&&  kernel_alg_esp_auth_ok(esp_info->esp_aalg_id, NULL))
		{
			u_int eklen = (esp_info->esp_ealg_keylen)
					? esp_info->esp_ealg_keylen
					: kernel_alg_esp_enc_keylen(esp_info->esp_ealg_id)
							* BITS_PER_BYTE;

			u_int aklen = esp_info->esp_aalg_keylen
					? esp_info->esp_aalg_keylen
					: kernel_alg_esp_auth_keylen(esp_info->esp_aalg_id)
							* BITS_PER_BYTE;

			int ret = snprintf(ptr, buflen, "%d_%03d-%d_%03d, ",
						   esp_info->esp_ealg_id, eklen,
						   esp_info->esp_aalg_id, aklen);
			ptr += ret;
			buflen -= ret;
			if (buflen < 0)
				break;
		}
		esp_info++;
	}
	return ptr - buf;
}

int alg_info_snprint_ike(char *buf, int buflen, struct alg_info_ike *alg_info)
{
	char *ptr = buf;

	int cnt = alg_info->alg_info_cnt;
	struct ike_info *ike_info = alg_info->ike;

	while (cnt--)
	{
		struct encrypt_desc *enc_desc = ike_alg_get_crypter(ike_info->ike_ealg);
		struct hash_desc *hash_desc = ike_alg_get_hasher(ike_info->ike_halg);
		struct dh_desc *dh_desc = ike_alg_get_dh_group(ike_info->ike_modp);

		if (enc_desc &&  hash_desc && dh_desc)
		{

			u_int eklen = (ike_info->ike_eklen)
						? ike_info->ike_eklen
						: enc_desc->keydeflen;

			u_int aklen = (ike_info->ike_hklen)
						? ike_info->ike_hklen
						: hash_desc->hash_digest_size * BITS_PER_BYTE;

			int ret = snprintf(ptr, buflen, "%d_%03d-%d_%03d-%d, ",
						   ike_info->ike_ealg, eklen,
						   ike_info->ike_halg, aklen,
						   ike_info->ike_modp);
			ptr += ret;
			buflen -= ret;
			if (buflen < 0)
				break;
		}
		ike_info++;
	}
	return ptr - buf;
}

