/* Kernel runtime algorithm handling interface
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>

#include <pfkeyv2.h>
#include <pfkey.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "packet.h"
#include "spdb.h"
#include "kernel.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "log.h"
#include "whack.h"
#include "db_ops.h"

/* ALG storage */
static struct sadb_alg esp_aalg[SADB_AALG_MAX+1];
static struct sadb_alg esp_ealg[SADB_EALG_MAX+1];
static int esp_ealg_num = 0;
static int esp_aalg_num = 0;

#define ESP_EALG_PRESENT(algo) (((algo)<=SADB_EALG_MAX)&&(esp_ealg[(algo)].sadb_alg_id==(algo)))
#define ESP_EALG_FOR_EACH_UPDOWN(algo) \
		for (algo=SADB_EALG_MAX; algo >0 ; algo--) \
				if (ESP_EALG_PRESENT(algo))
#define ESP_AALG_PRESENT(algo) ((algo<=SADB_AALG_MAX)&&(esp_aalg[(algo)].sadb_alg_id==(algo)))
#define ESP_AALG_FOR_EACH_UPDOWN(algo) \
		for (algo=SADB_AALG_MAX; algo >0 ; algo--) \
				if (ESP_AALG_PRESENT(algo))

static struct sadb_alg* sadb_alg_ptr (int satype, int exttype, int alg_id,
									  int rw)
{
	struct sadb_alg *alg_p = NULL;

	switch (exttype)
	{
	case SADB_EXT_SUPPORTED_AUTH:
		if (alg_id > SADB_AALG_MAX)
			return NULL;
		break;
	case SADB_EXT_SUPPORTED_ENCRYPT:
		if (alg_id > SADB_EALG_MAX)
			return NULL;
		break;
	default:
		return NULL;
	}

	switch (satype)
	{
	case SADB_SATYPE_ESP:
		alg_p = (exttype == SADB_EXT_SUPPORTED_ENCRYPT)?
					&esp_ealg[alg_id] : &esp_aalg[alg_id];
		/* get for write: increment elem count */
		if (rw)
		{
			(exttype == SADB_EXT_SUPPORTED_ENCRYPT)?
				esp_ealg_num++ : esp_aalg_num++;
		}
		break;
	case SADB_SATYPE_AH:
	default:
		return NULL;
	}

	return alg_p;
}

const struct sadb_alg* kernel_alg_sadb_alg_get(int satype, int exttype,
											   int alg_id)
{
	return sadb_alg_ptr(satype, exttype, alg_id, 0);
}

/*
 *      Forget previous registration
 */
static void kernel_alg_init(void)
{
	DBG(DBG_KERNEL,
		DBG_log("alg_init(): memset(%p, 0, %d) memset(%p, 0, %d)",
				&esp_aalg,  (int)sizeof (esp_aalg),
				&esp_ealg,  (int)sizeof (esp_ealg))
	)
	memset (&esp_aalg, 0, sizeof (esp_aalg));
	memset (&esp_ealg, 0, sizeof (esp_ealg));
	esp_ealg_num=esp_aalg_num = 0;
}

static int kernel_alg_add(int satype, int exttype,
						  const struct sadb_alg *sadb_alg)
{
	struct sadb_alg *alg_p = NULL;
	int alg_id = sadb_alg->sadb_alg_id;

	DBG(DBG_KERNEL,
		DBG_log("kernel_alg_add(): satype=%d, exttype=%d, alg_id=%d",
				satype, exttype, sadb_alg->sadb_alg_id)
	)
	if (!(alg_p = sadb_alg_ptr(satype, exttype, alg_id, 1)))
		return -1;

	/* This logic "mimics" KLIPS: first algo implementation will be used */
	if (alg_p->sadb_alg_id)
	{
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_add(): discarding already setup "
					"satype=%d, exttype=%d, alg_id=%d",
					satype, exttype, sadb_alg->sadb_alg_id)
		)
		return 0;
	}
	*alg_p = *sadb_alg;
	return 1;
}

bool kernel_alg_esp_enc_ok(u_int alg_id, u_int key_len,
					struct alg_info_esp *alg_info __attribute__((unused)))
{
	struct sadb_alg *alg_p = NULL;

	/*
	 * test #1: encrypt algo must be present
	 */
	int ret = ESP_EALG_PRESENT(alg_id);
	if (!ret) goto out;

	alg_p = &esp_ealg[alg_id];

	/*
	 * test #2: if key_len specified, it must be in range
	 */
	if (key_len
	&& (key_len < alg_p->sadb_alg_minbits || key_len > alg_p->sadb_alg_maxbits))
	{
		plog("kernel_alg_db_add() key_len not in range: alg_id=%d, "
			 "key_len=%d, alg_minbits=%d, alg_maxbits=%d"
			 , alg_id, key_len
			 , alg_p->sadb_alg_minbits
			 , alg_p->sadb_alg_maxbits);
		ret = FALSE;
	}

out:
	if (ret)
	{
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_esp_enc_ok(%d,%d): "
					"alg_id=%d, "
					"alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
					"res=%d, ret=%d"
					, alg_id, key_len
					, alg_p->sadb_alg_id
					, alg_p->sadb_alg_ivlen
					, alg_p->sadb_alg_minbits
					, alg_p->sadb_alg_maxbits
					, alg_p->sadb_alg_reserved
					, ret);
		)
	}
	else
	{
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_esp_enc_ok(%d,%d): NO", alg_id, key_len);
		)
	}
	return ret;
}

/*
 * ML: make F_STRICT logic consider enc,auth algorithms
 */
bool kernel_alg_esp_ok_final(u_int ealg, u_int key_len, u_int aalg,
							 struct alg_info_esp *alg_info)
{
	int ealg_insecure;

	/*
	 * key_len passed comes from esp_attrs read from peer
	 * For many older algorithms (eg 3DES) this key_len is fixed
	 * and get passed as 0.
	 * ... then get default key_len
	 */
	if (key_len == 0)
		key_len = kernel_alg_esp_enc_keylen(ealg) * BITS_PER_BYTE;

	/*
	 * simple test to toss low key_len, will accept it only
	 * if specified in "esp" string
	 */
	ealg_insecure = (key_len < 128) ;

	if (ealg_insecure
	|| (alg_info && alg_info->alg_info_flags & ALG_INFO_F_STRICT))
	{
		int i;
		struct esp_info *esp_info;

		if (alg_info)
		{
			ALG_INFO_ESP_FOREACH(alg_info, esp_info, i)
			{
				if (esp_info->esp_ealg_id == ealg
				&& (esp_info->esp_ealg_keylen == 0 || key_len == 0
					|| esp_info->esp_ealg_keylen == key_len)
				&&  esp_info->esp_aalg_id == aalg)
				{
					if (ealg_insecure)
					{
						loglog(RC_LOG_SERIOUS
							, "You should NOT use insecure ESP algorithms [%s (%d)]!"
							, enum_name(&esp_transform_names, ealg), key_len);
					}
					return TRUE;
				}
			}
		}
		plog("IPSec Transform [%s (%d), %s] refused due to %s",
				enum_name(&esp_transform_names, ealg), key_len,
				enum_name(&auth_alg_names, aalg),
				ealg_insecure ? "insecure key_len and enc. alg. not listed in \"esp\" string" : "strict flag");
		return FALSE;
	}
	return TRUE;
}

/**
 * Load kernel_alg arrays pluto's SADB_REGISTER user by pluto/kernel.c
 */
void kernel_alg_register_pfkey(const struct sadb_msg *msg_buf, int buflen)
{
	/* Trick: one 'type-mangle-able' pointer to ease offset/assign */
	union {
		const struct sadb_msg *msg;
		const struct sadb_supported *supported;
		const struct sadb_ext *ext;
		const struct sadb_alg *alg;
		const char *ch;
	} sadb;

	int satype;
	int msglen;
	int i = 0;

	/* Initialize alg arrays */
	kernel_alg_init();
	satype = msg_buf->sadb_msg_satype;
	sadb.msg = msg_buf;
	msglen = sadb.msg->sadb_msg_len*IPSEC_PFKEYv2_ALIGN;
	msglen -= sizeof(struct sadb_msg);
	buflen -= sizeof(struct sadb_msg);
	passert(buflen > 0);

	sadb.msg++;

	while (msglen)
	{
		int supp_exttype = sadb.supported->sadb_supported_exttype;
		int supp_len = sadb.supported->sadb_supported_len*IPSEC_PFKEYv2_ALIGN;

		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
					"sadb_msg_len=%d sadb_supported_len=%d"
					, satype==SADB_SATYPE_ESP? "ESP" : "AH"
					, msg_buf->sadb_msg_len, supp_len)
		)
		sadb.supported++;
		msglen -= supp_len;
		buflen -= supp_len;
		passert(buflen >= 0);

		for (supp_len -= sizeof(struct sadb_supported);
			 supp_len;
			 supp_len -= sizeof(struct sadb_alg), sadb.alg++,i++)
		{
			kernel_alg_add(satype, supp_exttype, sadb.alg);

			DBG(DBG_KERNEL,
				DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
						"alg[%d], exttype=%d, satype=%d, alg_id=%d, "
						"alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
						"res=%d"
						, satype == SADB_SATYPE_ESP? "ESP" : "AH"
						, i
						, supp_exttype
						, satype
						, sadb.alg->sadb_alg_id
						, sadb.alg->sadb_alg_ivlen
						, sadb.alg->sadb_alg_minbits
						, sadb.alg->sadb_alg_maxbits
						, sadb.alg->sadb_alg_reserved)
			)
			/* if AES_CBC is registered then also register AES_CCM and AES_GCM */
			if (satype == SADB_SATYPE_ESP &&
				supp_exttype == SADB_EXT_SUPPORTED_ENCRYPT &&
				sadb.alg->sadb_alg_id == SADB_X_EALG_AESCBC)
			{
				struct sadb_alg alg = *sadb.alg;
				int alg_id;

				for (alg_id = SADB_X_EALG_AES_CCM_ICV8;
					 alg_id <= SADB_X_EALG_AES_GCM_ICV16; alg_id++)
				{
					if (alg_id != ESP_UNASSIGNED_17)
					{
						alg.sadb_alg_id = alg_id;
						kernel_alg_add(satype, supp_exttype, &alg);
					}
				}

				/* also register AES_GMAC */
				alg.sadb_alg_id = SADB_X_EALG_NULL_AES_GMAC;
				kernel_alg_add(satype, supp_exttype, &alg);
			}
			/* if SHA2_256 is registered then also register SHA2_256_96 */
			if (satype == SADB_SATYPE_ESP &&
				supp_exttype == SADB_EXT_SUPPORTED_AUTH &&
				sadb.alg->sadb_alg_id == SADB_X_AALG_SHA2_256HMAC)
			{
				struct sadb_alg alg = *sadb.alg;

				alg.sadb_alg_id = SADB_X_AALG_SHA2_256_96HMAC;
				kernel_alg_add(satype, supp_exttype, &alg);
			}
		}
	}
}

u_int kernel_alg_esp_enc_keylen(u_int alg_id)
{
	u_int keylen = 0;

	if (!ESP_EALG_PRESENT(alg_id))
	{
		goto none;
	}
	keylen = esp_ealg[alg_id].sadb_alg_maxbits/BITS_PER_BYTE;

	switch (alg_id)
	{
		/*
		 * this is veryUgly[TM]
		 * Peer should have sent KEY_LENGTH attribute for ESP_AES
		 * but if not do force it to 128 instead of using sadb_alg_maxbits
		 * from kernel.
		 */
		case ESP_AES:
			keylen = 128/BITS_PER_BYTE;
			break;
	}

none:
	DBG(DBG_KERNEL,
		DBG_log("kernel_alg_esp_enc_keylen(): alg_id=%d, keylen=%d",
				alg_id, keylen)
	)
	return keylen;
}

struct sadb_alg* kernel_alg_esp_sadb_alg(u_int alg_id)
{
	struct sadb_alg *sadb_alg = (ESP_EALG_PRESENT(alg_id))
				? &esp_ealg[alg_id] : NULL;

	DBG(DBG_KERNEL,
		DBG_log("kernel_alg_esp_sadb_alg(): alg_id=%d, sadb_alg=%p"
				, alg_id, sadb_alg)
	)
	return sadb_alg;
}

/**
 * Print the name of a kernel algorithm
 */
static void print_alg(char *buf, int *len, enum_names *alg_names, int alg_type)
{
	char alg_name[BUF_LEN];
	int alg_name_len;

	alg_name_len = sprintf(alg_name, " %s", enum_name(alg_names, alg_type));
	if (*len + alg_name_len > CRYPTO_MAX_ALG_LINE)
	{
		whack_log(RC_COMMENT, "%s", buf);
		*len = sprintf(buf, "             ");
	}
	sprintf(buf + *len, "%s", alg_name);
	*len += alg_name_len;
}

void kernel_alg_list(void)
{
	char buf[BUF_LEN];
	int len;
	u_int sadb_id;

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of registered ESP Algorithms:");
	whack_log(RC_COMMENT, " ");

	len = sprintf(buf, "  encryption:");
	for (sadb_id = 1; sadb_id <= SADB_EALG_MAX; sadb_id++)
	{
		if (ESP_EALG_PRESENT(sadb_id))
		{
			print_alg(buf, &len, &esp_transform_names, sadb_id);
		}
	}
	whack_log(RC_COMMENT, "%s", buf);

	len = sprintf(buf, "  integrity: ");
	for (sadb_id = 1; sadb_id <= SADB_AALG_MAX; sadb_id++)
	{
		if (ESP_AALG_PRESENT(sadb_id))
		{
			u_int aaid = alg_info_esp_sadb2aa(sadb_id);

			print_alg(buf, &len, &auth_alg_names, aaid);
		}
	}
	whack_log(RC_COMMENT, "%s", buf);
}

void kernel_alg_show_connection(connection_t *c, const char *instance)
{
	struct state *st = state_with_serialno(c->newest_ipsec_sa);

	if (st && st->st_esp.present)
	{
		const char *aalg_name, *pfsgroup_name;

		aalg_name = (c->policy & POLICY_AUTHENTICATE) ?
					enum_show(&ah_transform_names, st->st_ah.attrs.transid):
					enum_show(&auth_alg_names, st->st_esp.attrs.auth);

		pfsgroup_name = (c->policy & POLICY_PFS) ?
						(c->alg_info_esp && c->alg_info_esp->esp_pfsgroup) ?
							enum_show(&oakley_group_names,
										  c->alg_info_esp->esp_pfsgroup) :
							"<Phase1>" : "<N/A>";

		if (st->st_esp.attrs.key_len)
		{
			whack_log(RC_COMMENT, "\"%s\"%s:   ESP%s proposal: %s_%u/%s/%s",
				c->name, instance,
				(st->st_ah.present) ? "/AH" : "",
				enum_show(&esp_transform_names, st->st_esp.attrs.transid),
				st->st_esp.attrs.key_len, aalg_name, pfsgroup_name);
		}
		else
		{
			whack_log(RC_COMMENT, "\"%s\"%s:   ESP%s proposal: %s/%s/%s",
				c->name, instance,
				(st->st_ah.present) ? "/AH" : "",
				enum_show(&esp_transform_names, st->st_esp.attrs.transid),
				aalg_name, pfsgroup_name);
		}
	}
}

bool kernel_alg_esp_auth_ok(u_int auth,
							struct alg_info_esp *alg_info __attribute__((unused)))
{
	return ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth));
}

u_int kernel_alg_esp_auth_keylen(u_int auth)
{
	u_int sadb_aalg = alg_info_esp_aa2sadb(auth);

	u_int a_keylen = (sadb_aalg)
				   ? esp_aalg[sadb_aalg].sadb_alg_maxbits/BITS_PER_BYTE
				   : 0;

	DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING,
		DBG_log("kernel_alg_esp_auth_keylen(auth=%d, sadb_aalg=%d): "
				"a_keylen=%d", auth, sadb_aalg, a_keylen)
	)
	return a_keylen;
}

struct esp_info* kernel_alg_esp_info(int transid, int auth)
{
	int sadb_aalg, sadb_ealg;
	static struct esp_info ei_buf;

	sadb_ealg = transid;
	sadb_aalg = alg_info_esp_aa2sadb(auth);

	if (!ESP_EALG_PRESENT(sadb_ealg))
		goto none;
	if (!ESP_AALG_PRESENT(sadb_aalg))
		goto none;

	memset(&ei_buf, 0, sizeof (ei_buf));
	ei_buf.transid = transid;
	ei_buf.auth = auth;

	/* don't return "default" keylen because this value is used from
	 * setup_half_ipsec_sa() to "validate" keylen
	 * In effect,  enckeylen will be used as "max" value
	 */
	ei_buf.enckeylen = esp_ealg[sadb_ealg].sadb_alg_maxbits/BITS_PER_BYTE;
	ei_buf.authkeylen = esp_aalg[sadb_aalg].sadb_alg_maxbits/BITS_PER_BYTE;
	ei_buf.encryptalg = sadb_ealg;
	ei_buf.authalg = sadb_aalg;

	DBG(DBG_PARSING,
		DBG_log("kernel_alg_esp_info():"
				"transid=%d, auth=%d, ei=%p, "
				"enckeylen=%d, authkeylen=%d, encryptalg=%d, authalg=%d",
				transid, auth, &ei_buf,
				(int)ei_buf.enckeylen, (int)ei_buf.authkeylen,
				ei_buf.encryptalg, ei_buf.authalg)
	)
	return &ei_buf;

none:
	DBG(DBG_PARSING,
		DBG_log("kernel_alg_esp_info():"
				"transid=%d, auth=%d, ei=NULL",
				transid, auth)
	)
	return NULL;
}

static void kernel_alg_policy_algorithms(struct esp_info *esp_info)
{
	u_int ealg_id = esp_info->esp_ealg_id;

	switch(ealg_id)
	{
	case 0:
	case ESP_DES:
	case ESP_3DES:
	case ESP_NULL:
	case ESP_CAST:
			break;
	default:
		if (!esp_info->esp_ealg_keylen)
		{
			/* algos that need  KEY_LENGTH
			 *
			 * Note: this is a very dirty hack ;-)
			 * Idea: Add a key_length_needed attribute to
			 * esp_ealg ??
			 */
			esp_info->esp_ealg_keylen = esp_ealg[ealg_id].sadb_alg_maxbits;
		}
	}
}

static bool kernel_alg_db_add(struct db_context *db_ctx,
							  struct esp_info *esp_info, lset_t policy)
{
	u_int ealg_id, aalg_id;

	ealg_id = esp_info->esp_ealg_id;

	if (!ESP_EALG_PRESENT(ealg_id))
	{
		DBG_log("kernel_alg_db_add() kernel enc ealg_id=%d not present", ealg_id);
		return FALSE;
	}

	if (!(policy & POLICY_AUTHENTICATE) &&    /* skip ESP auth attrs for AH */
		esp_info->esp_aalg_id != AUTH_ALGORITHM_NONE)
	{
		aalg_id = alg_info_esp_aa2sadb(esp_info->esp_aalg_id);

		if (!ESP_AALG_PRESENT(aalg_id))
		{
			DBG_log("kernel_alg_db_add() kernel auth aalg_id=%d not present",
					aalg_id);
			return FALSE;
		}
	}

	/* do algo policy */
	kernel_alg_policy_algorithms(esp_info);

	/*  open new transformation */
	db_trans_add(db_ctx, ealg_id);

	/* add ESP auth attr if not AH or AEAD */
	if (!(policy & POLICY_AUTHENTICATE) &&
		esp_info->esp_aalg_id != AUTH_ALGORITHM_NONE)
	{
		db_attr_add_values(db_ctx, AUTH_ALGORITHM, esp_info->esp_aalg_id);
	}

	/* add keylength if specified in esp= string */
	if (esp_info->esp_ealg_keylen)
	{
		db_attr_add_values(db_ctx, KEY_LENGTH, esp_info->esp_ealg_keylen);
	}

	return TRUE;
}

/*
 *      Create proposal with runtime kernel algos, merging
 *      with passed proposal if not NULL
 *
 *      for now this function does free() previous returned
 *      malloced pointer (this quirk allows easier spdb.c change)
 */
struct db_context* kernel_alg_db_new(struct alg_info_esp *alg_info,
									 lset_t policy)
{
	const struct esp_info *esp_info;
	struct esp_info tmp_esp_info;
	struct db_context *ctx_new = NULL;
	u_int trans_cnt = esp_ealg_num * esp_aalg_num;

	if (!(policy & POLICY_ENCRYPT))     /* not possible, I think  */
	{
		return NULL;
	}

	/* pass aprox. number of transforms and attributes */
	ctx_new = db_prop_new(PROTO_IPSEC_ESP, trans_cnt, trans_cnt * 2);

	if (alg_info)
	{
		int i;

		ALG_INFO_ESP_FOREACH(alg_info, esp_info, i)
		{
			tmp_esp_info = *esp_info;
			kernel_alg_db_add(ctx_new, &tmp_esp_info, policy);
		}
	}
	return ctx_new;
}

