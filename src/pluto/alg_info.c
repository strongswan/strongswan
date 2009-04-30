/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
#include <ipsec_policy.h>
#include <pfkeyv2.h>

#include "alg_info.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"
#include "sha1.h"
#include "md5.h"
#include "crypto.h"
#include "kernel_alg.h"
#include "ike_alg.h"

/*
 * sadb/ESP aa attrib converters
 */
int
alg_info_esp_aa2sadb(int auth)
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
			sadb_aalg = auth;
			break;
		default:
			/* loose ... */
			sadb_aalg = auth;
	}
	return sadb_aalg;
}

int /* __attribute__ ((unused)) */
alg_info_esp_sadb2aa(int sadb_aalg)
{
	int auth = 0;

	switch(sadb_aalg) {
		case SADB_AALG_MD5HMAC:
		case SADB_AALG_SHA1HMAC:
			auth = sadb_aalg - 1;
			break;
		/* since they are the same ...  :)  */
		case AUTH_ALGORITHM_HMAC_SHA2_256:
		case AUTH_ALGORITHM_HMAC_SHA2_384:
		case AUTH_ALGORITHM_HMAC_SHA2_512:
		case AUTH_ALGORITHM_HMAC_RIPEMD:
			auth = sadb_aalg;
			break;
		default:
			/* loose ... */
			auth = sadb_aalg;
	}
	return auth;
}

/*
 * Search enum_name array with in prefixed uppercase
 */
static int
enum_search_prefix (enum_names *ed, const char *prefix, const char *str, int strlen)
{
	char buf[64];
	char *ptr;
	int ret;
	int len = sizeof(buf) - 1;  /* reserve space for final \0 */

	for (ptr = buf; *prefix; *ptr++ = *prefix++, len--);
	while (strlen-- && len-- && *str) *ptr++ = toupper(*str++);
	*ptr = 0;

	DBG(DBG_CRYPT,
		DBG_log("enum_search_prefix () calling enum_search(%p, \"%s\")"
			, ed, buf)
	)
	ret = enum_search(ed, buf);
	return ret;
}

/*
 * Search enum_name array with in prefixed and postfixed uppercase
 */
static int
enum_search_ppfix (enum_names *ed, const char *prefix, const char *postfix, const char *str, int strlen)
{
	char buf[64];
	char *ptr;
	int ret;
	int len = sizeof(buf) - 1;  /* reserve space for final \0 */

	for (ptr = buf; *prefix; *ptr++ = *prefix++, len--);
	while (strlen-- && len-- && *str) *ptr++ = toupper(*str++);
	while (len-- && *postfix) *ptr++ = *postfix++;
	*ptr = 0;

	DBG(DBG_CRYPT,
		DBG_log("enum_search_ppfixi () calling enum_search(%p, \"%s\")"
			, ed, buf)
	)
	ret = enum_search(ed, buf);
	return ret;
}

/*
 * Search esp_transformid_names for a match, eg:
 *      "3des" <=> "ESP_3DES"
 */
#define ESP_MAGIC_ID 0x00ffff01

static int
ealg_getbyname_esp(const char *const str, int len)
{
	if (!str || !*str)
	{
		return -1;
	}

	/* leave special case for eg:  "id248" string */
	if (streq("id", str))
	{
		return ESP_MAGIC_ID;
	}
	return enum_search_prefix(&esp_transformid_names, "ESP_", str, len);
}

/*
 * Search auth_alg_names for a match, eg:
 *      "md5" <=> "AUTH_ALGORITHM_HMAC_MD5"
 */
static int
aalg_getbyname_esp(const char *const str, int len)
{
	int ret;
	unsigned num;

	if (!str || !*str)
		return -1;

	/* interpret 'SHA' as 'SHA1' */
	if (strncasecmp("SHA", str, len) == 0)
		return AUTH_ALGORITHM_HMAC_SHA1;

	/* interpret 'AESXCBC' as 'AES_XCBC_MAC' */
	if (strncasecmp("AESXCBC", str, len) == 0)
		return AUTH_ALGORITHM_AES_XCBC_MAC;

	ret = enum_search_prefix(&auth_alg_names,"AUTH_ALGORITHM_HMAC_", str ,len);
	if (ret >= 0)
		return ret;

	ret = enum_search_prefix(&auth_alg_names,"AUTH_ALGORITHM_", str, len);
	if (ret >= 0)
		return ret;

	sscanf(str, "id%d%n", &ret, &num);
	return (ret >= 0 && num != strlen(str))? -1 : ret;
}

static int
modp_getbyname_esp(const char *const str, int len)
{
	int ret;

	if (!str || !*str)
		return -1;
	
	ret = enum_search_prefix(&oakley_group_names,"OAKLEY_GROUP_", str, len);
	if (ret >= 0)
		return ret;

	ret = enum_search_ppfix(&oakley_group_names, "OAKLEY_GROUP_", " (extension)", str, len);
	return ret;
}

void 
alg_info_free(struct alg_info *alg_info)
{
	free(alg_info);
}

/*
 * Raw add routine: only checks for no duplicates
 */
static void
__alg_info_esp_add (struct alg_info_esp *alg_info, int ealg_id, unsigned ek_bits, int aalg_id, unsigned ak_bits)
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
			return;
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
		DBG_log("__alg_info_esp_add() ealg=%d aalg=%d cnt=%d"
			, ealg_id, aalg_id, alg_info->alg_info_cnt)
	)
}

/*
 * Add ESP alg info _with_ logic (policy):
 */
static void
alg_info_esp_add (struct alg_info *alg_info, int ealg_id, int ek_bits, int aalg_id, int ak_bits)
{
	/* Policy: default to 3DES */
	if (ealg_id == 0)
		ealg_id = ESP_3DES;

	if (ealg_id > 0)
	{
#ifndef NO_PLUTO
		if (aalg_id > 0)
#else
		/* Allow no auth for manual conns (from spi.c) */
		if (aalg_id >= 0)
#endif
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								aalg_id, ak_bits);
		else
		{
			/* Policy: default to MD5 and SHA1 */
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								AUTH_ALGORITHM_HMAC_MD5, ak_bits);
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
								ealg_id, ek_bits,
								AUTH_ALGORITHM_HMAC_SHA1, ak_bits);
		}
	}
}

#ifndef NO_PLUTO
/**************************************
 *
 *      IKE alg
 *
 *************************************/
/*
 * Search oakley_enc_names for a match, eg:
 *      "3des_cbc" <=> "OAKLEY_3DES_CBC"
 */
static int
ealg_getbyname_ike(const char *const str, int len)
{
	int ret;

	if (!str || !*str)
		return -1;

	ret = enum_search_prefix(&oakley_enc_names,"OAKLEY_", str, len);
	if (ret >= 0)
		return ret;

	ret = enum_search_ppfix(&oakley_enc_names, "OAKLEY_", "_CBC", str, len);
	return ret;
}

/*
 * Search  oakley_hash_names for a match, eg:
 *      "md5" <=> "OAKLEY_MD5"
 */
static int
aalg_getbyname_ike(const char *const str, int len)
{
	int ret;
	unsigned num;

	if (!str || !*str)
		return -1;

	/* interpret 'SHA1' as 'SHA' */
	if (strncasecmp("SHA1", str, len) == 0)
		return enum_search(&oakley_hash_names, "OAKLEY_SHA");

	ret = enum_search_prefix(&oakley_hash_names,"OAKLEY_", str, len);
	if (ret >= 0)
		return ret;

	sscanf(str, "id%d%n", &ret, &num);
	return (ret >=0 && num != strlen(str))? -1 : ret;
}

/*
 * Search oakley_group_names for a match, eg:
 *      "modp1024" <=> "OAKLEY_GROUP_MODP1024"
 */
static int
modp_getbyname_ike(const char *const str, int len)
{
	int ret;

	if (!str || !*str)
		return -1;

	ret = enum_search_prefix(&oakley_group_names,"OAKLEY_GROUP_", str, len);
	if (ret >= 0)
		return ret;

	ret = enum_search_ppfix(&oakley_group_names, "OAKLEY_GROUP_", " (extension)", str, len);
	return ret;
}

static void
__alg_info_ike_add (struct alg_info_ike *alg_info, int ealg_id, unsigned ek_bits, int aalg_id, unsigned ak_bits, int modp_id)
{
	struct ike_info *ike_info = alg_info->ike;
	unsigned cnt = alg_info->alg_info_cnt;
	unsigned i;

	/* check for overflows */
	passert(cnt < countof(alg_info->ike));

	/* dont add duplicates */
   for (i = 0;i < cnt; i++)
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
		DBG_log("__alg_info_ike_add() ealg=%d aalg=%d modp_id=%d, cnt=%d"
				, ealg_id, aalg_id, modp_id
				, alg_info->alg_info_cnt)
	)
}

/*
 * Proposals will be built by looping over default_ike_groups array and
 * merging alg_info (ike_info) contents
 */

static int default_ike_groups[] = { 
	OAKLEY_GROUP_MODP1536,
	OAKLEY_GROUP_MODP1024
};

/*      
 *      Add IKE alg info _with_ logic (policy):
 */
static void
alg_info_ike_add (struct alg_info *alg_info, int ealg_id, int ek_bits, int aalg_id, int ak_bits, int modp_id)
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
			ealg_id = OAKLEY_3DES_CBC;

		if (ealg_id > 0)
		{
			if (aalg_id > 0)
				__alg_info_ike_add((struct alg_info_ike *)alg_info,
								   ealg_id, ek_bits,
								   aalg_id, ak_bits,
								   modp_id);
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
#endif /* NO_PLUTO */

/*      
 *      Creates a new alg_info by parsing passed string         
 */
enum parser_state_esp {
	ST_INI,
	ST_EA,              /* encrypt algo   */
	ST_EA_END,
	ST_EK,              /* enc. key length */
	ST_EK_END,
	ST_AA,              /* auth algo */
	ST_AA_END,
	ST_AK,              /* auth. key length */
	ST_AK_END,
	ST_MODP,    /* modp spec */
	ST_FLAG_STRICT,
	ST_END,
	ST_EOF,
	ST_ERR
};

static const char *parser_state_esp_names[] = {
	"ST_INI",
	"ST_EA",
	"ST_EA_END",
	"ST_EK",
	"ST_EK_END",
	"ST_AA",
	"ST_AA_END",
	"ST_AK",
	"ST_AK_END",
	"ST_MOPD",
	"ST_FLAG_STRICT",
	"ST_END",
	"ST_EOF",
	"ST_ERR"
};

static const char*
parser_state_name_esp(enum parser_state_esp state)
{
	return parser_state_esp_names[state];
}

/* XXX:jjo to implement different parser for ESP and IKE */
struct parser_context {
	unsigned state, old_state;
	unsigned protoid;
	char ealg_buf[16];
	char aalg_buf[16];
	char modp_buf[16];
	int (*ealg_getbyname)(const char *const str, int len);
	int (*aalg_getbyname)(const char *const str, int len);
	int (*modp_getbyname)(const char *const str, int len);
	char *ealg_str;
	char *aalg_str;
	char *modp_str;
	int eklen;
	int aklen;
	int ch;
	const char *err;
};

static inline void 
parser_set_state(struct parser_context *p_ctx, enum parser_state_esp state)
{
	if (state != p_ctx->state)
	{
		p_ctx->old_state = p_ctx->state;
		p_ctx->state = state;
	}
}

static int 
parser_machine(struct parser_context *p_ctx)
{
	int ch = p_ctx->ch;

	/* special 'absolute' cases */
	p_ctx->err = "No error.";

	/* chars that end algo strings */
	switch (ch){
	case 0:     /* end-of-string */
	case '!':   /* flag as strict algo list */
	case ',':   /* algo string separator */
		switch (p_ctx->state) {
		case ST_EA:
		case ST_EK:
		case ST_AA:
		case ST_AK:
		case ST_MODP:
		case ST_FLAG_STRICT:
			{
				enum parser_state_esp next_state = 0;

				switch (ch) {
				case 0:
					next_state = ST_EOF;
					break;
				case ',':
					next_state = ST_END;
					break;
				case '!':
					next_state = ST_FLAG_STRICT;
					break;
				}
				/* ch? parser_set_state(p_ctx, ST_END) : parser_set_state(p_ctx, ST_EOF) ; */
				parser_set_state(p_ctx, next_state);
				goto out;
			}
		default:
			p_ctx->err = "String ended with invalid char";
			goto err;
		}
	}
re_eval:
	switch (p_ctx->state) {
	case ST_INI:
		if (isspace(ch))
			break;
		if (isalnum(ch))
		{
			*(p_ctx->ealg_str++) = ch;
			parser_set_state(p_ctx, ST_EA);
			break;
		}
		p_ctx->err = "No alphanum. char initially found";
		goto err;
	case ST_EA:
		if (isalpha(ch) || ch == '_')
		{
			*(p_ctx->ealg_str++) = ch;
			break;
		}
		if (isdigit(ch))
		{
			/* bravely switch to enc keylen */
			*(p_ctx->ealg_str) = 0;
			parser_set_state(p_ctx, ST_EK);
			goto re_eval;
		}
		if (ch == '-')
		{
			*(p_ctx->ealg_str) = 0;
			parser_set_state(p_ctx, ST_EA_END);
			break;
		}
		p_ctx->err = "No valid char found after enc alg string";
		goto err;
	case ST_EA_END:
		if (isdigit(ch))
		{
			/* bravely switch to enc keylen */
			parser_set_state(p_ctx, ST_EK);
			goto re_eval;
		}
		if (isalpha(ch))
		{
			parser_set_state(p_ctx, ST_AA);
			goto re_eval;
		}
		p_ctx->err = "No alphanum char found after enc alg separator";
		goto err;
	case ST_EK:
		if (ch == '-')
		{
			parser_set_state(p_ctx, ST_EK_END);
			break;
		}
		if (isdigit(ch))
		{
			p_ctx->eklen = p_ctx->eklen*10 + ch - '0';
			break;
		}
		p_ctx->err = "Non digit or valid separator found while reading enc keylen";
		goto err;
	case ST_EK_END:
		if (isalpha(ch))
		{
			parser_set_state(p_ctx, ST_AA);
			goto re_eval;
		}
		p_ctx->err = "Non alpha char found after enc keylen end separator";
		goto err;
	case ST_AA:
		if (ch == '-')
		{
			*(p_ctx->aalg_str++) = 0;
			parser_set_state(p_ctx, ST_AA_END);
			break;
		}
		if (isalnum(ch) || ch == '_')
		{
			*(p_ctx->aalg_str++) = ch;
			break;
		}
		p_ctx->err = "Non alphanum or valid separator found in auth string";
		goto err;
	case ST_AA_END:
		if (isdigit(ch))
		{
			parser_set_state(p_ctx, ST_AK);
			goto re_eval;
		}
		/* Only allow modpXXXX string if we have a modp_getbyname method */
		if ((p_ctx->modp_getbyname) && isalpha(ch))
		{
			parser_set_state(p_ctx, ST_MODP);
			goto re_eval;
		}
		p_ctx->err = "Non initial digit found for auth keylen";
		goto err;
	case ST_AK:
		if (ch=='-')
		{
			parser_set_state(p_ctx, ST_AK_END);
			break;
		}
		if (isdigit(ch))
		{
			p_ctx->aklen = p_ctx->aklen*10 + ch - '0';
			break;
		}
		p_ctx->err = "Non digit found for auth keylen";
		goto err;
	case ST_AK_END:
		/* Only allow modpXXXX string if we have a modp_getbyname method */
		if ((p_ctx->modp_getbyname) && isalpha(ch))
		{
			parser_set_state(p_ctx, ST_MODP);
			goto re_eval;
		}
		p_ctx->err = "Non alpha char found after auth keylen";
		goto err;
	case ST_MODP:
		if (isalnum(ch))
		{
			*(p_ctx->modp_str++) = ch;
			break;
		}
		p_ctx->err = "Non alphanum char found after in modp string";
		goto err;
	case ST_FLAG_STRICT:
		if (ch == 0)
			parser_set_state(p_ctx, ST_END);
		p_ctx->err = "Flags character(s) must be at end of whole string";
		goto err;

	/* XXX */
	case ST_END:
	case ST_EOF:
	case ST_ERR:
		break;
	/* XXX */
	}
out:
	return p_ctx->state;
err:
	parser_set_state(p_ctx, ST_ERR);
	return ST_ERR;
}

/*
 * Must be called for each "new" char, with new
 * character in ctx.ch
 */
static void
parser_init(struct parser_context *p_ctx, unsigned protoid)
{
	memset(p_ctx, 0, sizeof (*p_ctx));
	p_ctx->protoid = protoid; /* XXX: jjo */
	p_ctx->protoid = PROTO_IPSEC_ESP;
	p_ctx->ealg_str = p_ctx->ealg_buf;
	p_ctx->aalg_str = p_ctx->aalg_buf;
	p_ctx->modp_str = p_ctx->modp_buf;
	p_ctx->state = ST_INI;

	switch (protoid) {
#ifndef NO_PLUTO
	case PROTO_ISAKMP:
		p_ctx->ealg_getbyname = ealg_getbyname_ike;
		p_ctx->aalg_getbyname = aalg_getbyname_ike;
		p_ctx->modp_getbyname = modp_getbyname_ike;
		break;
#endif
	case PROTO_IPSEC_ESP:
		p_ctx->ealg_getbyname = ealg_getbyname_esp;
		p_ctx->aalg_getbyname = aalg_getbyname_esp;
		break;
	}
}

static int
parser_alg_info_add(struct parser_context *p_ctx, struct alg_info *alg_info)
{
	int ealg_id = 0;
	int aalg_id = 0;
	int modp_id = 0;
#ifndef NO_PLUTO
	const struct oakley_group_desc *gd;
#endif

	if (*p_ctx->ealg_buf)
	{
		ealg_id = p_ctx->ealg_getbyname(p_ctx->ealg_buf, strlen(p_ctx->ealg_buf));
		if (ealg_id == ESP_MAGIC_ID)
		{
			ealg_id = p_ctx->eklen;
			p_ctx->eklen = 0;
		}
		if (ealg_id < 0)
		{
			p_ctx->err = "enc_alg not found";
			return -1;
		}
		DBG(DBG_CRYPT,
			DBG_log("parser_alg_info_add() ealg_getbyname(\"%s\")=%d"
				, p_ctx->ealg_buf
				, ealg_id)
		)
	}
	if (*p_ctx->aalg_buf)
	{
		aalg_id = p_ctx->aalg_getbyname(p_ctx->aalg_buf, strlen(p_ctx->aalg_buf));
		if (aalg_id < 0)
		{
			p_ctx->err = "hash_alg not found";
			return -1;
		}
		DBG(DBG_CRYPT,
			DBG_log("parser_alg_info_add() aalg_getbyname(\"%s\")=%d"
				, p_ctx->aalg_buf
				, aalg_id)
		)
	}
	if (p_ctx->modp_getbyname && *p_ctx->modp_buf)
	{
		modp_id = p_ctx->modp_getbyname(p_ctx->modp_buf, strlen(p_ctx->modp_buf));
		if (modp_id < 0)
		{
			p_ctx->err = "modp group not found";
			return -1;
		}
		DBG(DBG_CRYPT,
			DBG_log("parser_alg_info_add() modp_getbyname(\"%s\")=%d"
				, p_ctx->modp_buf
				, modp_id)
		)
	}
	switch (alg_info->alg_info_protoid) {
	case PROTO_IPSEC_ESP:
		alg_info_esp_add(alg_info,
						 ealg_id, p_ctx->eklen,
						 aalg_id, p_ctx->aklen);
		break;
#ifndef NO_PLUTO
	case PROTO_ISAKMP:
		if (modp_id && !(gd = lookup_group(modp_id)))
		{
			p_ctx->err = "found modp group id, but not supported";
			return -1;
		}
		alg_info_ike_add(alg_info,
						 ealg_id, p_ctx->eklen,
						 aalg_id, p_ctx->aklen,
						 modp_id);
		break;
#endif
	default:
		return -1;
	}
	return 0;
}

static int
alg_info_parse_str (struct alg_info *alg_info, const char *alg_str, const char **err_p)
{
	struct parser_context ctx;
	int ret;
	const char *ptr;
	static char err_buf[256];

	*err_buf = 0;
	parser_init(&ctx, alg_info->alg_info_protoid);
	if (err_p)
		*err_p = NULL;

	/* use default if nul esp string */
	if (!*alg_str)
	{
		switch (alg_info->alg_info_protoid) {
#ifndef NO_PLUTO
		case PROTO_ISAKMP:
			alg_info_ike_add(alg_info, 0, 0, 0, 0, 0);
			return 0;
#endif
		case PROTO_IPSEC_ESP:
			alg_info_esp_add(alg_info, 0, 0, 0, 0);
			return 0;
		default:
			/* IMPOSSIBLE */
			passert(alg_info->alg_info_protoid);
		}
	}

	for (ret = 0, ptr = alg_str; ret < ST_EOF;)
	{
		ctx.ch = *ptr++;
		ret = parser_machine(&ctx);
				
		switch (ret) {
		case ST_FLAG_STRICT:
			alg_info->alg_info_flags |= ALG_INFO_F_STRICT;
			break;
		case ST_END:
		case ST_EOF:
			DBG(DBG_CRYPT,
				DBG_log("alg_info_parse_str() ealg_buf=%s aalg_buf=%s"
						"eklen=%d  aklen=%d",
						ctx.ealg_buf, ctx.aalg_buf,
						ctx.eklen, ctx.aklen)
			)
			if (parser_alg_info_add(&ctx, alg_info) < 0)
			{
				snprintf(err_buf, sizeof(err_buf),
					"%s, enc_alg=\"%s\", auth_alg=\"%s\", modp=\"%s\"",
					ctx.err,
					ctx.ealg_buf,
					ctx.aalg_buf,
					ctx.modp_buf);
				goto err;
			}
			/* zero out for next run (ST_END) */
			parser_init(&ctx, alg_info->alg_info_protoid);
			break;
		case ST_ERR:
			snprintf(err_buf, sizeof(err_buf),
				"%s, just after \"%.*s\" (old_state=%s)",
				ctx.err,
				(int)(ptr-alg_str-1), alg_str ,
				parser_state_name_esp(ctx.old_state));
			goto err;
		default:
			if (!ctx.ch)
				break;
		}
	}
	return 0;
err:
	if (err_p)
		*err_p=err_buf;
	return -1;
}

struct alg_info_esp *
alg_info_esp_create_from_str (const char *alg_str, const char **err_p)
{
	struct alg_info_esp *alg_info_esp;
	char esp_buf[256];
	static char err_buf[256];
	char *pfs_name;
	int ret = 0;
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
			ret = modp_getbyname_esp(pfs_name, strlen(pfs_name));
			if (ret < 0)
			{
				/* Bomb if pfsgroup not found */
				DBG(DBG_CRYPT,
					DBG_log("alg_info_esp_create_from_str(): pfsgroup \"%s\" not found"
						, pfs_name)
				)
				if (*err_p)
				{
					snprintf(err_buf, sizeof(err_buf),
						"pfsgroup \"%s\" not found",
						pfs_name);

					*err_p = err_buf;
				}
				goto out;
			}
			alg_info_esp->esp_pfsgroup = ret;
		}
	}
	else
		alg_info_esp->esp_pfsgroup = 0;
				
	alg_info_esp->alg_info_protoid = PROTO_IPSEC_ESP;
	ret = alg_info_parse_str((struct alg_info *)alg_info_esp, alg_str, err_p) ;
out:
	if (ret < 0)
	{
		free(alg_info_esp);
		alg_info_esp = NULL;
	}
	return alg_info_esp;
}

#ifndef NO_PLUTO
struct alg_info_ike *
alg_info_ike_create_from_str (const char *alg_str, const char **err_p)
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

	if (alg_info_parse_str((struct alg_info *)alg_info_ike, alg_str, err_p) < 0)
	{
		free(alg_info_ike);
		return NULL;
	}
	return alg_info_ike;
}
#endif

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
		DBG(DBG_CRYPT,
			DBG_log("alg_info_addref() alg_info->ref_cnt=%d"
				, alg_info->ref_cnt)
		)
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
		DBG(DBG_CRYPT,
			DBG_log("alg_info_delref() alg_info->ref_cnt=%d"
				, alg_info->ref_cnt)
		)
		if (alg_info->ref_cnt == 0)
		{
			DBG(DBG_CRYPT,
				DBG_log("alg_info_delref() freeing alg_info")
			)
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
#ifndef NO_PLUTO
	struct ike_info *ike_info;
#endif
	int cnt;
		
	switch (alg_info->alg_info_protoid) {
	case PROTO_IPSEC_ESP:
		{
			struct alg_info_esp *alg_info_esp = (struct alg_info_esp *)alg_info;

			ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt)
			{
				np = snprintf(ptr, buflen, "%d_%03d-%d, "
						, esp_info->esp_ealg_id
						, (int)esp_info->esp_ealg_keylen
						, esp_info->esp_aalg_id);
				ptr += np;
				buflen -= np;
				if (buflen < 0)
					goto out;
			}
			if (alg_info_esp->esp_pfsgroup)
			{
				np = snprintf(ptr, buflen, "; pfsgroup=%d; "
						, alg_info_esp->esp_pfsgroup);
				ptr += np;
				buflen -= np;
				if (buflen < 0)
					goto out;
			}
			break;
		}
#ifndef NO_PLUTO
	case PROTO_ISAKMP:
		ALG_INFO_IKE_FOREACH((struct alg_info_ike *)alg_info, ike_info, cnt)
		{
			np = snprintf(ptr, buflen, "%d_%03d-%d-%d, "
					, ike_info->ike_ealg
					, (int)ike_info->ike_eklen
					, ike_info->ike_halg
					, ike_info->ike_modp);
			ptr += np;
			buflen -= np;
			if (buflen < 0)
				goto out;
		}
		break;
#endif
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

#ifndef NO_PLUTO
int
alg_info_snprint_esp(char *buf, int buflen, struct alg_info_esp *alg_info)
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

int
alg_info_snprint_ike(char *buf, int buflen, struct alg_info_ike *alg_info)
{
	char *ptr = buf;

	int cnt = alg_info->alg_info_cnt;
	struct ike_info *ike_info = alg_info->ike;

	while (cnt--)
	{
		struct encrypt_desc *enc_desc = ike_alg_get_encrypter(ike_info->ike_ealg);
		struct hash_desc *hash_desc = ike_alg_get_hasher(ike_info->ike_halg);

		if (enc_desc != NULL &&  hash_desc != NULL
		&& lookup_group(ike_info->ike_modp))
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
#endif /* NO_PLUTO */
