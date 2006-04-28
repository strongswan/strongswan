/* Kernel runtime algorithm handling interface
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
 *
 * RCSID $Id: kernel_alg.c,v 1.9 2005/08/17 16:31:24 as Exp $
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
#include <freeswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "packet.h"
#include "spdb.h"
#include "kernel.h"
#include "kernel_alg.h"
#include "alg_info.h"

#ifndef NO_PLUTO
#include "log.h"
#include "whack.h"
#include "db_ops.h"
#else
/*
 *	macros/functions for compilation without pluto (eg: spi for manual conns)
 */
extern int debug;
#include <assert.h>
#define passert(x) assert(x)
#define DBG(cond, action)   { if (debug) { action ; } }
#define DBG_log(x, args...) fprintf(stderr, x "\n" , ##args);
#define plog(x, args...) fprintf(stderr, x "\n" , ##args);
#endif /* NO_PLUTO */
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

static struct sadb_alg*
sadb_alg_ptr (int satype, int exttype, int alg_id, int rw)
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

const struct sadb_alg *
kernel_alg_sadb_alg_get(int satype, int exttype, int alg_id)
{
    return sadb_alg_ptr(satype, exttype, alg_id, 0);
}

/*
 * 	Forget previous registration
 */
static void 
kernel_alg_init(void)
{
    DBG(DBG_KLIPS,
	DBG_log("alg_init(): memset(%p, 0, %d) memset(%p, 0, %d)",
		&esp_aalg,  (int)sizeof (esp_aalg),
		&esp_ealg,  (int)sizeof (esp_ealg))
    )
    memset (&esp_aalg, 0, sizeof (esp_aalg));
    memset (&esp_ealg, 0, sizeof (esp_ealg));
    esp_ealg_num=esp_aalg_num = 0;
}

static int
kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
    struct sadb_alg *alg_p = NULL;
    int alg_id = sadb_alg->sadb_alg_id;

    DBG(DBG_KLIPS,
	DBG_log("kernel_alg_add(): satype=%d, exttype=%d, alg_id=%d",
		satype, exttype, sadb_alg->sadb_alg_id)
    )
    if (!(alg_p = sadb_alg_ptr(satype, exttype, alg_id, 1)))
	return -1;

    /* This logic "mimics" KLIPS: first algo implementation will be used */
    if (alg_p->sadb_alg_id)
    {
	DBG(DBG_KLIPS,
	    DBG_log("kernel_alg_add(): discarding already setup "
		    "satype=%d, exttype=%d, alg_id=%d",
		    satype, exttype, sadb_alg->sadb_alg_id)
	)
	return 0;
    }
    *alg_p = *sadb_alg;
    return 1;
}

bool
kernel_alg_esp_enc_ok(u_int alg_id, u_int key_len,
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
	DBG(DBG_KLIPS,
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
	DBG(DBG_KLIPS,
	    DBG_log("kernel_alg_esp_enc_ok(%d,%d): NO", alg_id, key_len);
	)
    }
    return ret;
}

/* 
 * ML: make F_STRICT logic consider enc,auth algorithms 
 */
#ifndef NO_PLUTO
bool
kernel_alg_esp_ok_final(u_int ealg, u_int key_len, u_int aalg, struct alg_info_esp *alg_info)
{
    int ealg_insecure;

    /*
     * key_len passed comes from esp_attrs read from peer
     * For many older algoritms (eg 3DES) this key_len is fixed
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
			    , enum_name(&esp_transformid_names, ealg), key_len);
		    }
		    return TRUE;
		}
	    }
	}
	plog("IPSec Transform [%s (%d), %s] refused due to %s",
		enum_name(&esp_transformid_names, ealg), key_len,
		enum_name(&auth_alg_names, aalg),
		ealg_insecure ? "insecure key_len and enc. alg. not listed in \"esp\" string" : "strict flag");
	return FALSE;
    }
    return TRUE;
}
#endif /* NO_PLUTO */

/*	
 *	Load kernel_alg arrays from /proc
 * 	used in manual mode from klips/utils/spi.c
 */
int
kernel_alg_proc_read(void)
{
    int satype;
    int supp_exttype;
    int alg_id, ivlen, minbits, maxbits;
    struct sadb_alg sadb_alg;
    int ret;
    char buf[128];

    FILE *fp=fopen("/proc/net/pf_key_supported", "r");

    if (!fp)
	return -1;

    kernel_alg_init();

    while (fgets(buf, sizeof(buf), fp))
    {
	if (buf[0] != ' ') /* skip titles */
	    continue;

	sscanf(buf, "%d %d %d %d %d %d"
		,&satype, &supp_exttype
		, &alg_id, &ivlen
		, &minbits, &maxbits);

	switch (satype)
	{
	case SADB_SATYPE_ESP:
	    switch(supp_exttype)
	    {
	    case SADB_EXT_SUPPORTED_AUTH:
	    case SADB_EXT_SUPPORTED_ENCRYPT:
		sadb_alg.sadb_alg_id = alg_id;
		sadb_alg.sadb_alg_ivlen = ivlen;
		sadb_alg.sadb_alg_minbits = minbits;
		sadb_alg.sadb_alg_maxbits = maxbits;
		ret = kernel_alg_add(satype, supp_exttype, &sadb_alg);
		DBG(DBG_CRYPT,
		    DBG_log("kernel_alg_proc_read() alg_id=%d, "
			    "alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
			    "ret=%d"
			    , sadb_alg.sadb_alg_id
			    , sadb_alg.sadb_alg_ivlen
			    , sadb_alg.sadb_alg_minbits
			    , sadb_alg.sadb_alg_maxbits
			    , ret)
		)
	    }
	default:
	    continue;
	}
    }
    fclose(fp);
    return 0;
}

/*	
 *	Load kernel_alg arrays pluto's SADB_REGISTER	
 * 	user by pluto/kernel.c
 */

void
kernel_alg_register_pfkey(const struct sadb_msg *msg_buf, int buflen)
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

    while(msglen)
    {
	int supp_exttype = sadb.supported->sadb_supported_exttype;
	int supp_len = sadb.supported->sadb_supported_len*IPSEC_PFKEYv2_ALIGN;

	DBG(DBG_KLIPS,
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
	    int ret = kernel_alg_add(satype, supp_exttype, sadb.alg);

	    DBG(DBG_KLIPS,
		DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
			"alg[%d], exttype=%d, satype=%d, alg_id=%d, "
			"alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
			"res=%d, ret=%d"
			, satype==SADB_SATYPE_ESP? "ESP" : "AH"
			, i
			, supp_exttype
			, satype
			, sadb.alg->sadb_alg_id
			, sadb.alg->sadb_alg_ivlen
			, sadb.alg->sadb_alg_minbits
			, sadb.alg->sadb_alg_maxbits
			, sadb.alg->sadb_alg_reserved
			, ret)
	    )
	}
    }
}

u_int
kernel_alg_esp_enc_keylen(u_int alg_id)
{
    u_int keylen = 0;

    if (!ESP_EALG_PRESENT(alg_id))
	goto none;

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
    DBG(DBG_KLIPS,
	DBG_log("kernel_alg_esp_enc_keylen():"
		"alg_id=%d, keylen=%d",
		alg_id, keylen)
    )
    return keylen;
}

struct sadb_alg *
kernel_alg_esp_sadb_alg(u_int alg_id)
{
    struct sadb_alg *sadb_alg = (ESP_EALG_PRESENT(alg_id))
		? &esp_ealg[alg_id] : NULL;

    DBG(DBG_KLIPS,
	DBG_log("kernel_alg_esp_sadb_alg(): alg_id=%d, sadb_alg=%p"
		, alg_id, sadb_alg)
    )
    return sadb_alg;
}

#ifndef NO_PLUTO
void kernel_alg_list(void)
{
    u_int sadb_id;

    whack_log(RC_COMMENT, " ");
    whack_log(RC_COMMENT, "List of registered ESP Encryption Algorithms:");
    whack_log(RC_COMMENT, " ");

    for (sadb_id = 1; sadb_id <= SADB_EALG_MAX; sadb_id++)
    {
	if (ESP_EALG_PRESENT(sadb_id))
	{
	    struct sadb_alg *alg_p = &esp_ealg[sadb_id];

	    whack_log(RC_COMMENT, "#%-5d %s, blocksize: %d, keylen: %d-%d"
		, sadb_id
		, enum_name(&esp_transformid_names, sadb_id)
		, alg_p->sadb_alg_ivlen
		, alg_p->sadb_alg_minbits
		, alg_p->sadb_alg_maxbits
	    );
	}
    }
    
    whack_log(RC_COMMENT, " ");
    whack_log(RC_COMMENT, "List of registered ESP Authentication Algorithms:");
    whack_log(RC_COMMENT, " ");

    for (sadb_id = 1; sadb_id <= SADB_AALG_MAX; sadb_id++)
    {
	if (ESP_AALG_PRESENT(sadb_id))
	{
	    u_int aaid = alg_info_esp_sadb2aa(sadb_id);
	    struct sadb_alg *alg_p = &esp_aalg[sadb_id];

	    whack_log(RC_COMMENT, "#%-5d %s, keylen: %d-%d"
		, aaid
		, enum_name(&auth_alg_names, aaid)
		, alg_p->sadb_alg_minbits
		, alg_p->sadb_alg_maxbits
	    );
	}
    }
}

void
kernel_alg_show_connection(struct connection *c, const char *instance)
{
    char buf[256];
    struct state *st;

    if (c->alg_info_esp)
    {
	alg_info_snprint(buf, sizeof(buf), (struct alg_info *)c->alg_info_esp);
	whack_log(RC_COMMENT
		, "\"%s\"%s:   ESP algorithms wanted: %s"
		, c->name
		, instance
		, buf);
    }
    if (c->alg_info_esp)
    {
	alg_info_snprint_esp(buf, sizeof(buf), c->alg_info_esp);
	whack_log(RC_COMMENT
		, "\"%s\"%s:   ESP algorithms loaded: %s"
		, c->name
		, instance
		, buf);
    }
    st = state_with_serialno(c->newest_ipsec_sa);
    if (st && st->st_esp.present)
	whack_log(RC_COMMENT
		, "\"%s\"%s:   ESP algorithm newest: %s_%d-%s; pfsgroup=%s"
		, c->name
		, instance
		, enum_show(&esp_transformid_names, st->st_esp.attrs.transid)
		+4 /* strlen("ESP_") */
		, st->st_esp.attrs.key_len
		, enum_show(&auth_alg_names, st->st_esp.attrs.auth)+
		+15 /* strlen("AUTH_ALGORITHM_") */
		, c->policy & POLICY_PFS ?
			c->alg_info_esp->esp_pfsgroup ?
					enum_show(&oakley_group_names, 
						c->alg_info_esp->esp_pfsgroup)
						+13 /*strlen("OAKLEY_GROUP_")*/
				: "<Phase1>"
			: "<N/A>"
	);
}
#endif /* NO_PLUTO */

bool
kernel_alg_esp_auth_ok(u_int auth,
		struct alg_info_esp *alg_info __attribute__((unused)))
{
    return ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth));
}

u_int
kernel_alg_esp_auth_keylen(u_int auth)
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

struct esp_info *
kernel_alg_esp_info(int transid, int auth)
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

#ifndef NO_PLUTO
static void
kernel_alg_policy_algorithms(struct esp_info *esp_info)
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

static bool 
kernel_alg_db_add(struct db_context *db_ctx, struct esp_info *esp_info, lset_t policy)
{
    u_int ealg_id, aalg_id;

    ealg_id = esp_info->esp_ealg_id;

    if (!ESP_EALG_PRESENT(ealg_id))
    {
	DBG_log("kernel_alg_db_add() kernel enc ealg_id=%d not present", ealg_id);
	return FALSE;
    }
    
    if (!(policy & POLICY_AUTHENTICATE))    /* skip ESP auth attrs for AH */
    {
	aalg_id = alg_info_esp_aa2sadb(esp_info->esp_aalg_id);

	if (!ESP_AALG_PRESENT(aalg_id))
	{
	    DBG_log("kernel_alg_db_add() kernel auth "
		    "aalg_id=%d not present", aalg_id);
	    return FALSE;
	}
    }

    /* do algo policy */
    kernel_alg_policy_algorithms(esp_info);

    /*	open new transformation */
    db_trans_add(db_ctx, ealg_id);

    /* add ESP auth attr */
    if (!(policy & POLICY_AUTHENTICATE))
	db_attr_add_values(db_ctx, AUTH_ALGORITHM, esp_info->esp_aalg_id);

    /* add keylegth if specified in esp= string */
    if (esp_info->esp_ealg_keylen)
	db_attr_add_values(db_ctx, KEY_LENGTH, esp_info->esp_ealg_keylen);
	
    return TRUE;
}

/*	
 *	Create proposal with runtime kernel algos, merging
 *	with passed proposal if not NULL
 *
 *	for now this function does free() previous returned
 *	malloced pointer (this quirk allows easier spdb.c change)
 */
struct db_context * 
kernel_alg_db_new(struct alg_info_esp *alg_info, lset_t policy )
{
    const struct esp_info *esp_info;
    struct esp_info tmp_esp_info;
    struct db_context *ctx_new=NULL;
    struct db_trans *t;
    struct db_prop  *prop;
    u_int trans_cnt;
    int tn = 0;

    if (!(policy & POLICY_ENCRYPT))	/* not possible, I think  */
	return NULL;

    trans_cnt = esp_ealg_num * esp_aalg_num;
    DBG(DBG_EMITTING,
	DBG_log("kernel_alg_db_prop_new() initial trans_cnt=%d"
		, trans_cnt)
    )

    /* pass aprox. number of transforms and attributes */
    ctx_new = db_prop_new(PROTO_IPSEC_ESP, trans_cnt, trans_cnt * 2);

    /*
     * Loop: for each element (struct esp_info) of alg_info,
     *       if kernel support is present then build the transform (and attrs)
     *       if NULL alg_info, propose everything ...
     */

    if (alg_info)
    {
	int i;

	ALG_INFO_ESP_FOREACH(alg_info, esp_info, i)
	{
	    tmp_esp_info = *esp_info;
	    kernel_alg_db_add(ctx_new, &tmp_esp_info, policy);
	}
    }
    else
    {
	u_int ealg_id;
	
	ESP_EALG_FOR_EACH_UPDOWN(ealg_id)
	{
	    u_int aalg_id;

	    tmp_esp_info.esp_ealg_id = ealg_id;
	    tmp_esp_info.esp_ealg_keylen = 0;

	    for (aalg_id = 1; aalg_id <= SADB_AALG_MAX; aalg_id++)
	    {
		if (ESP_AALG_PRESENT(aalg_id))
		{
		    tmp_esp_info.esp_aalg_id = alg_info_esp_sadb2aa(aalg_id);
		    tmp_esp_info.esp_aalg_keylen = 0;
		    kernel_alg_db_add(ctx_new, &tmp_esp_info, policy);
		}
	    }
	}
    }

    prop = db_prop_get(ctx_new);

    DBG(DBG_CONTROL|DBG_EMITTING,
	DBG_log("kernel_alg_db_prop_new() "
		"will return p_new->protoid=%d, p_new->trans_cnt=%d"
		, prop->protoid, prop->trans_cnt)
    )

    for (t = prop->trans, tn = 0; tn < prop->trans_cnt; tn++)
    {
	DBG(DBG_CONTROL|DBG_EMITTING,
	    DBG_log("kernel_alg_db_prop_new() "
		    "    trans[%d]: transid=%d, attr_cnt=%d, "
		    "attrs[0].type=%d, attrs[0].val=%d"
		    , tn
		    , t[tn].transid, t[tn].attr_cnt
		    , t[tn].attrs[0].type, t[tn].attrs[0].val)
	)
    }
    return ctx_new;
}
#endif /* NO_PLUTO */
