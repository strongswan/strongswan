#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "libserpent/serpent_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  SERPENT_CBC_BLOCK_SIZE	(128/BITS_PER_BYTE)
#define  SERPENT_KEY_MIN_LEN	128
#define  SERPENT_KEY_DEF_LEN	128
#define  SERPENT_KEY_MAX_LEN	256

static void
do_serpent(u_int8_t *buf, size_t buf_size, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    serpent_context serpent_ctx;
    char iv_bak[SERPENT_CBC_BLOCK_SIZE];
    char *new_iv = NULL;	/* logic will avoid copy to NULL */


    serpent_set_key(&serpent_ctx, key, key_size);
    /*	
     *	my SERPENT cbc does not touch passed IV (optimization for
     *	ESP handling), so I must "emulate" des-like IV
     *	crunching
     */
    if (!enc)
	    memcpy(new_iv=iv_bak, 
			    (char*) buf + buf_size-SERPENT_CBC_BLOCK_SIZE,
			    SERPENT_CBC_BLOCK_SIZE);

    serpent_cbc_encrypt(&serpent_ctx, buf, buf, buf_size, iv, enc);

    if (enc)
	    new_iv = (char*) buf + buf_size-SERPENT_CBC_BLOCK_SIZE;

    memcpy(iv, new_iv, SERPENT_CBC_BLOCK_SIZE);
}

struct encrypt_desc encrypt_desc_serpent =
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_SERPENT_CBC,
	algo_next: 	NULL,
	enc_ctxsize: 	sizeof(struct serpent_context),
	enc_blocksize: 	SERPENT_CBC_BLOCK_SIZE,
        keyminlen: 	SERPENT_KEY_MIN_LEN,
        keydeflen: 	SERPENT_KEY_DEF_LEN,
        keymaxlen: 	SERPENT_KEY_MAX_LEN,
        do_crypt: 	do_serpent,
};

int ike_alg_serpent_init(void);

int
ike_alg_serpent_init(void)
{
    int ret = ike_alg_register_enc(&encrypt_desc_serpent);

    return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_serpent_init
*/
