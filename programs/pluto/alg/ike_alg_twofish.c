#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "libtwofish/twofish_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  TWOFISH_CBC_BLOCK_SIZE	(128/BITS_PER_BYTE)
#define  TWOFISH_KEY_MIN_LEN	128
#define  TWOFISH_KEY_DEF_LEN	128
#define  TWOFISH_KEY_MAX_LEN	256

static void
do_twofish(u_int8_t *buf, size_t buf_size, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    twofish_context twofish_ctx;
    char iv_bak[TWOFISH_CBC_BLOCK_SIZE];
    char *new_iv = NULL;	/* logic will avoid copy to NULL */

    twofish_set_key(&twofish_ctx, key, key_size);
    /*	
     *	my TWOFISH cbc does not touch passed IV (optimization for
     *	ESP handling), so I must "emulate" des-like IV
     *	crunching
     */
    if (!enc)
	    memcpy(new_iv=iv_bak, 
			    (char*) buf + buf_size-TWOFISH_CBC_BLOCK_SIZE,
			    TWOFISH_CBC_BLOCK_SIZE);

    twofish_cbc_encrypt(&twofish_ctx, buf, buf, buf_size, iv, enc);

    if (enc)
	    new_iv = (char*) buf + buf_size-TWOFISH_CBC_BLOCK_SIZE;

    memcpy(iv, new_iv, TWOFISH_CBC_BLOCK_SIZE);
}

struct encrypt_desc encrypt_desc_twofish = 
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_TWOFISH_CBC,
	algo_next: 	NULL,
	enc_ctxsize: 	sizeof(twofish_context),
        enc_blocksize: 	TWOFISH_CBC_BLOCK_SIZE,
        keydeflen: 	TWOFISH_KEY_MIN_LEN,
        keyminlen: 	TWOFISH_KEY_DEF_LEN,
	keymaxlen: 	TWOFISH_KEY_MAX_LEN,
	do_crypt: 	do_twofish,
};

struct encrypt_desc encrypt_desc_twofish_ssh =
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_TWOFISH_CBC_SSH,
	algo_next: 	NULL,
	enc_ctxsize: 	sizeof(twofish_context),
        enc_blocksize: 	TWOFISH_CBC_BLOCK_SIZE,
        keydeflen: 	TWOFISH_KEY_MIN_LEN,
        keyminlen: 	TWOFISH_KEY_DEF_LEN,
	keymaxlen: 	TWOFISH_KEY_MAX_LEN,
	do_crypt: 	do_twofish,
};

int ike_alg_twofish_init(void);

int
ike_alg_twofish_init(void)
{
    int ret = ike_alg_register_enc(&encrypt_desc_twofish);

    if (ike_alg_register_enc(&encrypt_desc_twofish_ssh) < 0)
	plog("ike_alg_twofish_init(): Experimental OAKLEY_TWOFISH_CBC_SSH activation failed");

    return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_twofish_init
*/
