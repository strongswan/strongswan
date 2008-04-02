#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "libaes/aes_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  AES_CBC_BLOCK_SIZE	(128/BITS_PER_BYTE)
#define  AES_KEY_MIN_LEN	128
#define  AES_KEY_DEF_LEN	128
#define  AES_KEY_MAX_LEN	256

static void
do_aes(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    aes_context aes_ctx;
    char iv_bak[AES_CBC_BLOCK_SIZE];
    char *new_iv = NULL;	/* logic will avoid copy to NULL */

    aes_set_key(&aes_ctx, key, key_size, 0);

    /*	
     *	my AES cbc does not touch passed IV (optimization for
     *	ESP handling), so I must "emulate" des-like IV
     *	crunching
     */
    if (!enc)
	memcpy(new_iv=iv_bak, (char*) buf + buf_len - AES_CBC_BLOCK_SIZE
		, AES_CBC_BLOCK_SIZE);

    SS_AES_cbc_encrypt(&aes_ctx, buf, buf, buf_len, iv, enc);

    if (enc)
	new_iv = (char*) buf + buf_len-AES_CBC_BLOCK_SIZE;

    memcpy(iv, new_iv, AES_CBC_BLOCK_SIZE);
}

struct encrypt_desc algo_aes =
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_AES_CBC,
	algo_next: 	NULL, 
	enc_ctxsize: 	sizeof(aes_context),
	enc_blocksize: 	AES_CBC_BLOCK_SIZE,
	keyminlen: 	AES_KEY_MIN_LEN,
	keydeflen: 	AES_KEY_DEF_LEN,
	keymaxlen: 	AES_KEY_MAX_LEN,
	do_crypt: 	do_aes,
};

int ike_alg_aes_init(void);

int
ike_alg_aes_init(void)
{
	int ret = ike_alg_register_enc(&algo_aes);
	return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_aes_init
*/
