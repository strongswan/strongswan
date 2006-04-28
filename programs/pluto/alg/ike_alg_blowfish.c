#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "libblowfish/blowfish.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  BLOWFISH_CBC_BLOCK_SIZE	8  	/* block size */
#define  BLOWFISH_KEY_MIN_LEN	128
#define  BLOWFISH_KEY_MAX_LEN	448


static void
do_blowfish(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    BF_KEY bf_ctx;

    BF_set_key(&bf_ctx, key_size , key);
    BF_cbc_encrypt(buf, buf, buf_len, &bf_ctx, iv, enc);
}

struct encrypt_desc algo_blowfish =
{
	algo_type: IKE_ALG_ENCRYPT,
	algo_id:   OAKLEY_BLOWFISH_CBC,
	algo_next: NULL, 
	enc_ctxsize: sizeof(BF_KEY),
	enc_blocksize: BLOWFISH_CBC_BLOCK_SIZE,
	keyminlen: BLOWFISH_KEY_MIN_LEN,
	keydeflen: BLOWFISH_KEY_MIN_LEN,
	keymaxlen: BLOWFISH_KEY_MAX_LEN,
	do_crypt: do_blowfish,
};

int ike_alg_blowfish_init(void);

int
ike_alg_blowfish_init(void)
{
    int ret = ike_alg_register_enc(&algo_blowfish);

    return ret;
}
/*
IKE_ALG_INIT_NAME: ike_alg_blowfish_init
*/
