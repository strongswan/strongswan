#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  AES_KEY_MIN_LEN	128
#define  AES_KEY_DEF_LEN	128
#define  AES_KEY_MAX_LEN	256

struct encrypt_desc algo_aes =
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_AES_CBC,
	algo_next: 	NULL, 

	enc_blocksize: 	AES_BLOCK_SIZE,
	keyminlen: 		AES_KEY_MIN_LEN,
	keydeflen: 		AES_KEY_DEF_LEN,
	keymaxlen: 		AES_KEY_MAX_LEN,
	enc_testvectors: NULL
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
