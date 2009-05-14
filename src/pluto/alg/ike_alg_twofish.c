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

#define  TWOFISH_KEY_MIN_LEN	128
#define  TWOFISH_KEY_DEF_LEN	128
#define  TWOFISH_KEY_MAX_LEN	256

struct encrypt_desc encrypt_desc_twofish = 
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_TWOFISH_CBC,
	algo_next: 	NULL,

	enc_blocksize:	TWOFISH_BLOCK_SIZE,
	keydeflen:		TWOFISH_KEY_MIN_LEN,
	keyminlen:		TWOFISH_KEY_DEF_LEN,
	keymaxlen:		TWOFISH_KEY_MAX_LEN,
	enc_testvectors: NULL
};

struct encrypt_desc encrypt_desc_twofish_ssh =
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_TWOFISH_CBC_SSH,
	algo_next: 	NULL,

	enc_blocksize:	TWOFISH_BLOCK_SIZE,
	keydeflen:		TWOFISH_KEY_MIN_LEN,
	keyminlen:		TWOFISH_KEY_DEF_LEN,
	keymaxlen:		TWOFISH_KEY_MAX_LEN,
	enc_testvectors: NULL
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
