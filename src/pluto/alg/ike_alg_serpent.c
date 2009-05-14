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

#define  SERPENT_KEY_MIN_LEN	128
#define  SERPENT_KEY_DEF_LEN	128
#define  SERPENT_KEY_MAX_LEN	256

struct encrypt_desc encrypt_desc_serpent =
{
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_SERPENT_CBC,
	algo_next: 	NULL,

	enc_blocksize:	SERPENT_BLOCK_SIZE,
	keyminlen:		SERPENT_KEY_MIN_LEN,
	keydeflen:		SERPENT_KEY_DEF_LEN,
	keymaxlen:		SERPENT_KEY_MAX_LEN,
	enc_testvectors: NULL		
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
