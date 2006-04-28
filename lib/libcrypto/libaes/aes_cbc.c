#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif
#include "aes_cbc.h"
#include "cbc_generic.h"
/* returns bool success */
int AES_set_key(aes_context *aes_ctx, const u_int8_t *key, int keysize) {
	aes_set_key(aes_ctx, key, keysize, 0);
	return 1;	
}
CBC_IMPL_BLK16(AES_cbc_encrypt, aes_context, u_int8_t *, aes_encrypt, aes_decrypt);
