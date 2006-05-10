/* Glue header */
#include "aes.h"
int AES_set_key(aes_context *aes_ctx, const u_int8_t * key, int keysize);
int AES_cbc_encrypt(aes_context *ctx, const u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t * iv, int encrypt);
