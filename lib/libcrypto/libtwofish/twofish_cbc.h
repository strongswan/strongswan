/* Glue header */
#include "twofish.h"
int twofish_cbc_encrypt(twofish_context *ctx, const u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t* iv, int encrypt);
