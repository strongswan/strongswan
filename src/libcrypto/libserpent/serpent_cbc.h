/* Glue header */
#include "serpent.h"
int serpent_cbc_encrypt(serpent_context *ctx, const u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t * iv, int encrypt);
