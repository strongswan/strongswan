#ifndef _SM4_H_
#define _SM4_H_

#include "typedef.h"

typedef struct {
	u32 sk_enc[32];
	u32 sk_dec[32];
	u32 iv[16];
} sm4_ctx;

void sm4_ecb_encrypt(sm4_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out);
void sm4_ecb_decrypt(sm4_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out);
void sm4_cbc_encrypt(sm4_ctx *ctx, u8 *key, u8 *iv, u8 *in, u8 len, u8 *out);
void sm4_cbc_decrypt(sm4_ctx *ctx, u8 *key, u8 *iv, u8 *in, u8 len, u8 *out);

#endif /* _SM4_H_ */
