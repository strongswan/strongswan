#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <sys/types.h>
#include <string.h>
#endif
#include "hmac_generic.h"
#include "sha2.h"
#include "hmac_sha2.h"

void inline sha256_result(sha256_context *ctx, u_int8_t * hash, int hashlen) {
	sha256_final(ctx);
	memcpy(hash, &ctx->sha_out[0], hashlen);
}
void inline sha512_result(sha512_context *ctx, u_int8_t * hash, int hashlen) {
	sha512_final(ctx);
	memcpy(hash, &ctx->sha_out[0], hashlen);
}
HMAC_SET_KEY_IMPL (sha256_hmac_set_key, 
		sha256_hmac_context, SHA256_BLOCKSIZE, 
		sha256_init, sha256_write)
HMAC_HASH_IMPL (sha256_hmac_hash, 
		sha256_hmac_context, sha256_context, SHA256_HASHLEN,
		sha256_write, sha256_result)

HMAC_SET_KEY_IMPL (sha512_hmac_set_key, 
		sha512_hmac_context, SHA512_BLOCKSIZE, 
		sha512_init, sha512_write)
HMAC_HASH_IMPL (sha512_hmac_hash, 
		sha512_hmac_context, sha512_context, SHA512_HASHLEN,
		sha512_write, sha512_result)
