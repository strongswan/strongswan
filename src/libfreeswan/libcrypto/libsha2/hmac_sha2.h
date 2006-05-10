typedef struct {
	sha256_context ictx,octx;
} sha256_hmac_context;
typedef struct {
	sha512_context ictx,octx;
} sha512_hmac_context;
#define SHA256_BLOCKSIZE 64
#define SHA256_HASHLEN   32
#define SHA384_BLOCKSIZE 128	/* XXX ok? */
#define SHA384_HASHLEN   48
#define SHA512_BLOCKSIZE 128
#define SHA512_HASHLEN   64

void sha256_hmac_hash(sha256_hmac_context *hctx, const u_int8_t * dat, int len, u_int8_t * hash, int hashlen);
void sha256_hmac_set_key(sha256_hmac_context *hctx, const u_int8_t * key, int keylen);
void sha512_hmac_hash(sha512_hmac_context *hctx, const u_int8_t * dat, int len, u_int8_t * hash, int hashlen);
void sha512_hmac_set_key(sha512_hmac_context *hctx, const u_int8_t * key, int keylen);
