#ifndef TWOFISH_H
#define TWOFISH_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif
/* Structure for an expanded Twofish key.  s contains the key-dependent
 * S-boxes composed with the MDS matrix; w contains the eight "whitening"
 * subkeys, K[0] through K[7].	k holds the remaining, "round" subkeys.  Note
 * that k[i] corresponds to what the Twofish paper calls K[i+8]. */
typedef struct {
   u_int32_t s[4][256], w[8], k[32];
} TWOFISH_context;

typedef TWOFISH_context twofish_context;
int twofish_set_key(twofish_context *tf_ctx, const u_int8_t * in_key, int key_len);
int twofish_encrypt(twofish_context *tf_ctx, const u_int8_t * in, u_int8_t * out);
int twofish_decrypt(twofish_context * tf_ctx, const u_int8_t * in, u_int8_t * out);
#endif /* TWOFISH_H */
