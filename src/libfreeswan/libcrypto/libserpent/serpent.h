#ifndef SERPENT_H
#define SERPENT_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#define u32 u_int32_t
#define u8 u_int8_t
#endif
struct serpent_context {
	u32  keyinfo[140]; /* storage for the key schedule         */
};
typedef struct serpent_context serpent_context;
int serpent_set_key(serpent_context *ctx, const u8 * in_key, int key_len);
int serpent_decrypt(serpent_context *ctx, const u8 * in_blk, u8 * out_blk);
int serpent_encrypt(serpent_context *ctx, const u8 * in_blk, u8 * out_blk);
#endif /* SERPENT_H */
