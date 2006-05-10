#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/kernel.h>
#define DEBUG(x) 
#else
#include <stdio.h>
#include <sys/types.h>
#define DEBUG(x) x
#endif

#include "aes.h"
#include "aes_xcbc_mac.h"

int AES_xcbc_mac_set_key(aes_context_mac *ctxm, const u_int8_t *key, int keylen)
{
	int ret=1;
	aes_block kn[3] = { 
		{ 0x01010101, 0x01010101, 0x01010101, 0x01010101 },
		{ 0x02020202, 0x02020202, 0x02020202, 0x02020202 },
		{ 0x03030303, 0x03030303, 0x03030303, 0x03030303 },
	};
	aes_set_key(&ctxm->ctx_k1, key, keylen, 0);
	aes_encrypt(&ctxm->ctx_k1, (u_int8_t *) kn[0], (u_int8_t *) kn[0]);
	aes_encrypt(&ctxm->ctx_k1, (u_int8_t *) kn[1], (u_int8_t *) ctxm->k2);
	aes_encrypt(&ctxm->ctx_k1, (u_int8_t *) kn[2], (u_int8_t *) ctxm->k3);
	aes_set_key(&ctxm->ctx_k1, (u_int8_t *) kn[0], 16, 0);
	return ret;
}
static void do_pad_xor(u_int8_t *out, const u_int8_t *in, int len) {
	int pos=0;
	for (pos=1; pos <= 16; pos++, in++, out++) {
		if (pos <= len)
			*out ^= *in;
		if (pos > len) {
			DEBUG(printf("put 0x80 at pos=%d\n", pos));
			*out ^= 0x80;
			break;
		}
	}
}
static void xor_block(aes_block res, const aes_block op) {
	res[0] ^= op[0];
	res[1] ^= op[1];
	res[2] ^= op[2];
	res[3] ^= op[3];
}
int AES_xcbc_mac_hash(const aes_context_mac *ctxm, const u_int8_t * in, int ilen, u_int8_t hash[16]) {
	int ret=ilen;
	u_int32_t out[4] = { 0, 0, 0, 0 }; 
	for (; ilen > 16 ; ilen-=16) {
		xor_block(out, (const u_int32_t*) &in[0]);
		aes_encrypt(&ctxm->ctx_k1, in, (u_int8_t *)&out[0]);
		in+=16; 
	}
	do_pad_xor((u_int8_t *)&out, in, ilen);
	if (ilen==16) {
		DEBUG(printf("using k3\n"));
		xor_block(out, ctxm->k3);
	}
	else 
	{
		DEBUG(printf("using k2\n"));
		xor_block(out, ctxm->k2);
	}
	aes_encrypt(&ctxm->ctx_k1, (u_int8_t *)out, hash);
	return ret;
} 
