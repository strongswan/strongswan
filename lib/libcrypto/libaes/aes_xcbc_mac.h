#ifndef _AES_XCBC_MAC_H
#define _AES_XCBC_MAC_H

typedef u_int32_t aes_block[4];
typedef struct {
	aes_context ctx_k1;
	aes_block k2;
	aes_block k3;
} aes_context_mac;
int AES_xcbc_mac_set_key(aes_context_mac *ctxm, const u_int8_t *key, int keylen);
int AES_xcbc_mac_hash(const aes_context_mac *ctxm, const u_int8_t * in, int ilen, u_int8_t hash[16]);
#endif /* _AES_XCBC_MAC_H */
