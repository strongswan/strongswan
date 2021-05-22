#ifndef _SM2_H_
#define _SM2_H_

#include "typedef.h"
#include "ecc.h"

int sm2_make_prikey(u8 *prikey);
int sm2_make_pubkey(u8 *prikey, ecc_point *pubkey);
int sm2_make_keypair(u8 *prikey, ecc_point *pubkey);
int sm2_sign(u8 *r, u8 *s, u8 *pri, u8 *hash);
int sm2_verify(ecc_point *pubkey, u8 *hash, u8 *r, u8 *s);
int sm2_encrypt(ecc_point *pubKey, u8 *M, u32 Mlen, u8 *C, u32 *Clen);
int sm2_decrypt(u8 *prikey, u8 *C, u32 Clen, u8 *M, u32 *Mlen);

void sm3_z(u8 *id, u32 idlen, ecc_point *pub, u8 *hash);
int sm2_shared_point(u8* selfPriKey,  u8* selfTempPriKey, ecc_point* selfTempPubKey,
		 ecc_point *otherPubKey, ecc_point* otherTempPubKey, ecc_point *key);
int sm2_shared_key(ecc_point *point, u8 *ZA, u8 *ZB, u32 keyLen, u8 *key);
int sm2_point_mult(ecc_point *G, u8 *k, ecc_point *P);


int ECC_KeyEx_Init_I(u8 *pri, ecc_point *pub);

int ECC_KeyEx_Re_I(u8 *rb, u8 *dB, ecc_point *RA, ecc_point *PA,
		u8* ZA, u8 *ZB, u8 *K, u32 klen, ecc_point *RB,
		ecc_point *V, u8* hash);

int ECC_KeyEx_Init_II(u8* ra, u8* dA, ecc_point* RA, ecc_point* RB, ecc_point* PB, u8
		ZA[],u8 ZB[],u8 SB[],u8 K[], u32 klen,u8 SA[]);

int ECC_KeyEx_Re_II(ecc_point *V,ecc_point *RA,ecc_point *RB,u8 ZA[],u8 ZB[],u8 SA[]);

#endif /* _SM2_H_ */
