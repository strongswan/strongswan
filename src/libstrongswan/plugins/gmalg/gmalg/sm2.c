#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "debug.h"
#include "random.h"
#include "ecc.h"
#include "sm2.h"
#include "sm3.h"

struct ecc_curve ecc_curve = {
	.g = {
		.x = {
			0xC7, 0x74, 0x4C, 0x33, 0x89, 0x45, 0x5A, 0x71, 0xE1, 0x0B, 0x66, 0xF2, 0xBF, 0x0B, 0xE3, 0x8F,
			0x94, 0xC9, 0x39, 0x6A, 0x46, 0x04, 0x99, 0x5F, 0x19, 0x81, 0x19, 0x1F, 0x2C, 0xAE, 0xC4, 0x32},
		.y = {
			0xA0, 0xF0, 0x39, 0x21, 0xE5, 0x32, 0xDF, 0x02, 0x40, 0x47, 0x2A, 0xC6, 0x7C, 0x87, 0xA9, 0xD0,
			0x53, 0x21, 0x69, 0x6B, 0xE3, 0xCE, 0xBD, 0x59, 0x9C, 0x77, 0xF6, 0xF4, 0xA2, 0x36, 0x37, 0xBC},
	},
	.p = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF},
	.n = {
		0x23, 0x41, 0xD5, 0x39, 0x09, 0xF4, 0xBB, 0x53, 0x2B, 0x05, 0xC6, 0x21, 0x6B, 0xDF, 0x03, 0x72,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF},
	.h = {
		0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	.a = {
		0xfc,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
		0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, 0xfe,0xff,0xff,0xff},
	.b = {
		0x93, 0x0E, 0x94, 0x4D, 0x41, 0xBD, 0xBC, 0xDD, 0x92, 0x8F, 0xAB, 0x15, 0xF5, 0x89, 0x97, 0xF3,
		0xA7, 0x09, 0x65, 0xCF, 0x4B, 0x9E, 0x5A, 0x4D, 0x34, 0x5E, 0x9F, 0x9D, 0x9E, 0xFA, 0xE9, 0x28},
};

void ecc_bytes2native(u8 *native, u8 *bytes)
{
	unsigned int i;

	for (i = 0; i < ECC_NUMWORD/2; ++i) {
		if (native == bytes) {
			u8 temp;

			temp = native[i];
			native[i] = bytes[ECC_NUMWORD - i - 1];
			bytes[ECC_NUMWORD - i - 1] = temp;
		}else {
			native[i] = bytes[ECC_NUMWORD - i - 1];
			native[ECC_NUMWORD - i - 1] = bytes[i];
		}
	}
}

void ecc_native2bytes(u8 *bytes, u8 *native)
{
	unsigned int i;

	for (i = 0; i < ECC_NUMWORD/2; ++i) {
		if (bytes == native) {
			u8 temp;
			temp = bytes[ECC_NUMWORD - i - 1];
			bytes[ECC_NUMWORD - i - 1] = native[i];
			native[i] = temp;
		} else {
			bytes[i] = native[ECC_NUMWORD - i - 1];
			bytes[ECC_NUMWORD - i - 1] = native[i];
		}
	}
}

/*x¯2 = 2w + (x2&(2w − 1))*/
void sm2_w(u8 *result, u8 *x)
{
	memcpy(result, x, 16);
	result[15] |= 0x80;
	memset(result + 16, 0, 16);
}

void sm3_kdf(u8 *Z ,u32 zlen, u8 *K, u32 klen)
{
	u32 ct = 0x00000001;
	u8 ct_char[32];
	u8 *hash = K ;
	u32 i, t;
	sm3_ctx md[1];

	t = klen/ECC_NUMWORD;
	//s4: K=Ha1||Ha2||...
	for (i = 0; i < t; i++) {
		//s2: Hai=Hv(Z||ct)
		sm3_init(md);
		sm3_update(md, Z, zlen);
		digit2str32(ct, ct_char);
		sm3_update(md, ct_char, 4);
		sm3_finish(md, hash);
		hash += 32;
		ct++;
	}

	t = klen%ECC_NUMBITS;
	if (t) {
		sm3_init(md);
		sm3_update(md, Z, zlen);
		digit2str32(ct, ct_char);
		sm3_update(md, ct_char, 4);
		sm3_finish(md, ct_char);
		memcpy(hash, ct_char, t);
	}
}

void sm3_z(u8 *id, u32 idlen, ecc_point *pub, u8 *hash)
{
	u8 a[ECC_NUMWORD];
	u8 b[ECC_NUMWORD];
	u8 x[ECC_NUMWORD];
	u8 y[ECC_NUMWORD];
	u8 idlen_char[2];
	sm3_ctx md[1];

	digit2str16(idlen<<3, idlen_char);

	ecc_bytes2native(a, ecc_curve.a);
	ecc_bytes2native(b, ecc_curve.b);
	ecc_bytes2native(x, ecc_curve.g.x);
	ecc_bytes2native(y, ecc_curve.g.y);

	sm3_init(md);
	sm3_update(md, idlen_char, 2);
	sm3_update(md, id, idlen);
	sm3_update(md, a, ECC_NUMWORD);
	sm3_update(md, b, ECC_NUMWORD);
	sm3_update(md, x, ECC_NUMWORD);
	sm3_update(md, y, ECC_NUMWORD);
	sm3_update(md, pub->x, ECC_NUMWORD);
	sm3_update(md, pub->y, ECC_NUMWORD);
	sm3_finish(md, hash);

	return;
}

int ecc_valid_public_key(ecc_point *publicKey)
{
	u8 na[ECC_NUMWORD] = {3}; /* a mod p = (-3) mod p */
	u8 tmp1[ECC_NUMWORD];
	u8 tmp2[ECC_NUMWORD];

	if (ecc_point_is_zero(publicKey))
		return 1;

	if (vli_cmp(ecc_curve.p, publicKey->x) != 1 || vli_cmp(ecc_curve.p, publicKey->y) != 1)
		return 1;

	vli_mod_square_fast(tmp1, publicKey->y, ecc_curve.p); /* tmp1 = y^2 */
	vli_mod_square_fast(tmp2, publicKey->x, ecc_curve.p); /* tmp2 = x^2 */
	vli_mod_sub(tmp2, tmp2, na, ecc_curve.p);  /* tmp2 = x^2 + a = x^2 - 3 */
	vli_mod_mult_fast(tmp2, tmp2, publicKey->x, ecc_curve.p); /* tmp2 = x^3 + ax */
	vli_mod_add(tmp2, tmp2, ecc_curve.b, ecc_curve.p); /* tmp2 = x^3 + ax + b */

	/* Make sure that y^2 == x^3 + ax + b */
	if (vli_cmp(tmp1, tmp2) != 0)
		return 1;

	return 0;
}

int sm2_make_prikey(u8 *prikey)
{
	ecc_point pub[1];
	u8 pri[ECC_NUMWORD];
	int i = 10;

	do {
		vli_get_random(pri, ECC_NUMWORD);
		if(vli_cmp(ecc_curve.n, pri) != 1) {
			vli_sub(pri, pri, ecc_curve.n);
		}

		/* The private key cannot be 0 (mod p). */
		if(!vli_is_zero(pri)) {
			ecc_bytes2native(prikey, pri);
			return 0;
		}
	} while(i--);

	return -1;
}

int sm2_make_pubkey(u8 *prikey, ecc_point *pubkey)
{
	ecc_point pub[1];
	u8 pri[ECC_NUMWORD];

	ecc_bytes2native(pri, prikey);
	ecc_point_mult(pub, &ecc_curve.g, pri, NULL);
	ecc_bytes2native(pubkey->x, pub->x);
	ecc_bytes2native(pubkey->y, pub->y);

	return 0;
}

int sm2_make_keypair(u8 *prikey, ecc_point *pubkey)
{
	sm2_make_prikey(prikey);
	sm2_make_pubkey(prikey, pubkey);
	return 0;
}

int sm2_point_mult(ecc_point *G, u8 *k, ecc_point *P)
{
	int rc = 0;

	ecc_point G_[1];
	ecc_point P_[1];
	u8 k_[ECC_NUMWORD];

	ecc_bytes2native(k_, k);
	ecc_bytes2native(G_->x, G->x);
	ecc_bytes2native(G_->y, G->y);

	ecc_point_mult(P_, G_, k_, NULL);

	ecc_bytes2native(P->x, P_->x);
	ecc_bytes2native(P->y, P_->y);

	return rc;
}

int sm2_sign(u8 *r, u8 *s, u8 *prikey, u8 *hash)
{
	u8 k[ECC_NUMWORD];
	u8 one[ECC_NUMWORD] = {1};
	u8 random[ECC_NUMWORD];
	u8 pri[ECC_NUMWORD];
	u8 e[ECC_NUMWORD];
	ecc_point p;

	vli_set(e, hash);
	ecc_bytes2native(e, e);
	vli_set(pri, prikey);
	ecc_bytes2native(pri, pri);

	vli_get_random(random, ECC_NUMWORD);
	if (vli_is_zero(random)) {
		/* The random number must not be 0. */
		return 0;
	}

	vli_set(k, random);
	if (vli_cmp(ecc_curve.n, k) != 1) {
		vli_sub(k, k, ecc_curve.n);
	}

	/* tmp = k * G */
	ecc_point_mult(&p, &ecc_curve.g, k, NULL);

	/* r = x1 + e (mod n) */
	vli_set(r, p.x);
	vli_mod_add(r, r, e, ecc_curve.n);
	if (vli_cmp(ecc_curve.n, r) != 1) {
		vli_sub(r, r, ecc_curve.n);
	}

	if (vli_is_zero(r)) {
		/* If r == 0, fail (need a different random number). */
		return 0;
	}

	vli_mod_mult(s, r, pri, ecc_curve.n); /* s = r*d */
	vli_mod_sub(s, k, s, ecc_curve.n); /* k-r*d */
	vli_mod_add(pri, pri, one, ecc_curve.n); /* 1+d */
	vli_mod_inv(pri, pri, ecc_curve.n); /* (1+d)' */
	vli_mod_mult(s, pri, s, ecc_curve.n); /* (1+d)'*(k-r*d) */

	ecc_bytes2native(r, r);
	ecc_bytes2native(s, s);

	return 1;
}

int sm2_verify(ecc_point *pubkey, u8 *hash, u8 *r, u8 *s)
{
	ecc_point result;
	u8 t[ECC_NUMWORD];
	u8 e[ECC_NUMWORD];
	ecc_point pub[1];

	vli_set(e, hash);
	ecc_bytes2native(e, e);
	vli_set(pub->x, pubkey->x);
	vli_set(pub->y, pubkey->y);

	ecc_bytes2native(pub->x, pub->x);
	ecc_bytes2native(pub->y, pub->y);
	ecc_bytes2native(r, r);
	ecc_bytes2native(s, s);

	if (vli_is_zero(r) || vli_is_zero(s)) {
		/* r, s must not be 0. */
		return -1;
	}

	if (vli_cmp(ecc_curve.n, r) != 1 || vli_cmp(ecc_curve.n, s) != 1) {
		/* r, s must be < n. */
		return -1;
	}

	vli_mod_add(t, r, s, ecc_curve.n); // r + s
	if (t == 0)
		return -1;

	ecc_point_mult2(&result, &ecc_curve.g, pub, s, t);

	/* v = x1 + e (mod n) */
	vli_mod_add(result.x, result.x, e, ecc_curve.n);

	if(vli_cmp(ecc_curve.n, result.x) != 1) {
		vli_sub(result.x, result.x, ecc_curve.n);
	}

	/* Accept only if v == r. */
	return vli_cmp(result.x, r);
}

int sm2_encrypt(ecc_point *pubKey, u8 *M, u32 Mlen, u8 *C, u32 *Clen)
{
	u8 k[ECC_NUMWORD];
	u8 t[ECC_NUMWORD];
	ecc_point pub[1];
	ecc_point *C1 = (ecc_point *)C;
	u8 *C2 = C + ECC_NUMWORD*2;
	u8 *C3 = C + ECC_NUMWORD*2 + Mlen;

	ecc_point kP;
	u8 *x2 = kP.x;
	u8 *y2 = kP.y;
	u8 *x2y2 = x2;
	sm3_ctx md[1];
	int i=0;

	ecc_bytes2native(pub->x, pubKey->x);
	ecc_bytes2native(pub->y, pubKey->y);

	vli_get_random(k, ECC_NUMWORD);

	/* C1 = k * G */
	ecc_point_mult(C1, &ecc_curve.g, k, NULL);
	ecc_bytes2native(C1->x, C1->x);
	ecc_bytes2native(C1->y, C1->y);
	/*vli_set(C, C1->x);*/
	/*vli_set(C+ECC_NUMWORD, C1->y);*/

	/* S = h * Pb */
	ecc_point S;
	ecc_point_mult(&S, pub, ecc_curve.h, NULL);
	if (ecc_valid_public_key(&S) != 0)
		return -1;

	/* kP = k * Pb */
	ecc_point_mult(&kP, pub, k, NULL);
	ecc_bytes2native(x2, x2);
	ecc_bytes2native(y2, y2);
	/*vli_set(x2, kP.x);*/
	/*vli_set(y2, kP.y);*/

	/* t=KDF(x2 ∥ y2, klen) */
	sm3_kdf(x2y2, ECC_NUMWORD*2, t, Mlen);
	if (vli_is_zero(x2) | vli_is_zero(y2)) {
		return 0;
	}

	/* C2 = M ⊕ t；*/
	for (i = 0; i < Mlen; i++) {
		C2[i] = M[i]^t[+i];
	}

	/*C3 = Hash(x2 ∥ M ∥ y2)*/
	sm3_init(md);
	sm3_update(md, x2, ECC_NUMWORD);
	sm3_update(md, M, Mlen);
	sm3_update(md, y2, ECC_NUMWORD);
	sm3_finish(md, C3);

	if (Clen)
		*Clen = Mlen + ECC_NUMWORD*2 + ECC_NUMWORD;

	return 0;
}

int sm2_decrypt(u8 *prikey, u8 *C, u32 Clen, u8 *M, u32 *Mlen)
{
	u8 hash[ECC_NUMWORD];
	u8 pri[ECC_NUMWORD];
	ecc_point *C1 = (ecc_point *)C;
	u8 *C2 = C + ECC_NUMWORD*2;
	u8 *C3 = C + Clen - ECC_NUMWORD;
	ecc_point dB;
	u8 *x2 = dB.x;
	u8 *y2 = dB.y;
	u8 *x2y2 = x2;
	sm3_ctx md[1];
	int outlen = Clen-ECC_NUMWORD*3;
	int i=0;

	ecc_bytes2native(pri, prikey);
	ecc_bytes2native(C1->x, C1->x);
	ecc_bytes2native(C1->y, C1->y);

	if (ecc_valid_public_key(C1) != 0)
		return -1;

	ecc_point S;
	ecc_point_mult(&S, C1, ecc_curve.h, NULL);
	if (ecc_valid_public_key(&S) != 0)
		return -1;

	ecc_point_mult(&dB, C1, pri, NULL);
	ecc_bytes2native(x2, x2);
	ecc_bytes2native(y2, y2);

	sm3_kdf(x2y2, ECC_NUMWORD*2, M, outlen);
	if (vli_is_zero(x2) | vli_is_zero(y2)) {
		return 0;
	}

	for (i = 0; i < outlen; i++)
		M[i]=M[i]^C2[i];

	sm3_init(md);
	sm3_update(md, x2, ECC_NUMWORD);
	sm3_update(md, M, outlen);
	sm3_update(md, y2, ECC_NUMWORD);
	sm3_finish(md, hash);

	*Mlen = outlen;
	if (memcmp(hash , C3, ECC_NUMWORD) != 0)
		return -1;
	else
		return 0;
}

int sm2_shared_point(u8* selfPriKey,  u8* selfTempPriKey, ecc_point* selfTempPubKey,
		 ecc_point *otherPubKey, ecc_point* otherTempPubKey, ecc_point *key)
{
	ecc_point selfTempPub;
	ecc_point otherTempPub;
	ecc_point otherPub;
	ecc_point U[1];

	u8 selfTempPri[ECC_NUMWORD];
	u8 selfPri[ECC_NUMWORD];
	u8 temp1[ECC_NUMWORD];
	u8 temp2[ECC_NUMWORD];
	u8 tA[ECC_NUMWORD];

	ecc_bytes2native(selfTempPri, selfTempPriKey);
	ecc_bytes2native(selfPri, selfPriKey);
	ecc_bytes2native(selfTempPub.x, selfTempPubKey->x);
	ecc_bytes2native(selfTempPub.y, selfTempPubKey->y);
	ecc_bytes2native(otherTempPub.x, otherTempPubKey->x);
	ecc_bytes2native(otherTempPub.y, otherTempPubKey->y);
	ecc_bytes2native(otherPub.x, otherPubKey->x);
	ecc_bytes2native(otherPub.y, otherPubKey->y);

	/***********x1_=2^w+x2 & (2^w-1)*************/
	sm2_w(temp1, selfTempPub.x);
	/***********tA=(dA+x1_*rA)mod n *************/
	vli_mod_mult(temp1, selfTempPri, temp1, ecc_curve.n);
	vli_mod_add(tA, selfPri, temp1, ecc_curve.n);
	/***********x2_=2^w+x2 & (2^w-1)*************/
	if(ecc_valid_public_key(&otherTempPub) != 0)
		return -1;
	sm2_w(temp2, otherTempPub.x);
	/**************U=[h*tA](PB+[x2_]RB)**********/
	ecc_point_mult(U, &otherTempPub, temp2, NULL);/* U=[x2_]RB */
	ecc_point_add(U, &otherPub, U); /*U=PB+U*/
	vli_mod_mult(tA, tA, ecc_curve.h, ecc_curve.n); /*tA=tA*h */
	ecc_point_mult(U, U,tA, NULL);

	ecc_bytes2native(key->x, U->x);
	ecc_bytes2native(key->y, U->y);
}

int sm2_shared_key(ecc_point *point, u8 *ZA, u8 *ZB, u32 keyLen, u8 *key)
{
	u8 Z[ECC_NUMWORD*4];
	memcpy(Z, point->x, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD, point->y, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD*2, ZA, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD*3, ZB, ECC_NUMWORD);
	sm3_kdf(Z, ECC_NUMWORD*4, key, keyLen);
}

/****hash = Hash(Ux||ZA||ZB||x1||y1||x2||y2)****/
int ECC_Key_ex_hash1(u8* x, ecc_point *RA, ecc_point* RB, u8 ZA[],u8 ZB[],u8 *hash)
{
	sm3_ctx md[1];

	sm3_init(md);
	sm3_update(md, x, ECC_NUMWORD);
	sm3_update(md, ZA, ECC_NUMWORD);
	sm3_update(md, ZB, ECC_NUMWORD);
	sm3_update(md, RA->x, ECC_NUMWORD);
	sm3_update(md, RA->y, ECC_NUMWORD);
	sm3_update(md, RB->x, ECC_NUMWORD);
	sm3_update(md, RB->y, ECC_NUMWORD);
	sm3_finish(md, hash);

	return 0;
}

/****SA = Hash(temp||Uy||Hash)****/
int ECC_Key_ex_hash2(u8 temp, u8* y,u8 *hash, u8* SA)
{
	sm3_ctx md[1];

	sm3_init(md);
	sm3_update(md, &temp,1);
	sm3_update(md, y,ECC_NUMWORD);
	sm3_update(md, hash,ECC_NUMWORD);
	sm3_finish(md, SA);

	return 0;
}

int ECC_KeyEx_Init_I(u8 *pri, ecc_point *pub)
{
	return sm2_make_pubkey(pri, pub);
}

int ECC_KeyEx_Re_I(u8 *rb, u8 *dB, ecc_point *RA, ecc_point *PA, u8* ZA, u8 *ZB, u8 *K, u32 klen, ecc_point *RB, ecc_point *V, u8* SB)
{
	sm3_ctx md[1];
	u8 Z[ECC_NUMWORD*2 + ECC_NUMBITS/4]={0};
	u8 hash[ECC_NUMWORD],S1[ECC_NUMWORD];
	u8 temp=0x02;

	//--------B2: RB=[rb]G=(x2,y2)--------
	sm2_make_pubkey(rb, RB);
	/********************************************/
	sm2_shared_point(dB,  rb, RB, PA, RA, V);
	//------------B7:KB=KDF(VX,VY,ZA,ZB,KLEN)----------
	memcpy(Z, V->x, ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD, V->y, ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*2, ZA,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*3, ZB,ECC_NUMWORD);
	sm3_kdf(Z,ECC_NUMWORD*4, K, klen);
	//---------------B8:(optional) SB=hash(0x02||Vy||HASH(Vx||ZA||ZB||x1||y1||x2||y2)-------------
	ECC_Key_ex_hash1(V->x,  RA, RB, ZA, ZB, hash);
	ECC_Key_ex_hash2(temp, V->y, hash, SB);

	return 0;
}

int ECC_KeyEx_Init_II(u8* ra, u8* dA, ecc_point* RA, ecc_point* RB, ecc_point* PB, u8
		ZA[],u8 ZB[],u8 SB[],u8 K[], u32 klen,u8 SA[])
{
	sm3_ctx md[1];
	u8 Z[ECC_NUMWORD*2 + ECC_NUMWORD*2]={0};
	u8 hash[ECC_NUMWORD],S1[ECC_NUMWORD];
	u8 temp[2]={0x02,0x03};
	ecc_point U[1];

	/********************************************/
	sm2_shared_point(dA, ra, RA, PB, RB, U);
	/************KA=KDF(UX,UY,ZA,ZB,KLEN)**********/
	memcpy(Z, U->x,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD, U->y,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*2,ZA,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*2 +ECC_NUMWORD ,ZB,ECC_NUMWORD);
	sm3_kdf(Z,ECC_NUMWORD*2+ECC_NUMWORD*2, K, klen);
	/****S1 = Hash(0x02||Uy||Hash(Ux||ZA||ZB||x1||y1||x2||y2))****/
	ECC_Key_ex_hash1(U->x,  RA, RB, ZA, ZB, hash);
	ECC_Key_ex_hash2(temp[0], U->y, hash, S1);
	/*test S1=SB?*/
	if( memcmp(S1,SB,ECC_NUMWORD)!=0)
		return -1;
	/*SA = Hash(0x03||yU||Hash(xU||ZA||ZB||x1||y1||x2||y2)) */
	ECC_Key_ex_hash2(temp[1], U->y, hash, SA);

	return 0;
}

int ECC_KeyEx_Re_II(ecc_point *V, ecc_point *RA, ecc_point *RB, u8 ZA[], u8 ZB[], u8 SA[])
{
	u8 hash[ECC_NUMWORD];
	u8 S2[ECC_NUMWORD];
	u8 temp=0x03;
	sm3_ctx md[1];

	/*S2 = Hash(0x03||Vy||Hash(Vx||ZA||ZB||x1||y1||x2||y2))*/
	ECC_Key_ex_hash1(V->x,  RA, RB, ZA, ZB, hash);
	ECC_Key_ex_hash2(temp, V->y, hash, S2);

	if( memcmp(S2,SA,ECC_NUMWORD)!=0)
		return -1;

	return 0;
}
