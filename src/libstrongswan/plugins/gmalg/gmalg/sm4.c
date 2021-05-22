#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "debug.h"
#include "sm4.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                      \
{                                                \
	(n) =     ( (u32) (b)[(i)    ] << 24 )   \
		| ( (u32) (b)[(i) + 1] << 16 )   \
		| ( (u32) (b)[(i) + 2] <<  8 )   \
		| ( (u32) (b)[(i) + 3]       );  \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                   \
{                                             \
	(b)[(i)    ] = (u8) ( (n) >> 24 );    \
	(b)[(i) + 1] = (u8) ( (n) >> 16 );    \
	(b)[(i) + 2] = (u8) ( (n) >>  8 );    \
	(b)[(i) + 3] = (u8) ( (n)       );    \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define SWAP(a,b) { u32 t = a; a = b; b = t;}

/*
 * Expanded SM4 S-boxes
 * Sbox table: 8bits input convert to 8 bits output*/

static const u8 SboxTable[16][16] =
{
	{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
	{0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
	{0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
	{0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
	{0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
	{0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
	{0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
	{0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
	{0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
	{0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
	{0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
	{0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
	{0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
	{0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
	{0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
	{0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

/* System parameter */
static const u32 FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};

/* fixed parameter */
static const u32 CK[32] =
{
	0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
	0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
	0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
	0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
	0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
	0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
	0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
	0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static u8 sm4Sbox(u8 inch)
{
	u8 *pTable = (u8 *)SboxTable;
	u8 retVal = (u8)(pTable[inch]);
	return retVal;
}

/*
 * private F(Lt) function:
 * "T algorithm" == "L algorithm" + "t algorithm".
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: c: c is calculated with line algorithm "L" and nonline algorithm "t"
 */
static u32 sm4Lt(u32 ka)
{
	u32 bb = 0;
	u32 c = 0;
	u8 a[4];
	u8 b[4];

	PUT_ULONG_BE(ka,a,0);
	b[0] = sm4Sbox(a[0]);
	b[1] = sm4Sbox(a[1]);
	b[2] = sm4Sbox(a[2]);
	b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0);
	c =bb^(ROTL(bb, 2))^(ROTL(bb, 10))^(ROTL(bb, 18))^(ROTL(bb, 24));
	return c;
}

/*
 * private F function:
 * Calculating and getting encryption/decryption contents.
 * args:    [in] x0: original contents;
 * args:    [in] x1: original contents;
 * args:    [in] x2: original contents;
 * args:    [in] x3: original contents;
 * args:    [in] rk: encryption/decryption key;
 * return the contents of encryption/decryption contents.
 */
static u32 sm4F(u32 x0, u32 x1, u32 x2, u32 x3, u32 rk)
{
	return (x0^sm4Lt(x1^x2^x3^rk));
}


/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static u32 sm4CalciRK(u32 ka)
{
	u32 bb = 0;
	u32 rk = 0;
	u8 a[4];
	u8 b[4];
	PUT_ULONG_BE(ka,a,0);
	b[0] = sm4Sbox(a[0]);
	b[1] = sm4Sbox(a[1]);
	b[2] = sm4Sbox(a[2]);
	b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0);
	rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
	return rk;
}

static void sm4_setkey( u32 SK[32], u8 key[16] )
{
	u32 MK[4];
	u32 k[36];
	u32 i = 0;

	GET_ULONG_BE( MK[0], key, 0 );
	GET_ULONG_BE( MK[1], key, 4 );
	GET_ULONG_BE( MK[2], key, 8 );
	GET_ULONG_BE( MK[3], key, 12 );
	k[0] = MK[0]^FK[0];
	k[1] = MK[1]^FK[1];
	k[2] = MK[2]^FK[2];
	k[3] = MK[3]^FK[3];
	for(; i<32; i++)
	{
		k[i+4] = k[i] ^ (sm4CalciRK(k[i+1]^k[i+2]^k[i+3]^CK[i]));
		SK[i] = k[i+4];
	}
}

/*
 * SM4 standard one round processing
 *
 */
static void sm4_one_round( u32 sk[32],
		u8 input[16],
		u8 output[16] )
{
	u32 i = 0;
	u32 ulbuf[36];

	memset(ulbuf, 0, sizeof(ulbuf));
	GET_ULONG_BE( ulbuf[0], input, 0 );
	GET_ULONG_BE( ulbuf[1], input, 4 );
	GET_ULONG_BE( ulbuf[2], input, 8 );
	GET_ULONG_BE( ulbuf[3], input, 12 );
	while(i<32) {
		ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], sk[i]);
		#if ALG_DEBUG
			printf("rk(%02d) = 0x%08x,  X(%02d) = 0x%08x \n",i,sk[i], i, ulbuf[i+4] );
		#endif
		i++;
	}
	PUT_ULONG_BE(ulbuf[35],output,0);
	PUT_ULONG_BE(ulbuf[34],output,4);
	PUT_ULONG_BE(ulbuf[33],output,8);
	PUT_ULONG_BE(ulbuf[32],output,12);
}

int sm4_set_key(sm4_ctx *ctx, u8 *key, u32 len)
{
	int i;

#if DEBUG
	printf(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif
	if( len != 16) {
		printf(" sm4 set key leng  errr \n");
		return -1;
	}

	sm4_setkey(ctx->sk_enc, key);

	memcpy(ctx->sk_dec, ctx->sk_enc, 32*4);
	for(i = 0; i < 16; i ++) {
		SWAP(ctx->sk_dec[i], ctx->sk_dec[31-i]);
	}

	return 0;
}

void sm4_ecb_encrypt(sm4_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out)
{
#if DEBUG
	printf(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif
	sm4_set_key(ctx, key, 16);

	while(len > 0) {
		sm4_one_round(ctx->sk_enc, in, out);
		in  += 16;
		out += 16;
		len -= 16;
	}
}

void sm4_ecb_decrypt(sm4_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out)
{

#if DEBUG
	printf(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif
	while( len > 0 ) {
		sm4_one_round( ctx->sk_dec, in, out);
		in  += 16;
		out += 16;
		len -= 16;
	}
}

void sm4_cbc_encrypt(sm4_ctx *ctx, u8 *key, u8 *iv, u8 *in, u8 len, u8 *out)
{
#if DEBUG
	printf(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif
	int i;

	sm4_set_key(ctx, key, 16);
	while(len > 0)
	{
		for(i = 0; i < 16; i++)
		{
			out[i] = (u8)(in[i] ^ iv[i]);
		}
		sm4_one_round(ctx->sk_enc, out, out);
		iv = out;
		in  += 16;
		out += 16;
		len -= 16;
	}
}

void sm4_cbc_decrypt(sm4_ctx *ctx, u8 *key, u8 *iv, u8 *in, u8 len, u8 *out)
{
#if DEBUG
	printf(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif
	u8 temp[16];
	u8 temp_iv[16];
	int i;

	sm4_set_key(ctx, key, 16);
	
	while(len > 0)
	{
		if(in == out)
		{
			memcpy(temp, in, 16); /* /if in and out are same buf, bakup in as next iv. */
		}
		sm4_one_round(ctx->sk_dec, in, out);
		for(i = 0; i < 16; i++)
		{
			out[i] = (u8)(out[i] ^ iv[i]);
		}
		if(in == out)
		{
			memcpy(temp_iv, temp, 16);
			iv = temp_iv;
		}
		else
		{
			iv = in;
		}
		in  += 16;
		out += 16;
		len -= 16;
	}

}
