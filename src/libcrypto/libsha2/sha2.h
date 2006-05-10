#ifndef _SHA2_H
#define _SHA2_H
/*
 *  sha512.h
 *
 *  Written by Jari Ruusu, April 16 2001
 *
 *  Copyright 2001 by Jari Ruusu.
 *  Redistribution of this file is permitted under the GNU Public License.
 */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif

typedef struct {
    unsigned char   sha_out[64];    /* results are here, bytes 0...31 */
    u_int32_t       sha_H[8];
    u_int64_t       sha_blocks;
    int             sha_bufCnt;
} sha256_context;

typedef struct {
    unsigned char   sha_out[128];   /* results are here, bytes 0...63 */
    u_int64_t       sha_H[8];
    u_int64_t       sha_blocks;
    u_int64_t       sha_blocksMSB;
    int             sha_bufCnt;
} sha512_context;

/* no sha384_context, use sha512_context */

/* 256 bit hash, provides 128 bits of security against collision attacks */
extern void sha256_init(sha256_context *);
extern void sha256_write(sha256_context *, const unsigned char *, int);
extern void sha256_final(sha256_context *);
extern void sha256_hash_buffer(unsigned char *, int, unsigned char *, int);

/* 512 bit hash, provides 256 bits of security against collision attacks */
extern void sha512_init(sha512_context *);
extern void sha512_write(sha512_context *, const unsigned char *, int);
extern void sha512_final(sha512_context *);
extern void sha512_hash_buffer(unsigned char *, int, unsigned char *, int);

/* 384 bit hash, provides 192 bits of security against collision attacks */
extern void sha384_init(sha512_context *);
/* no sha384_write(), use sha512_write() */
/* no sha384_final(), use sha512_final(), result in ctx->sha_out[0...47]  */
extern void sha384_hash_buffer(unsigned char *, int, unsigned char *, int);
#endif /* _SHA2_H */
