/*
 * Authentication Header declarations
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id$
 */

#include "ipsec_md5h.h"
#include "ipsec_sha1.h"

#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif /* IPPROTO_AH */

#define AH_FLENGTH		12		/* size of fixed part */
#define AHMD5_KMAX		64		/* MD5 max 512 bits key */
#define AHMD5_AMAX		12		/* MD5 96 bits of authenticator */

#define AHMD596_KLEN		16		/* MD5 128 bits key */
#define AHSHA196_KLEN		20		/* SHA1 160 bits key */

#define AHMD596_ALEN    	16		/* MD5 128 bits authentication length */
#define AHSHA196_ALEN		20		/* SHA1 160 bits authentication length */

#define AHMD596_BLKLEN  	64		/* MD5 block length */
#define AHSHA196_BLKLEN 	64		/* SHA1 block length */
#define AHSHA2_256_BLKLEN 	64		/* SHA2-256 block length */
#define AHSHA2_384_BLKLEN 	128 		/* SHA2-384 block length (?) */
#define AHSHA2_512_BLKLEN 	128		/* SHA2-512 block length */

#define AH_BLKLEN_MAX 		128		/* keep up to date! */

#define AH_AMAX         	AHSHA196_ALEN   /* keep up to date! */
#define AHHMAC_HASHLEN  	12              /* authenticator length of 96bits */
#define AHHMAC_RPLLEN   	4               /* 32 bit replay counter */

#define DB_AH_PKTRX		0x0001
#define DB_AH_PKTRX2		0x0002
#define DB_AH_DMP		0x0004
#define DB_AH_IPSA		0x0010
#define DB_AH_XF		0x0020
#define DB_AH_INAU		0x0040
#define DB_AH_REPLAY		0x0100

#ifdef __KERNEL__

/* General HMAC algorithm is described in RFC 2104 */

#define		HMAC_IPAD	0x36
#define		HMAC_OPAD	0x5C

struct md5_ctx {
	MD5_CTX ictx;		/* context after H(K XOR ipad) */
	MD5_CTX	octx;		/* context after H(K XOR opad) */
};

struct sha1_ctx {
	SHA1_CTX ictx;		/* context after H(K XOR ipad) */
	SHA1_CTX octx;		/* context after H(K XOR opad) */
};

struct auth_alg {
	void (*init)(void *ctx);
	void (*update)(void *ctx, unsigned char *bytes, __u32 len);
	void (*final)(unsigned char *hash, void *ctx);
	int hashlen;
};

extern struct inet_protocol ah_protocol;

struct options;

extern int 
ah_rcv(struct sk_buff *skb,
       struct device *dev,
       struct options *opt, 
       __u32 daddr,
       unsigned short len,
       __u32 saddr,
       int redo,
       struct inet_protocol *protocol);

struct ahhdr				/* Generic AH header */
{
	__u8	ah_nh;			/* Next header (protocol) */
	__u8	ah_hl;			/* AH length, in 32-bit words */
	__u16	ah_rv;			/* reserved, must be 0 */
	__u32	ah_spi;			/* Security Parameters Index */
        __u32   ah_rpl;                 /* Replay prevention */
	__u8	ah_data[AHHMAC_HASHLEN];/* Authentication hash */
};
#define AH_BASIC_LEN 8      /* basic AH header is 8 bytes, nh,hl,rv,spi
			     * and the ah_hl, says how many bytes after that
			     * to cover. */


#ifdef CONFIG_IPSEC_DEBUG
extern int debug_ah;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */
