/*
 * RCSID $Id: ipsec_md5h.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */

/*
 * The rest of this file is Copyright RSA DSI. See the following comments
 * for the full Copyright notice.
 */

#ifndef _IPSEC_MD5H_H_
#define _IPSEC_MD5H_H_

/* GLOBAL.H - RSAREF types and constants
 */

/* PROTOTYPES should be set to one if and only if the compiler supports
     function argument prototyping.
   The following makes PROTOTYPES default to 0 if it has not already
     been defined with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif /* !PROTOTYPES */

/* POINTER defines a generic pointer type */
typedef __u8 *POINTER;

/* UINT2 defines a two byte word */
typedef __u16 UINT2;

/* UINT4 defines a four byte word */
typedef __u32 UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
   If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
     returns an empty list.
 */

#if PROTOTYPES
#define PROTO_LIST(list) list
#else /* PROTOTYPES */
#define PROTO_LIST(list) ()
#endif /* PROTOTYPES */


/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init PROTO_LIST ((void *));
void MD5Update PROTO_LIST
  ((void *, unsigned char *, __u32));
void MD5Final PROTO_LIST ((unsigned char [16], void *));
 
#endif /* _IPSEC_MD5H_H_ */
