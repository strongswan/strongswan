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

/*
 * $Log: ipsec_md5h.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.8  2002/09/10 01:45:09  mcr
 * 	changed type of MD5_CTX and SHA1_CTX to void * so that
 * 	the function prototypes would match, and could be placed
 * 	into a pointer to a function.
 *
 * Revision 1.7  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_md5h.h,v
 *
 * Revision 1.6  1999/12/13 13:59:13  rgb
 * Quick fix to argument size to Update bugs.
 *
 * Revision 1.5  1999/12/07 18:16:23  rgb
 * Fixed comments at end of #endif lines.
 *
 * Revision 1.4  1999/04/06 04:54:26  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.3  1999/01/22 06:19:58  rgb
 * 64-bit clean-up.
 *
 * Revision 1.2  1998/11/30 13:22:54  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.1  1998/06/18 21:27:48  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.2  1998/04/23 20:54:03  rgb
 * Fixed md5 and sha1 include file nesting issues, to be cleaned up when
 * verified.
 *
 * Revision 1.1  1998/04/09 03:04:21  henry
 * sources moved up from linux/net/ipsec
 * these two include files modified not to include others except in kernel
 *
 * Revision 1.1.1.1  1998/04/08 05:35:03  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * No changes.
 *
 * Revision 0.3  1996/11/20 14:48:53  ji
 * Release update only.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
