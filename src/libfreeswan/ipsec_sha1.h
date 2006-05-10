/*
 * RCSID $Id: ipsec_sha1.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */

/*
 * Here is the original comment from the distribution:

SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain

 * Adapted for use by the IPSEC code by John Ioannidis
 */


#ifndef _IPSEC_SHA1_H_
#define _IPSEC_SHA1_H_

typedef struct
{
	__u32	state[5];
	__u32	count[2];
	__u8	buffer[64];
} SHA1_CTX;

void SHA1Transform(__u32 state[5], __u8 buffer[64]);
void SHA1Init(void *context);
void SHA1Update(void *context, unsigned char *data, __u32 len);
void SHA1Final(unsigned char digest[20], void *context);

 
#endif /* _IPSEC_SHA1_H_ */

/*
 * $Log: ipsec_sha1.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.7  2002/09/10 01:45:09  mcr
 * 	changed type of MD5_CTX and SHA1_CTX to void * so that
 * 	the function prototypes would match, and could be placed
 * 	into a pointer to a function.
 *
 * Revision 1.6  2002/04/24 07:36:47  mcr
 * Moved from ./klips/net/ipsec/ipsec_sha1.h,v
 *
 * Revision 1.5  1999/12/13 13:59:13  rgb
 * Quick fix to argument size to Update bugs.
 *
 * Revision 1.4  1999/12/07 18:16:23  rgb
 * Fixed comments at end of #endif lines.
 *
 * Revision 1.3  1999/04/06 04:54:27  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.2  1998/11/30 13:22:54  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.1  1998/06/18 21:27:50  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.2  1998/04/23 20:54:05  rgb
 * Fixed md5 and sha1 include file nesting issues, to be cleaned up when
 * verified.
 *
 * Revision 1.1  1998/04/09 03:04:21  henry
 * sources moved up from linux/net/ipsec
 * these two include files modified not to include others except in kernel
 *
 * Revision 1.1.1.1  1998/04/08 05:35:04  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * New transform
 *
 */
