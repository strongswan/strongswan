/*
 * RCSID $Id$
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
