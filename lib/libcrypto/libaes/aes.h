// I retain copyright in this code but I encourage its free use provided
// that I don't carry any responsibility for the results. I am especially 
// happy to see it used in free and open source software. If you do use 
// it I would appreciate an acknowledgement of its origin in the code or
// the product that results and I would also appreciate knowing a little
// about the use to which it is being put. I am grateful to Frank Yellin
// for some ideas that are used in this implementation.
//
// Dr B. R. Gladman <brg@gladman.uk.net> 6th April 2001.
//
// This is an implementation of the AES encryption algorithm (Rijndael)
// designed by Joan Daemen and Vincent Rijmen. This version is designed
// to provide both fixed and dynamic block and key lengths and can also 
// run with either big or little endian internal byte order (see aes.h). 
// It inputs block and key lengths in bytes with the legal values being 
// 16, 24 and 32.

/*
 * Modified by Jari Ruusu,  May 1 2001
 *  - Fixed some compile warnings, code was ok but gcc warned anyway.
 *  - Changed basic types: byte -> unsigned char, word -> u_int32_t
 *  - Major name space cleanup: Names visible to outside now begin
 *    with "aes_" or "AES_". A lot of stuff moved from aes.h to aes.c
 *  - Removed C++ and DLL support as part of name space cleanup.
 *  - Eliminated unnecessary recomputation of tables. (actual bug fix)
 *  - Merged precomputed constant tables to aes.c file.
 *  - Removed data alignment restrictions for portability reasons.
 *  - Made block and key lengths accept bit count (128/192/256)
 *    as well byte count (16/24/32).
 *  - Removed all error checks. This change also eliminated the need
 *    to preinitialize the context struct to zero.
 *  - Removed some totally unused constants.
 */

#ifndef _AES_H
#define _AES_H

#if defined(__linux__) && defined(__KERNEL__)
#  include <linux/types.h>
#else 
#  include <sys/types.h>
#endif

// CONFIGURATION OPTIONS (see also aes.c)
//
// Define AES_BLOCK_SIZE to set the cipher block size (16, 24 or 32) or
// leave this undefined for dynamically variable block size (this will
// result in much slower code).
// IMPORTANT NOTE: AES_BLOCK_SIZE is in BYTES (16, 24, 32 or undefined). If
// left undefined a slower version providing variable block length is compiled

#define AES_BLOCK_SIZE  16

// The number of key schedule words for different block and key lengths
// allowing for method of computation which requires the length to be a
// multiple of the key length
//
// Nk =       4   6   8
//        -------------
// Nb = 4 |  60  60  64
//      6 |  96  90  96
//      8 | 120 120 120

#if !defined(AES_BLOCK_SIZE) || (AES_BLOCK_SIZE == 32)
#define AES_KS_LENGTH   120
#define AES_RC_LENGTH    29
#else
#define AES_KS_LENGTH   4 * AES_BLOCK_SIZE
#define AES_RC_LENGTH   (9 * AES_BLOCK_SIZE) / 8 - 8
#endif

typedef struct
{
    u_int32_t    aes_Nkey;      // the number of words in the key input block
    u_int32_t    aes_Nrnd;      // the number of cipher rounds
    u_int32_t    aes_e_key[AES_KS_LENGTH];   // the encryption key schedule
    u_int32_t    aes_d_key[AES_KS_LENGTH];   // the decryption key schedule
#if !defined(AES_BLOCK_SIZE)
    u_int32_t    aes_Ncol;      // the number of columns in the cipher state
#endif
} aes_context;

// THE CIPHER INTERFACE

#if !defined(AES_BLOCK_SIZE)
extern void aes_set_blk(aes_context *, const int);
#endif
extern void aes_set_key(aes_context *, const unsigned char [], const int, const int);
extern void aes_encrypt(const aes_context *, const unsigned char [], unsigned char []);
extern void aes_decrypt(const aes_context *, const unsigned char [], unsigned char []);

// The block length inputs to aes_set_block and aes_set_key are in numbers
// of bytes or bits.  The calls to subroutines must be made in the above
// order but multiple calls can be made without repeating earlier calls
// if their parameters have not changed.

#endif  // _AES_H
