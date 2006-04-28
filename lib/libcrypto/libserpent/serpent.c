
/* Optimized implementation of the Serpent AES candidate algorithm
 * Designed by Anderson, Biham and Knudsen and Implemented by 
 * Gisle Sælensminde 2000. 
 *
 * The implementation is based on the pentium optimised sboxes of
 * Dag Arne Osvik. Even these sboxes are designed to be optimal for x86 
 * processors they are efficient on other processors as well, but the speedup 
 * isn't so impressive compared to other implementations.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License
 * as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version. 
 */

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/types.h>

#include <asm/byteorder.h>
#else
#include <sys/types.h>
#include <asm/byteorder.h>
#endif

#include "serpent.h"

#define rotl(reg, val) ((reg << val) | (reg >> (32 - val)))
#define rotr(reg, val) ((reg >> val) | (reg << (32 - val)))
 
#ifdef __cpu_to_be32
#define BLOCK_SWAP
#define io_swap(x)  __cpu_to_be32(x)
#else
#undef BLOCK_SWAP
#endif

/* The sbox functions. The first four parameters is the input bits, and 
 * the last is a tempoary. These parameters are also used for output, but
 * the bit order is permuted. The output bit order from S0 is
 * (1 4 2 0 3), where 3 is the (now useless) tempoary. 
 */

#define S0(r0,r1,r2,r3,r4) \
      r3 = r3 ^ r0; \
      r4 = r1; \
      r1 = r1 & r3; \
      r4 = r4 ^ r2; \
      r1 = r1 ^ r0; \
      r0 = r0 | r3; \
      r0 = r0 ^ r4; \
      r4 = r4 ^ r3; \
      r3 = r3 ^ r2; \
      r2 = r2 | r1; \
      r2 = r2 ^ r4; \
      r4 = -1 ^ r4; \
      r4 = r4 | r1; \
      r1 = r1 ^ r3; \
      r1 = r1 ^ r4; \
      r3 = r3 | r0; \
      r1 = r1 ^ r3; \
      r4 = r4 ^ r3; 

#define S1(r0,r1,r2,r3,r4) \
      r1 = -1 ^ r1; \
      r4 = r0; \
      r0 = r0 ^ r1; \
      r4 = r4 | r1; \
      r4 = r4 ^ r3; \
      r3 = r3 & r0; \
      r2 = r2 ^ r4; \
      r3 = r3 ^ r1; \
      r3 = r3 | r2; \
      r0 = r0 ^ r4; \
      r3 = r3 ^ r0; \
      r1 = r1 & r2; \
      r0 = r0 | r1; \
      r1 = r1 ^ r4; \
      r0 = r0 ^ r2; \
      r4 = r4 | r3; \
      r0 = r0 ^ r4; \
      r4 = -1 ^ r4; \
      r1 = r1 ^ r3; \
      r4 = r4 & r2; \
      r1 = -1 ^ r1; \
      r4 = r4 ^ r0; \
      r1 = r1 ^ r4; 

#define S2(r0,r1,r2,r3,r4) \
      r4 = r0; \
      r0 = r0 & r2; \
      r0 = r0 ^ r3; \
      r2 = r2 ^ r1; \
      r2 = r2 ^ r0; \
      r3 = r3 | r4; \
      r3 = r3 ^ r1; \
      r4 = r4 ^ r2; \
      r1 = r3; \
      r3 = r3 | r4; \
      r3 = r3 ^ r0; \
      r0 = r0 & r1; \
      r4 = r4 ^ r0; \
      r1 = r1 ^ r3; \
      r1 = r1 ^ r4; \
      r4 = -1 ^ r4; 

#define S3(r0,r1,r2,r3,r4) \
      r4 = r0 ; \
      r0 = r0 | r3; \
      r3 = r3 ^ r1; \
      r1 = r1 & r4; \
      r4 = r4 ^ r2; \
      r2 = r2 ^ r3; \
      r3 = r3 & r0; \
      r4 = r4 | r1; \
      r3 = r3 ^ r4; \
      r0 = r0 ^ r1; \
      r4 = r4 & r0; \
      r1 = r1 ^ r3; \
      r4 = r4 ^ r2; \
      r1 = r1 | r0; \
      r1 = r1 ^ r2; \
      r0 = r0 ^ r3; \
      r2 = r1; \
      r1 = r1 | r3; \
      r1 = r1 ^ r0; 

#define S4(r0,r1,r2,r3,r4) \
      r1 = r1 ^ r3; \
      r3 = -1 ^ r3; \
      r2 = r2 ^ r3; \
      r3 = r3 ^ r0; \
      r4 = r1; \
      r1 = r1 & r3; \
      r1 = r1 ^ r2; \
      r4 = r4 ^ r3; \
      r0 = r0 ^ r4; \
      r2 = r2 & r4; \
      r2 = r2 ^ r0; \
      r0 = r0 & r1; \
      r3 = r3 ^ r0; \
      r4 = r4 | r1; \
      r4 = r4 ^ r0; \
      r0 = r0 | r3; \
      r0 = r0 ^ r2; \
      r2 = r2 & r3; \
      r0 = -1 ^ r0; \
      r4 = r4 ^ r2; 

#define S5(r0,r1,r2,r3,r4) \
      r0 = r0 ^ r1; \
      r1 = r1 ^ r3; \
      r3 = -1 ^ r3; \
      r4 = r1; \
      r1 = r1 & r0; \
      r2 = r2 ^ r3; \
      r1 = r1 ^ r2; \
      r2 = r2 | r4; \
      r4 = r4 ^ r3; \
      r3 = r3 & r1; \
      r3 = r3 ^ r0; \
      r4 = r4 ^ r1; \
      r4 = r4 ^ r2; \
      r2 = r2 ^ r0; \
      r0 = r0 & r3; \
      r2 = -1 ^ r2; \
      r0 = r0 ^ r4; \
      r4 = r4 | r3; \
      r2 = r2 ^ r4; 

#define S6(r0,r1,r2,r3,r4) \
      r2 = -1 ^ r2; \
      r4 = r3; \
      r3 = r3 & r0; \
      r0 = r0 ^ r4; \
      r3 = r3 ^ r2; \
      r2 = r2 | r4; \
      r1 = r1 ^ r3; \
      r2 = r2 ^ r0; \
      r0 = r0 | r1; \
      r2 = r2 ^ r1; \
      r4 = r4 ^ r0; \
      r0 = r0 | r3; \
      r0 = r0 ^ r2; \
      r4 = r4 ^ r3; \
      r4 = r4 ^ r0; \
      r3 = -1 ^ r3; \
      r2 = r2 & r4; \
      r2 = r2 ^ r3; 

#define S7(r0,r1,r2,r3,r4) \
      r4 = r2; \
      r2 = r2 & r1; \
      r2 = r2 ^ r3; \
      r3 = r3 & r1; \
      r4 = r4 ^ r2; \
      r2 = r2 ^ r1; \
      r1 = r1 ^ r0; \
      r0 = r0 | r4; \
      r0 = r0 ^ r2; \
      r3 = r3 ^ r1; \
      r2 = r2 ^ r3; \
      r3 = r3 & r0; \
      r3 = r3 ^ r4; \
      r4 = r4 ^ r2; \
      r2 = r2 & r0; \
      r4 = -1 ^ r4; \
      r2 = r2 ^ r4; \
      r4 = r4 & r0; \
      r1 = r1 ^ r3; \
      r4 = r4 ^ r1; 

/* The inverse sboxes */

#define I0(r0,r1,r2,r3,r4) \
      r2 = r2 ^ -1; \
      r4 = r1; \
      r1 = r1 | r0; \
      r4 = r4 ^ -1; \
      r1 = r1 ^ r2; \
      r2 = r2 | r4; \
      r1 = r1 ^ r3; \
      r0 = r0 ^ r4; \
      r2 = r2 ^ r0; \
      r0 = r0 & r3; \
      r4 = r4 ^ r0; \
      r0 = r0 | r1; \
      r0 = r0 ^ r2; \
      r3 = r3 ^ r4; \
      r2 = r2 ^ r1; \
      r3 = r3 ^ r0; \
      r3 = r3 ^ r1; \
      r2 = r2 & r3; \
      r4 = r4 ^ r2; 
 
#define I1(r0,r1,r2,r3,r4) \
      r4 = r1; \
      r1 = r1 ^ r3; \
      r3 = r3 & r1; \
      r4 = r4 ^ r2; \
      r3 = r3 ^ r0; \
      r0 = r0 | r1; \
      r2 = r2 ^ r3; \
      r0 = r0 ^ r4; \
      r0 = r0 | r2; \
      r1 = r1 ^ r3; \
      r0 = r0 ^ r1; \
      r1 = r1 | r3; \
      r1 = r1 ^ r0; \
      r4 = r4 ^ -1; \
      r4 = r4 ^ r1; \
      r1 = r1 | r0; \
      r1 = r1 ^ r0; \
      r1 = r1 | r4; \
      r3 = r3 ^ r1; 

#define I2(r0,r1,r2,r3,r4) \
      r2 = r2 ^ r3; \
      r3 = r3 ^ r0; \
      r4 =  r3; \
      r3 = r3 & r2; \
      r3 = r3 ^ r1; \
      r1 = r1 | r2; \
      r1 = r1 ^ r4; \
      r4 = r4 & r3; \
      r2 = r2 ^ r3; \
      r4 = r4 & r0; \
      r4 = r4 ^ r2; \
      r2 = r2 & r1; \
      r2 = r2 | r0; \
      r3 = r3 ^ -1; \
      r2 = r2 ^ r3; \
      r0 = r0 ^ r3; \
      r0 = r0 & r1; \
      r3 = r3 ^ r4; \
      r3 = r3 ^ r0; 

#define I3(r0,r1,r2,r3,r4) \
      r4 =  r2; \
      r2 = r2 ^ r1; \
      r0 = r0 ^ r2; \
      r4 = r4 & r2; \
      r4 = r4 ^ r0; \
      r0 = r0 & r1; \
      r1 = r1 ^ r3; \
      r3 = r3 | r4; \
      r2 = r2 ^ r3; \
      r0 = r0 ^ r3; \
      r1 = r1 ^ r4; \
      r3 = r3 & r2; \
      r3 = r3 ^ r1; \
      r1 = r1 ^ r0; \
      r1 = r1 | r2; \
      r0 = r0 ^ r3; \
      r1 = r1 ^ r4; \
      r0 = r0 ^ r1; 

#define I4(r0,r1,r2,r3,r4) \
      r4 =  r2; \
      r2 = r2 & r3; \
      r2 = r2 ^ r1; \
      r1 = r1 | r3; \
      r1 = r1 & r0; \
      r4 = r4 ^ r2; \
      r4 = r4 ^ r1; \
      r1 = r1 & r2; \
      r0 = r0 ^ -1; \
      r3 = r3 ^ r4; \
      r1 = r1 ^ r3; \
      r3 = r3 & r0; \
      r3 = r3 ^ r2; \
      r0 = r0 ^ r1; \
      r2 = r2 & r0; \
      r3 = r3 ^ r0; \
      r2 = r2 ^ r4; \
      r2 = r2 | r3; \
      r3 = r3 ^ r0; \
      r2 = r2 ^ r1; 

#define I5(r0,r1,r2,r3,r4) \
      r1 = r1 ^ -1; \
      r4 = r3; \
      r2 = r2 ^ r1; \
      r3 = r3 | r0; \
      r3 = r3 ^ r2; \
      r2 = r2 | r1; \
      r2 = r2 & r0; \
      r4 = r4 ^ r3; \
      r2 = r2 ^ r4; \
      r4 = r4 | r0; \
      r4 = r4 ^ r1; \
      r1 = r1 & r2; \
      r1 = r1 ^ r3; \
      r4 = r4 ^ r2; \
      r3 = r3 & r4; \
      r4 = r4 ^ r1; \
      r3 = r3 ^ r0; \
      r3 = r3 ^ r4; \
      r4 = r4 ^ -1; 


#define I6(r0,r1,r2,r3,r4) \
      r0 = r0 ^ r2; \
      r4 = r2; \
      r2 = r2 & r0; \
      r4 = r4 ^ r3; \
      r2 = r2 ^ -1; \
      r3 = r3 ^ r1; \
      r2 = r2 ^ r3; \
      r4 = r4 | r0; \
      r0 = r0 ^ r2; \
      r3 = r3 ^ r4; \
      r4 = r4 ^ r1; \
      r1 = r1 & r3; \
      r1 = r1 ^ r0; \
      r0 = r0 ^ r3; \
      r0 = r0 | r2; \
      r3 = r3 ^ r1; \
      r4 = r4 ^ r0; 

#define I7(r0,r1,r2,r3,r4) \
      r4 = r2; \
      r2 = r2 ^ r0; \
      r0 = r0 & r3; \
      r4 = r4 | r3; \
      r2 = r2 ^ -1; \
      r3 = r3 ^ r1; \
      r1 = r1 | r0; \
      r0 = r0 ^ r2; \
      r2 = r2 & r4; \
      r3 = r3 & r4; \
      r1 = r1 ^ r2; \
      r2 = r2 ^ r0; \
      r0 = r0 | r2; \
      r4 = r4 ^ r1; \
      r0 = r0 ^ r3; \
      r3 = r3 ^ r4; \
      r4 = r4 | r0; \
      r3 = r3 ^ r2; \
      r4 = r4 ^ r2; 

/* forward and inverse linear transformations */

#define LINTRANS(r0,r1,r2,r3,r4) \
      r0 = rotl(r0, 13); \
      r2 = rotl(r2, 3); \
      r3 = r3 ^ r2; \
      r4 = r0 << 3; \
      r1 = r1 ^ r0; \
      r3 = r3 ^ r4; \
      r1 = r1 ^ r2; \
      r3 = rotl(r3, 7); \
      r1 = rotl(r1, 1); \
      r2 = r2 ^ r3; \
      r4 = r1 << 7; \
      r0 = r0 ^ r1; \
      r2 = r2 ^ r4; \
      r0 = r0 ^ r3; \
      r2 = rotl(r2, 22); \
      r0 = rotl(r0, 5);
     
#define ILINTRANS(r0,r1,r2,r3,r4) \
      r2 = rotr(r2, 22); \
      r0 = rotr(r0, 5); \
      r2 = r2 ^ r3; \
      r4 = r1 << 7; \
      r0 = r0 ^ r1; \
      r2 = r2 ^ r4; \
      r0 = r0 ^ r3; \
      r3 = rotr(r3, 7); \
      r1 = rotr(r1, 1); \
      r3 = r3 ^ r2; \
      r4 = r0 << 3; \
      r1 = r1 ^ r0; \
      r3 = r3 ^ r4; \
      r1 = r1 ^ r2; \
      r2 = rotr(r2, 3); \
      r0 = rotr(r0, 13); 


#define KEYMIX(r0,r1,r2,r3,r4,IN) \
      r0  = r0 ^ l_key[IN+8]; \
      r1  = r1 ^ l_key[IN+9]; \
      r2  = r2 ^ l_key[IN+10]; \
      r3  = r3 ^ l_key[IN+11]; 

#define GETKEY(r0, r1, r2, r3, IN) \
      r0 = l_key[IN+8]; \
      r1 = l_key[IN+9]; \
      r2 = l_key[IN+10]; \
      r3 = l_key[IN+11]; 

#define SETKEY(r0, r1, r2, r3, IN) \
      l_key[IN+8] = r0; \
      l_key[IN+9] = r1; \
      l_key[IN+10] = r2; \
      l_key[IN+11] = r3;

/* initialise the key schedule from the user supplied key   */

int serpent_set_key(serpent_context *cx, const unsigned char *key, int key_len)
{   const u32 *in_key = (const u32 *)key;
    /* l_key - storage for the key schedule */
    u32 *l_key   = cx->keyinfo;
    u32  i,lk,r0,r1,r2,r3,r4;

    if (key_len != 16 && key_len != 24 && key_len != 32)
      return -1; /* unsupported key length */
    
    key_len *= 8;

    i = 0; lk = (key_len + 31) / 32;
    
    while(i < lk)
    {
#ifdef  BLOCK_SWAP
        l_key[i] = io_swap(in_key[lk - i - 1]);
#else
        l_key[i] = in_key[i];
#endif  
        i++;
    }

    if (key_len < 256)
    {
        while(i < 8)

            l_key[i++] = 0;

        i = key_len / 32; lk = 1 << key_len % 32; 

        l_key[i] &= lk - 1;
        l_key[i] |= lk;
    }

    for(i = 0; i < 132; ++i)
    {
        lk = l_key[i] ^ l_key[i + 3] ^ l_key[i + 5] 
                                ^ l_key[i + 7] ^ 0x9e3779b9 ^ i;

        l_key[i + 8] = (lk << 11) | (lk >> 21); 
    }

      GETKEY(r0, r1, r2, r3, 0);
      S3(r0,r1,r2,r3,r4);
      SETKEY(r1, r2, r3, r4, 0) 

      GETKEY(r0, r1, r2, r3, 4);
      S2(r0,r1,r2,r3,r4);
      SETKEY(r2, r3, r1, r4, 4) 

      GETKEY(r0, r1, r2, r3, 8);
      S1(r0,r1,r2,r3,r4);
      SETKEY(r3, r1, r2, r0, 8) 

      GETKEY(r0, r1, r2, r3, 12);
      S0(r0,r1,r2,r3,r4);
      SETKEY(r1, r4, r2, r0, 12) 

      GETKEY(r0, r1, r2, r3, 16);
      S7(r0,r1,r2,r3,r4);
      SETKEY(r2, r4, r3, r0, 16) 

      GETKEY(r0, r1, r2, r3, 20);
      S6(r0,r1,r2,r3,r4) 
      SETKEY(r0, r1, r4, r2, 20) 

      GETKEY(r0, r1, r2, r3, 24);
      S5(r0,r1,r2,r3,r4);
      SETKEY(r1, r3, r0, r2, 24) 

      GETKEY(r0, r1, r2, r3, 28);
      S4(r0,r1,r2,r3,r4) 
      SETKEY(r1, r4, r0, r3, 28) 

      GETKEY(r0, r1, r2, r3, 32);
      S3(r0,r1,r2,r3,r4);
      SETKEY(r1, r2, r3, r4, 32) 

      GETKEY(r0, r1, r2, r3, 36);
      S2(r0,r1,r2,r3,r4);
      SETKEY(r2, r3, r1, r4, 36) 

      GETKEY(r0, r1, r2, r3, 40);
      S1(r0,r1,r2,r3,r4);
      SETKEY(r3, r1, r2, r0, 40) 

      GETKEY(r0, r1, r2, r3, 44);
      S0(r0,r1,r2,r3,r4);
      SETKEY(r1, r4, r2, r0, 44) 

      GETKEY(r0, r1, r2, r3, 48);
      S7(r0,r1,r2,r3,r4);
      SETKEY(r2, r4, r3, r0, 48) 

      GETKEY(r0, r1, r2, r3, 52);
      S6(r0,r1,r2,r3,r4) 
      SETKEY(r0, r1, r4, r2, 52) 

      GETKEY(r0, r1, r2, r3, 56);
      S5(r0,r1,r2,r3,r4);
      SETKEY(r1, r3, r0, r2, 56) 

      GETKEY(r0, r1, r2, r3, 60);
      S4(r0,r1,r2,r3,r4) 
      SETKEY(r1, r4, r0, r3, 60) 

      GETKEY(r0, r1, r2, r3, 64);
      S3(r0,r1,r2,r3,r4);
      SETKEY(r1, r2, r3, r4, 64) 

      GETKEY(r0, r1, r2, r3, 68);
      S2(r0,r1,r2,r3,r4);
      SETKEY(r2, r3, r1, r4, 68) 

      GETKEY(r0, r1, r2, r3, 72);
      S1(r0,r1,r2,r3,r4);
      SETKEY(r3, r1, r2, r0, 72) 

      GETKEY(r0, r1, r2, r3, 76);
      S0(r0,r1,r2,r3,r4);
      SETKEY(r1, r4, r2, r0, 76) 

      GETKEY(r0, r1, r2, r3, 80);
      S7(r0,r1,r2,r3,r4);
      SETKEY(r2, r4, r3, r0, 80) 

      GETKEY(r0, r1, r2, r3, 84);
      S6(r0,r1,r2,r3,r4) 
      SETKEY(r0, r1, r4, r2, 84) 

      GETKEY(r0, r1, r2, r3, 88);
      S5(r0,r1,r2,r3,r4);
      SETKEY(r1, r3, r0, r2, 88) 

      GETKEY(r0, r1, r2, r3, 92);
      S4(r0,r1,r2,r3,r4) 
      SETKEY(r1, r4, r0, r3, 92) 

      GETKEY(r0, r1, r2, r3, 96);
      S3(r0,r1,r2,r3,r4);
      SETKEY(r1, r2, r3, r4, 96) 

      GETKEY(r0, r1, r2, r3, 100);
      S2(r0,r1,r2,r3,r4);
      SETKEY(r2, r3, r1, r4, 100) 

      GETKEY(r0, r1, r2, r3, 104);
      S1(r0,r1,r2,r3,r4);
      SETKEY(r3, r1, r2, r0, 104) 

      GETKEY(r0, r1, r2, r3, 108);
      S0(r0,r1,r2,r3,r4);
      SETKEY(r1, r4, r2, r0, 108) 

      GETKEY(r0, r1, r2, r3, 112);
      S7(r0,r1,r2,r3,r4);
      SETKEY(r2, r4, r3, r0, 112) 

      GETKEY(r0, r1, r2, r3, 116);
      S6(r0,r1,r2,r3,r4) 
      SETKEY(r0, r1, r4, r2, 116) 

      GETKEY(r0, r1, r2, r3, 120);
      S5(r0,r1,r2,r3,r4);
      SETKEY(r1, r3, r0, r2, 120) 

      GETKEY(r0, r1, r2, r3, 124);
      S4(r0,r1,r2,r3,r4) 
      SETKEY(r1, r4, r0, r3, 124) 

      GETKEY(r0, r1, r2, r3, 128);
      S3(r0,r1,r2,r3,r4);
      SETKEY(r1, r2, r3, r4, 128) 

    return 0;
};

/* Encryption and decryption functions. The rounds are fully inlined. 
 * The sboxes alters the bit order of the output, and the altered
 * bit ordrer is used progressivly. */

/* encrypt a block of text */

int serpent_encrypt(serpent_context *cx, const u8 *in, 
		    u8 *out)
{    u32 *l_key = cx->keyinfo;
     const u32 *in_blk = (const u32 *) in;
     u32 *out_blk = (u32 *) out;
     u32  r0,r1,r2,r3,r4;
    
#ifdef  BLOCK_SWAP
    r0 = io_swap(in_blk[3]); r1 = io_swap(in_blk[2]); 
    r2 = io_swap(in_blk[1]); r3 = io_swap(in_blk[0]);
#else
    r0 = in_blk[0]; r1 = in_blk[1]; r2 = in_blk[2]; r3 = in_blk[3];
#endif

      /* round 1  */
      KEYMIX(r0,r1,r2,r3,r4,0);
      S0(r0,r1,r2,r3,r4);
      LINTRANS(r1,r4,r2,r0,r3);

      /* round 2  */
      KEYMIX(r1,r4,r2,r0,r3,4);
      S1(r1,r4,r2,r0,r3);
      LINTRANS(r0,r4,r2,r1,r3);

      /* round 3  */
      KEYMIX(r0,r4,r2,r1,r3,8);
      S2(r0,r4,r2,r1,r3);
      LINTRANS(r2,r1,r4,r3,r0);

      /* round 4  */
      KEYMIX(r2,r1,r4,r3,r0,12);
      S3(r2,r1,r4,r3,r0);
      LINTRANS(r1,r4,r3,r0,r2);

      /* round 5  */
      KEYMIX(r1,r4,r3,r0,r2,16);
      S4(r1,r4,r3,r0,r2) 
      LINTRANS(r4,r2,r1,r0,r3);

      /* round 6  */
      KEYMIX(r4,r2,r1,r0,r3,20);
      S5(r4,r2,r1,r0,r3);
      LINTRANS(r2,r0,r4,r1,r3);

      /* round 7  */
      KEYMIX(r2,r0,r4,r1,r3,24);
      S6(r2,r0,r4,r1,r3) 
      LINTRANS(r2,r0,r3,r4,r1);

      /* round 8  */
      KEYMIX(r2,r0,r3,r4,r1,28);
      S7(r2,r0,r3,r4,r1);
      LINTRANS(r3,r1,r4,r2,r0);

      /* round 9  */
      KEYMIX(r3,r1,r4,r2,r0,32);
      S0(r3,r1,r4,r2,r0);
      LINTRANS(r1,r0,r4,r3,r2);

      /* round 10  */
      KEYMIX(r1,r0,r4,r3,r2,36);
      S1(r1,r0,r4,r3,r2);
      LINTRANS(r3,r0,r4,r1,r2);

      /* round 11  */
      KEYMIX(r3,r0,r4,r1,r2,40);
      S2(r3,r0,r4,r1,r2);
      LINTRANS(r4,r1,r0,r2,r3);

      /* round 12  */
      KEYMIX(r4,r1,r0,r2,r3,44);
      S3(r4,r1,r0,r2,r3);
      LINTRANS(r1,r0,r2,r3,r4);

      /* round 13  */
      KEYMIX(r1,r0,r2,r3,r4,48);
      S4(r1,r0,r2,r3,r4) 
      LINTRANS(r0,r4,r1,r3,r2);

      /* round 14  */
      KEYMIX(r0,r4,r1,r3,r2,52);
      S5(r0,r4,r1,r3,r2);
      LINTRANS(r4,r3,r0,r1,r2);

      /* round 15  */
      KEYMIX(r4,r3,r0,r1,r2,56);
      S6(r4,r3,r0,r1,r2) 
      LINTRANS(r4,r3,r2,r0,r1);

      /* round 16  */
      KEYMIX(r4,r3,r2,r0,r1,60);
      S7(r4,r3,r2,r0,r1);
      LINTRANS(r2,r1,r0,r4,r3);

      /* round 17  */
      KEYMIX(r2,r1,r0,r4,r3,64);
      S0(r2,r1,r0,r4,r3);
      LINTRANS(r1,r3,r0,r2,r4);

      /* round 18  */
      KEYMIX(r1,r3,r0,r2,r4,68);
      S1(r1,r3,r0,r2,r4);
      LINTRANS(r2,r3,r0,r1,r4);

      /* round 19  */
      KEYMIX(r2,r3,r0,r1,r4,72);
      S2(r2,r3,r0,r1,r4);
      LINTRANS(r0,r1,r3,r4,r2);

      /* round 20  */
      KEYMIX(r0,r1,r3,r4,r2,76);
      S3(r0,r1,r3,r4,r2);
      LINTRANS(r1,r3,r4,r2,r0);

      /* round 21  */
      KEYMIX(r1,r3,r4,r2,r0,80);
      S4(r1,r3,r4,r2,r0) 
      LINTRANS(r3,r0,r1,r2,r4);

      /* round 22  */
      KEYMIX(r3,r0,r1,r2,r4,84);
      S5(r3,r0,r1,r2,r4);
      LINTRANS(r0,r2,r3,r1,r4);

      /* round 23  */
      KEYMIX(r0,r2,r3,r1,r4,88);
      S6(r0,r2,r3,r1,r4) 
      LINTRANS(r0,r2,r4,r3,r1);

      /* round 24  */
      KEYMIX(r0,r2,r4,r3,r1,92);
      S7(r0,r2,r4,r3,r1);
      LINTRANS(r4,r1,r3,r0,r2);

      /* round 25  */
      KEYMIX(r4,r1,r3,r0,r2,96);
      S0(r4,r1,r3,r0,r2);
      LINTRANS(r1,r2,r3,r4,r0);

      /* round 26  */
      KEYMIX(r1,r2,r3,r4,r0,100);
      S1(r1,r2,r3,r4,r0);
      LINTRANS(r4,r2,r3,r1,r0);

      /* round 27  */
      KEYMIX(r4,r2,r3,r1,r0,104);
      S2(r4,r2,r3,r1,r0);
      LINTRANS(r3,r1,r2,r0,r4);

      /* round 28  */
      KEYMIX(r3,r1,r2,r0,r4,108);
      S3(r3,r1,r2,r0,r4);
      LINTRANS(r1,r2,r0,r4,r3);

      /* round 29  */
      KEYMIX(r1,r2,r0,r4,r3,112);
      S4(r1,r2,r0,r4,r3) 
      LINTRANS(r2,r3,r1,r4,r0);

      /* round 30  */
      KEYMIX(r2,r3,r1,r4,r0,116);
      S5(r2,r3,r1,r4,r0);
      LINTRANS(r3,r4,r2,r1,r0);

      /* round 31  */
      KEYMIX(r3,r4,r2,r1,r0,120);
      S6(r3,r4,r2,r1,r0) 
      LINTRANS(r3,r4,r0,r2,r1);

      /* round 32  */
      KEYMIX(r3,r4,r0,r2,r1,124);
      S7(r3,r4,r0,r2,r1);
      KEYMIX(r0,r1,r2,r3,r4,128);

    
#ifdef  BLOCK_SWAP
    out_blk[3] = io_swap(r0); out_blk[2] = io_swap(r1); 
    out_blk[1] = io_swap(r2); out_blk[0] = io_swap(r3);
#else
    out_blk[0] = r0; out_blk[1] = r1; out_blk[2] = r2; out_blk[3] = r3;
#endif
    return 0;
};

/* decrypt a block of text  */

int serpent_decrypt(serpent_context *cx, const u8 *in,
		    u8 *out)
{   u32 *l_key = cx->keyinfo;
    const u32 *in_blk = (const u32 *)in;
    u32 *out_blk = (u32 *)out;
    u32  r0,r1,r2,r3,r4;
    
#ifdef  BLOCK_SWAP
    r0 = io_swap(in_blk[3]); r1 = io_swap(in_blk[2]); 
    r2 = io_swap(in_blk[1]); r3 = io_swap(in_blk[0]);
#else
    r0 = in_blk[0]; r1 = in_blk[1]; r2 = in_blk[2]; r3 = in_blk[3];
#endif

      /* round 1 */
      KEYMIX(r0,r1,r2,r3,r4,128);
      I7(r0,r1,r2,r3,r4);
      KEYMIX(r3,r0,r1,r4,r2,124);

      /* round 2  */
      ILINTRANS(r3,r0,r1,r4,r2);
      I6(r3,r0,r1,r4,r2);
      KEYMIX(r0,r1,r2,r4,r3,120);

      /* round 3  */
      ILINTRANS(r0,r1,r2,r4,r3);
      I5(r0,r1,r2,r4,r3);
      KEYMIX(r1,r3,r4,r2,r0,116);

      /* round 4  */
      ILINTRANS(r1,r3,r4,r2,r0);
      I4(r1,r3,r4,r2,r0);
      KEYMIX(r1,r2,r4,r0,r3,112);

      /* round 5  */
      ILINTRANS(r1,r2,r4,r0,r3);
      I3(r1,r2,r4,r0,r3);
      KEYMIX(r4,r2,r0,r1,r3,108);

      /* round 6  */
      ILINTRANS(r4,r2,r0,r1,r3);
      I2(r4,r2,r0,r1,r3);
      KEYMIX(r2,r3,r0,r1,r4,104);

      /* round 7  */
      ILINTRANS(r2,r3,r0,r1,r4);
      I1(r2,r3,r0,r1,r4);
      KEYMIX(r4,r2,r1,r0,r3,100);

      /* round 8  */
      ILINTRANS(r4,r2,r1,r0,r3);
      I0(r4,r2,r1,r0,r3);
      KEYMIX(r4,r3,r2,r0,r1,96);

      /* round 9  */
      ILINTRANS(r4,r3,r2,r0,r1);
      I7(r4,r3,r2,r0,r1);
      KEYMIX(r0,r4,r3,r1,r2,92);

      /* round 10  */
      ILINTRANS(r0,r4,r3,r1,r2);
      I6(r0,r4,r3,r1,r2);
      KEYMIX(r4,r3,r2,r1,r0,88);

      /* round 11  */
      ILINTRANS(r4,r3,r2,r1,r0);
      I5(r4,r3,r2,r1,r0);
      KEYMIX(r3,r0,r1,r2,r4,84);

      /* round 12  */
      ILINTRANS(r3,r0,r1,r2,r4);
      I4(r3,r0,r1,r2,r4);
      KEYMIX(r3,r2,r1,r4,r0,80);

      /* round 13  */
      ILINTRANS(r3,r2,r1,r4,r0);
      I3(r3,r2,r1,r4,r0);
      KEYMIX(r1,r2,r4,r3,r0,76);

      /* round 14  */
      ILINTRANS(r1,r2,r4,r3,r0);
      I2(r1,r2,r4,r3,r0);
      KEYMIX(r2,r0,r4,r3,r1,72);

      /* round 15  */
      ILINTRANS(r2,r0,r4,r3,r1);
      I1(r2,r0,r4,r3,r1);
      KEYMIX(r1,r2,r3,r4,r0,68);

      /* round 16  */
      ILINTRANS(r1,r2,r3,r4,r0);
      I0(r1,r2,r3,r4,r0);
      KEYMIX(r1,r0,r2,r4,r3,64);

      /* round 17  */
      ILINTRANS(r1,r0,r2,r4,r3);
      I7(r1,r0,r2,r4,r3);
      KEYMIX(r4,r1,r0,r3,r2,60);

      /* round 18  */
      ILINTRANS(r4,r1,r0,r3,r2);
      I6(r4,r1,r0,r3,r2);
      KEYMIX(r1,r0,r2,r3,r4,56);

      /* round 19  */
      ILINTRANS(r1,r0,r2,r3,r4);
      I5(r1,r0,r2,r3,r4);
      KEYMIX(r0,r4,r3,r2,r1,52);

      /* round 20  */
      ILINTRANS(r0,r4,r3,r2,r1);
      I4(r0,r4,r3,r2,r1);
      KEYMIX(r0,r2,r3,r1,r4,48);

      /* round 21  */
      ILINTRANS(r0,r2,r3,r1,r4);
      I3(r0,r2,r3,r1,r4);
      KEYMIX(r3,r2,r1,r0,r4,44);

      /* round 22  */
      ILINTRANS(r3,r2,r1,r0,r4);
      I2(r3,r2,r1,r0,r4);
      KEYMIX(r2,r4,r1,r0,r3,40);

      /* round 23  */
      ILINTRANS(r2,r4,r1,r0,r3);
      I1(r2,r4,r1,r0,r3);
      KEYMIX(r3,r2,r0,r1,r4,36);

      /* round 24  */
      ILINTRANS(r3,r2,r0,r1,r4);
      I0(r3,r2,r0,r1,r4);
      KEYMIX(r3,r4,r2,r1,r0,32);

      /* round 25  */
      ILINTRANS(r3,r4,r2,r1,r0);
      I7(r3,r4,r2,r1,r0);
      KEYMIX(r1,r3,r4,r0,r2,28);

      /* round 26  */
      ILINTRANS(r1,r3,r4,r0,r2);
      I6(r1,r3,r4,r0,r2);
      KEYMIX(r3,r4,r2,r0,r1,24);

      /* round 27  */
      ILINTRANS(r3,r4,r2,r0,r1);
      I5(r3,r4,r2,r0,r1);
      KEYMIX(r4,r1,r0,r2,r3,20);

      /* round 28  */
      ILINTRANS(r4,r1,r0,r2,r3);
      I4(r4,r1,r0,r2,r3);
      KEYMIX(r4,r2,r0,r3,r1,16);

      /* round 29  */
      ILINTRANS(r4,r2,r0,r3,r1);
      I3(r4,r2,r0,r3,r1);
      KEYMIX(r0,r2,r3,r4,r1,12);

      /* round 30  */
      ILINTRANS(r0,r2,r3,r4,r1);
      I2(r0,r2,r3,r4,r1);
      KEYMIX(r2,r1,r3,r4,r0,8);

      /* round 31  */
      ILINTRANS(r2,r1,r3,r4,r0);
      I1(r2,r1,r3,r4,r0);
      KEYMIX(r0,r2,r4,r3,r1,4);

      /* round 32  */
      ILINTRANS(r0,r2,r4,r3,r1);
      I0(r0,r2,r4,r3,r1);
      KEYMIX(r0,r1,r2,r3,r4,0);
    
#ifdef  BLOCK_SWAP
    out_blk[3] = io_swap(r0); out_blk[2] = io_swap(r1); 
    out_blk[1] = io_swap(r2); out_blk[0] = io_swap(r3);
#else
    out_blk[0] = r0; out_blk[1] = r1; out_blk[2] = r2; out_blk[3] = r3;
#endif
    return 0;
};


