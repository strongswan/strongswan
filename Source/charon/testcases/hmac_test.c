/**
 * @file hmac_test.h
 * 
 * @brief Tests the hmac class 
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 */

#include <string.h>
 
#include "hmac_test.h"

#include "../transforms/hmac.h"
#include "../utils/allocator.h"


/* 
 * described in Header-File
 */
void test_hmac_sha1(tester_t *tester)
{
	/*
	 * Test cases from RFC2202
	 * 
	 * test_case =     1
	 * key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
	 * key_len =       20
	 * data =          "Hi There"
	 * data_len =      8
	 * digest =        0xb617318655057264e28bc0b6fb378c8ef146be00
	 * 
	 * test_case =     2
	 * key =           "Jefe"
	 * key_len =       4
	 * data =          "what do ya want for nothing?"
	 * data_len =      28
	 * digest =        0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
	 * 
	 * test_case =     3
	 * key =           0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	 * key_len =       20
	 * data =          0xdd repeated 50 times
	 * data_len =      50
	 * digest =        0x125d7342b9ac11cd91a39af48aa17b4f63f175d3
	 * 
	 * test_case =     4
	 * key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
	 * key_len =       25
	 * data =          0xcd repeated 50 times
	 * data_len =      50
	 * digest =        0x4c9007f4026250c6bc8414f9bf50c86c2d7235da
	 * 
	 * test_case =     5
	 * key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
	 * key_len =       20
	 * data =          "Test With Truncation"
	 * data_len =      20
	 * digest =        0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
	 * digest-96 =     0x4c1a03424b55e07fe7f27be1
	 * 
	 * test_case =     6
	 * key =           0xaa repeated 80 times
	 * key_len =       80
	 * data =          "Test Using Larger Than Block-Size Key - Hash Key First"
	 * data_len =      54
	 * digest =        0xaa4ae5e15272d00e95705637ce8a3b55ed402112
	 *  
	 * test_case =     7
	 * key =           0xaa repeated 80 times
	 * key_len =       80
	 * data =          "Test Using Larger Than Block-Size Key and Larger
	 *                 Than One Block-Size Data"
	 * data_len =      73
	 * digest =        0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
	 * 
	 * currently performing test 1, 2 and 7
	 */
	
	chunk_t keys[7];
	chunk_t data[7];
	chunk_t digest[7];
	chunk_t reference[7];
	int i;
	
	/*
	 * values for test 1
	 */
	u_int8_t key1[] = {
		0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b
	};
	keys[0].ptr = key1;
	keys[0].len = sizeof(key1);
	data[0].ptr = "Hi There";
	data[0].len = 8; 
	u_int8_t reference1[] = {
		0xb6,0x17,0x31,0x86,
		0x55,0x05,0x72,0x64,
		0xe2,0x8b,0xc0,0xb6,
		0xfb,0x37,0x8c,0x8e,
		0xf1,0x46,0xbe,0x00
	};
	reference[0].ptr = reference1;
	reference[0].len = sizeof(reference1);
	
	/*
	 * values for test 2
	 */
	u_int8_t reference2[] = {
		0xef,0xfc,0xdf,0x6a,
		0xe5,0xeb,0x2f,0xa2,
		0xd2,0x74,0x16,0xd5,
		0xf1,0x84,0xdf,0x9c,
		0x25,0x9a,0x7c,0x79
	};
	keys[1].ptr = "Jefe";
	keys[1].len = 4;
	data[1].ptr = "what do ya want for nothing?";
	data[1].len = 28; 
	reference[1].ptr = reference2;
	reference[1].len = sizeof(reference2);     
	
	/*
	 * values for test 7
	 */
	u_int8_t key7[] = {
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	};
	u_int8_t reference7[] = {
		0xe8,0xe9,0x9d,0x0f,
		0x45,0x23,0x7d,0x78,
		0x6d,0x6b,0xba,0xa7,
		0x96,0x5c,0x78,0x08,
		0xbb,0xff,0x1a,0x91
	};
	keys[2].ptr = key7;
	keys[2].len = sizeof(key7);
	data[2].ptr = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
	data[2].len = 73; 
	reference[2].ptr = reference7;
	reference[2].len = sizeof(reference7);
	
	
 	for (i=0; i<3; i++)
 	{
	 	hmac_t *hmac = hmac_create(HASH_SHA1, keys[i]);
		hmac->allocate_mac(hmac, data[i], &digest[i]);
		hmac->destroy(hmac);
		
		tester->assert_true(tester, digest[i].len == 20, "chunk len");
		tester->assert_false(tester, memcmp(digest[i].ptr, reference[i].ptr, 20), "hmac value");
		allocator_free(digest[i].ptr);
 	}
}
