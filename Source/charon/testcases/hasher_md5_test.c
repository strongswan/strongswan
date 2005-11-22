/**
 * @file hasher_md5_test.h
 * 
 * @brief Tests the md5 hasher 
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
 
#include "hasher_md5_test.h"

#include "../utils/allocator.h"


/* 
 * described in Header-File
 */
void test_hasher_md5(tester_t *tester)
{
	/*
	 * Test vectors from RFC1321:
	 * MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
	 * MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
	 * MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
	 * MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
	 * MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
	 * 
	 * currently testing "", "abc", "abcdefghijklmnopqrstuvwxyz"
	 */	
	hasher_t *hasher = hasher_create(HASH_MD5);
	u_int8_t hash_buffer[16];
	chunk_t empty, abc, abcd, hash_chunk;
	
	u_int8_t hash_empty[] = {
		0xd4,0x1d,0x8c,0xd9,
		0x8f,0x00,0xb2,0x04,
		0xe9,0x80,0x09,0x98,
		0xec,0xf8,0x42,0x7e
	};
		
	u_int8_t hash_abc[] = {
		0x90,0x01,0x50,0x98,
		0x3c,0xd2,0x4f,0xb0,
		0xd6,0x96,0x3f,0x7d,
		0x28,0xe1,0x7f,0x72
	};
		
	u_int8_t hash_abcd[] = {
		0xc3,0xfc,0xd3,0xd7,
		0x61,0x92,0xe4,0x00,
		0x7d,0xfb,0x49,0x6c,
		0xca,0x67,0xe1,0x3b
	};

	empty.ptr = "";
	empty.len = 0;
	abc.ptr = "abc";
	abc.len = 3;
	abcd.ptr = "abcdefghijklmnopqrstuvwxyz";
	abcd.len = strlen(abcd.ptr);
	
	tester->assert_true(tester, hasher->get_block_size(hasher) == 16, "block size");
	
	/* simple hashing, using empty */
	hasher->get_hash(hasher, empty, hash_buffer);
	tester->assert_false(tester, memcmp(hash_buffer, hash_empty, 16), "hash for empty");
	
	/* simple hashing, using "abc" */
	hasher->get_hash(hasher, abc, hash_buffer);
	tester->assert_false(tester, memcmp(hash_buffer, hash_abc, 16), "hash for abc");
	
	/* with allocation, using "abcdb..." */
	hasher->reset(hasher);
	hasher->allocate_hash(hasher, abcd, &hash_chunk);
	tester->assert_true(tester, hash_chunk.len == 16, "hash len");
	tester->assert_false(tester, memcmp(hash_chunk.ptr, hash_abcd, hash_chunk.len), "hash for abcd...");
	allocator_free(hash_chunk.ptr);
}
