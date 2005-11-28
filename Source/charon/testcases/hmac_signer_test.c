/**
 * @file hmac_signer_test.c
 * 
 * @brief Tests the hmac SHA1 and MD5 signer class hmac_signer_t 
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
 
#include "hmac_signer_test.h"

#include <transforms/signers/signer.h>
#include <utils/allocator.h>
#include <globals.h>


/*
 * Described in header.
 */
void test_hmac_md5_signer(tester_t *tester)
{
	/* Test cases from RFC2202
	 * 
	 * test_case =     5
	 * key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
	 * key_len =       16
	 * data =          "Test With Truncation"
	 * data_len =      20
	 * digest =        0x56461ef2342edc00f9bab995690efd4c
	 * digest-96       0x56461ef2342edc00f9bab995
	 * 
	 * currently only this test 5 gets performed!
	 */
	chunk_t keys[4];
	chunk_t data[4];
	chunk_t signature[4];
	chunk_t reference[4];
	chunk_t wrong_reference[4];
	int i;
 	logger_t *logger;
 	bool valid;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"HMAC MD5 96");
	
	signer_t *signer = (signer_t *)	signer_create(AUTH_HMAC_MD5_96);
	tester->assert_true(tester, (signer != NULL), "signer create call check");
	
	
		/*
	 * values for test 5
	 */
	u_int8_t key1[] = {
		0x0c,0x0c,0x0c,0x0c,
		0x0c,0x0c,0x0c,0x0c,
		0x0c,0x0c,0x0c,0x0c,
		0x0c,0x0c,0x0c,0x0c,
	};
	keys[0].ptr = key1;
	keys[0].len = sizeof(key1);
	data[0].ptr = "Test With Truncation";
	data[0].len = 20; 
	u_int8_t reference1[] = {
		0x56,0x46,0x1e,0xf2,0x34,0x2e,
		0xdc,0x00,0xf9,0xba,0xb9,0x95
	};
	reference[0].ptr = reference1;
	reference[0].len = sizeof(reference1);

	u_int8_t wrong_reference1[] = {
		0x56,0x46,0x1e,0xa2,0x34,0x2e,
		0xdc,0x00,0xf9,0xba,0xb9,0x95
	};

	wrong_reference[0].ptr = wrong_reference1;
	wrong_reference[0].len = sizeof(wrong_reference1);
	
	for (i=0; i<1; i++)
 	{
	 	signer->set_key(signer, keys[i]);
		signer->allocate_signature(signer, data[i], &signature[i]);
		tester->assert_true(tester, signature[i].len == 12, "chunk len");
		tester->assert_true(tester, (memcmp(signature[i].ptr, reference[i].ptr, 12) == 0), "hmac value");
		logger->log_chunk(logger,RAW,"expected signature:",&reference[i]);
		logger->log_chunk(logger,RAW,"signature:",&signature[i]);
		allocator_free(signature[i].ptr);
		signer->verify_signature(signer, data[i],reference[i], &valid);
		tester->assert_true(tester, (valid == TRUE), "Signature valid check");

		signer->verify_signature(signer, data[i],wrong_reference[i], &valid);
		tester->assert_true(tester, (valid == FALSE), "Signature not valid check");
 	}
	
	

	signer->destroy(signer);	
	global_logger_manager->destroy_logger(global_logger_manager,logger);
}


/*
 * Described in header.
 */
void test_hmac_sha1_signer(tester_t *tester)
{
	/*
	 * test_case =     7
	 * key =           0xaa repeated 80 times
	 * key_len =       80
	 * data =          "Test Using Larger Than Block-Size Key and Larger
	 *                 Than One Block-Size Data"
	 * data_len =      73
	 * digest =        0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
	 * digest-96 =     0x4c1a03424b55e07fe7f27be1
	 */
	
	chunk_t keys[4];
	chunk_t data[4];
	chunk_t signature[4];
	chunk_t reference[4];
	chunk_t wrong_reference[4];
	int i;
 	logger_t *logger;
 	bool valid;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"HMAC SHA1 96");
	
	signer_t *signer = (signer_t *)	signer_create(AUTH_HMAC_SHA1_96);
	tester->assert_true(tester, (signer != NULL), "signer create call check");
	
	
		/*
	 * values for test 5
	 */
	u_int8_t key1[] = {
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
		0xaa,0xaa,0xaa,0xaa,
	};
	keys[0].ptr = key1;
	keys[0].len = sizeof(key1);
	data[0].ptr = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
	data[0].len = 73; 
	u_int8_t reference1[] = {
		0xe8,0xe9,0x9d,0x0f,0x45,0x23,
		0x7d,0x78,0x6d,0x6b,0xba,0xa7
	};
	reference[0].ptr = reference1;
	reference[0].len = sizeof(reference1);

	u_int8_t wrong_reference1[] = {
		0xe8,0xe9,0x9d,0x0f,0x46,0x23,
		0x7d,0x71,0x6d,0x6b,0xba,0xa7
	};

	wrong_reference[0].ptr = wrong_reference1;
	wrong_reference[0].len = sizeof(wrong_reference1);
	
	for (i=0; i<1; i++)
 	{
	 	signer->set_key(signer, keys[i]);
		signer->allocate_signature(signer, data[i], &signature[i]);
		tester->assert_true(tester, signature[i].len == 12, "chunk len");
		tester->assert_true(tester, (memcmp(signature[i].ptr, reference[i].ptr, 12) == 0), "hmac value");
		logger->log_chunk(logger,RAW,"expected signature:",&reference[i]);
		logger->log_chunk(logger,RAW,"signature:",&signature[i]);
		allocator_free(signature[i].ptr);
		signer->verify_signature(signer, data[i],reference[i], &valid);
		tester->assert_true(tester, (valid == TRUE), "Signature valid check");

		signer->verify_signature(signer, data[i],wrong_reference[i], &valid);
		tester->assert_true(tester, (valid == FALSE), "Signature not valid check");
 	}
	
	signer->destroy(signer);
	global_logger_manager->destroy_logger(global_logger_manager,logger);

}
