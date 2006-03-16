/**
 * @file rsa_test.h
 * 
 * @brief Tests for the hasher_t classes.
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
 
#include "rsa_test.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <utils/logger.h>


/* 
 * described in Header-File
 */
void test_rsa(protected_tester_t *tester)
{
	rsa_private_key_t *private_key;
	rsa_public_key_t *public_key;
	chunk_t data, signature, private_key_chunk, public_key_chunk;
	logger_t *logger;
	status_t status;
	u_int8_t test_data[] = {
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
		0x01,0x02,0x03,0x04,
	};
	data.ptr = test_data;
	data.len = sizeof(test_data);
	
	logger = charon->logger_manager->create_logger(charon->logger_manager, TESTER, NULL);
	logger->disable_level(logger, FULL);
	
	private_key = rsa_private_key_create();
	
	private_key->generate_key(private_key, 512);
	
	status = private_key->build_emsa_pkcs1_signature(private_key, HASH_MD5, data, &signature);
	tester->assert_true(tester, status == SUCCESS, "build emsa_pkcs1_signature");
	
	public_key = private_key->get_public_key(private_key);
	
	status = public_key->verify_emsa_pkcs1_signature(public_key, data, signature);
	tester->assert_true(tester, status == SUCCESS, "verify emsa_pkcs1_signature");
	
	public_key->get_key(public_key, &public_key_chunk);
	private_key->get_key(private_key, &private_key_chunk);
	
	logger->log_chunk(logger, RAW, "Public Key", public_key_chunk);
	logger->log_chunk(logger, RAW, "Private Key", private_key_chunk);
	
	
	allocator_free(public_key_chunk.ptr);
	allocator_free(private_key_chunk.ptr);
	allocator_free(signature.ptr);
	
	private_key->destroy(private_key);
	public_key->destroy(public_key);
	
}
