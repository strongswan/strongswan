/**
 * @file encryption_payload_test.c
 * 
 * @brief Tests for the encryption_payload_t class.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "encryption_payload_test.h"

#include <daemon.h>
#include <utils/logger_manager.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <encoding/payloads/encryption_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>

/* 
 * described in Header-File
 */
void test_encryption_payload(protected_tester_t *tester)
{
	encryption_payload_t *encryption_payload;
	nonce_payload_t *nonce_payload; 
	crypter_t *crypter;
	signer_t *signer;
	chunk_t nonce, got_nonce;
	chunk_t data;
	chunk_t key;
	generator_t *generator;
	parser_t *parser;
	status_t status;
	logger_t *logger;
	iterator_t *iterator;
	
	
	u_int8_t key_bytes[]  = {
		0x01,0x01,0x01,0x01,
		0x01,0x01,0x01,0x01,
		0x01,0x01,0x01,0x01,
		0x01,0x01,0x01,0x01
	};
	key.ptr = key_bytes;
	key.len = sizeof(key_bytes);
	
	logger = logger_manager->get_logger(logger_manager, TESTER);
	
	nonce.ptr = "test text und so...";
	nonce.len = strlen(nonce.ptr) + 1;
	
	logger->log_chunk(logger, RAW, "nonce", nonce);
	
	encryption_payload = encryption_payload_create();
	nonce_payload = nonce_payload_create();
	nonce_payload->set_nonce(nonce_payload, nonce);
	
	encryption_payload->add_payload(encryption_payload, (payload_t*)nonce_payload);
	signer = signer_create(AUTH_HMAC_SHA1_96);
	crypter = crypter_create(ENCR_AES_CBC, 16);
	
	signer->set_key(signer, key);
	crypter->set_key(crypter, key);
	
	
	
	/* generating */
		
	encryption_payload->set_transforms(encryption_payload, crypter, signer);
	
	logger->log(logger, RAW, "encrypt");
	status = encryption_payload->encrypt(encryption_payload);
	tester->assert_true(tester, (status == SUCCESS), "encryption");
	
	generator = generator_create();
	generator->generate_payload(generator, (payload_t*)encryption_payload);
	
	generator->write_to_chunk(generator, &data);
	logger->log_chunk(logger, RAW, "generated data", data);
	
	encryption_payload->build_signature(encryption_payload, data);
	logger->log_chunk(logger, RAW, "generated data", data);
	
	encryption_payload->destroy(encryption_payload);
	
	
	/* parsing */
	
	parser = parser_create(data);
	status = parser->parse_payload(parser, ENCRYPTED, (payload_t**)&encryption_payload);
	tester->assert_true(tester, (status == SUCCESS), "parsing");
	
	encryption_payload->set_transforms(encryption_payload, crypter, signer);
	status = encryption_payload->verify_signature(encryption_payload, data);
	tester->assert_true(tester, (status == SUCCESS), "signature verification");
	
	status = encryption_payload->decrypt(encryption_payload);
	tester->assert_true(tester, (status == SUCCESS), "decryption");
	
	
	iterator = encryption_payload->create_payload_iterator(encryption_payload, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&nonce_payload);
		got_nonce = nonce_payload->get_nonce(nonce_payload);
	}
	iterator->destroy(iterator);
	
	
	tester->assert_true(tester, (got_nonce.len == nonce.len), "decrypted nonce");
	tester->assert_false(tester, memcmp(nonce.ptr, got_nonce.ptr, nonce.len), "decrypted nonce");
	
	logger->log_chunk(logger, RAW, "nonce", got_nonce);
	
	free(data.ptr);
	free(got_nonce.ptr);
	encryption_payload->destroy(encryption_payload);
	crypter->destroy(crypter);
	signer->destroy(signer);
	generator->destroy(generator);
	parser->destroy(parser);
}
