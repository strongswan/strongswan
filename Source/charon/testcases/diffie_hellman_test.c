/**
 * @file diffie_hellman_test.c
 * 
 * @brief Tests for the diffie_hellman_t class.
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
 
#include "diffie_hellman_test.h"

#include "../transforms/diffie_hellman.h"

#include <daemon.h>
#include <utils/logger_manager.h>
#include <utils/allocator.h>
#include <encoding/payloads/transform_substructure.h>

/* 
 * described in Header-File
 */
void test_diffie_hellman(tester_t *tester)
{
	diffie_hellman_t *my_diffie_hellman, *other_diffie_hellman;
	logger_t *logger;
	chunk_t my_public_value, other_public_value;
	chunk_t my_secret, other_secret;

	logger = charon->logger_manager->create_logger(charon->logger_manager,TESTER,"Diffie Hellman");


	my_diffie_hellman = diffie_hellman_create(MODP_1024_BIT);
	tester->assert_true(tester,(my_diffie_hellman != NULL), "create call check");	
	
	other_diffie_hellman = diffie_hellman_create(MODP_1024_BIT);
	tester->assert_true(tester,(other_diffie_hellman != NULL), "create call check");	

	my_diffie_hellman->get_my_public_value(my_diffie_hellman,&my_public_value);
	logger->log_chunk(logger,RAW,"My public value",&my_public_value);

	other_diffie_hellman->get_my_public_value(other_diffie_hellman,&other_public_value);
	logger->log_chunk(logger,RAW,"Other public value",&other_public_value);

	my_diffie_hellman->set_other_public_value(my_diffie_hellman,other_public_value);
	other_diffie_hellman->set_other_public_value(other_diffie_hellman,my_public_value);

	allocator_free(my_public_value.ptr);
	allocator_free(other_public_value.ptr);
	
	tester->assert_true(tester,(	my_diffie_hellman->get_shared_secret(my_diffie_hellman,&my_secret) == SUCCESS), "get_shared_secret call check");
	logger->log_chunk(logger,RAW,"My shared secret",&my_secret);

	tester->assert_true(tester,(	other_diffie_hellman->get_shared_secret(other_diffie_hellman,&other_secret) == SUCCESS), "get_shared_secret call check");
	logger->log_chunk(logger,RAW,"Other shared secret",&other_secret);
	
	tester->assert_true(tester,(	memcmp(my_secret.ptr,other_secret.ptr,other_secret.len) == 0), "shared secret same value check");
	
	allocator_free(my_secret.ptr);
	allocator_free(other_secret.ptr);	
		
	my_diffie_hellman->destroy(my_diffie_hellman);
	other_diffie_hellman->destroy(other_diffie_hellman);
	charon->logger_manager->destroy_logger(charon->logger_manager,logger);
}
