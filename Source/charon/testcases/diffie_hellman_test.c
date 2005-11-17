/**
 * @file diffie_hellman_test.c
 * 
 * @brief Tests to test the Diffie Hellman object diffie_hellman_t
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

#include "../globals.h"
#include "../utils/logger_manager.h"
#include "../utils/allocator.h"

/* 
 * described in Header-File
 */
void test_diffie_hellman(tester_t *tester)
{
	diffie_hellman_t *diffie_hellman;
	logger_t *logger;
	chunk_t public_value;

	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"Diffie Hellman");


	diffie_hellman = diffie_hellman_create(5);
	tester->assert_true(tester,(diffie_hellman != NULL), "create call check");	
	

	
	tester->assert_true(tester,(	diffie_hellman->get_my_public_value(diffie_hellman,&public_value) == SUCCESS), "get_my_public_value call check");

	logger->log_chunk(logger,RAW,"Public value",&public_value);

	allocator_free(public_value.ptr);
		
	tester->assert_true(tester,(diffie_hellman->destroy(diffie_hellman) == SUCCESS), "destroy call check");
	global_logger_manager->destroy_logger(global_logger_manager,logger);
}
