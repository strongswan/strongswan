/**
 * @file generator.h
 * 
 * @brief Tests to test the Generator class generator_t
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
 
#include "generator_test.h"
#include "../tester.h"
#include "../encodings.h"
#include "../generator.h"

extern payload_info_t *payload_infos[];

void test_generator_with_unsupported_payload(tester_t *tester)
{
	generator_t *generator;
	void * data_struct;
	chunk_t generated_data;
	
	generator = generator_create(payload_infos);
	tester->assert_true(tester,(generator != NULL), "generator create check");
	tester->assert_true(tester,(generator->generate_payload(generator,(payload_type_t) -1,data_struct,&generated_data) == NOT_SUPPORTED),"generate_payload call check");
	
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
}
