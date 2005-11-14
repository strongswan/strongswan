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
 
#include <string.h>

#include "generator_test.h"

#include "../globals.h"
#include "../generator.h"
#include "../utils/allocator.h"
#include "../utils/logger_manager.h"
#include "../utils/logger.h"
#include "../payloads/encodings.h"
#include "../payloads/ike_header.h"

extern payload_info_t *payload_infos[];

/*
 * Described in Header 
 */
void test_generator_with_unsupported_payload(tester_t *tester)
{
	generator_t *generator;
	generator_context_t *generator_context;
	void * data_struct;
	
	generator = generator_create(payload_infos);
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	generator_context = generator->create_context(generator);
	
	tester->assert_true(tester,(generator->generate_payload(generator,(payload_type_t) -1,data_struct,generator_context) == NOT_SUPPORTED),"generate_payload call check");

	generator_context->destroy(generator_context);
		
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
}

/*
 * Described in Header 
 */
void test_generator_with_header_payload(tester_t *tester)
{
	generator_t *generator;
	generator_context_t *generator_context;
	ike_header_t header_data;
	chunk_t generated_data;
	status_t status;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"header payload");
	
	header_data.initiator_spi = 1;
	header_data.responder_spi = 2;
	header_data.next_payload = 3;
	header_data.maj_version = 4;
	header_data.min_version = 5;
	header_data.exchange_type = 6;
	header_data.flags.initiator = TRUE;
	header_data.flags.version = FALSE;
	header_data.flags.response = TRUE;
	header_data.message_id = 7;
	header_data.length = 8;
	
	generator = generator_create(payload_infos);
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	generator_context = generator->create_context(generator);
	tester->assert_true(tester,(generator_context != NULL), "generator_context create check");

	status = generator->generate_payload(generator,HEADER,&header_data,generator_context);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");

	tester->assert_true(tester,(generator->write_to_chunk(generator,generator_context,&generated_data) == SUCCESS),"write_to_chunk call check");

	u_int8_t expected_generation[] = {
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x01,
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x02,
		0x03,0x45,0x06,0x28,
		0x00,0x00,0x00,0x07,
		0x00,0x00,0x00,0x08,
	};


	tester->assert_true(tester,(generated_data.len == sizeof(expected_generation)), "compare generated data length");
	logger->log_chunk(logger,RAW,"generated header",&generated_data);		
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data 1");
	allocator_free_chunk(generated_data);
	generator_context->destroy(generator_context);
	
	
	header_data.initiator_spi = 0x22000054231234;
	header_data.responder_spi = 0x122398;
	header_data.next_payload = 0xF3;
	header_data.maj_version = 0x2;
	header_data.min_version = 0x0;
	header_data.exchange_type = 0x12;
	header_data.flags.initiator = TRUE;
	header_data.flags.version = TRUE;
	header_data.flags.response = TRUE;
	header_data.message_id = 0x33AFF3;
	header_data.length = 0xAA11F;
	
	generator_context = generator->create_context(generator);
	
	status = generator->generate_payload(generator,HEADER,&header_data,generator_context);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");
	
	tester->assert_true(tester,(generator->write_to_chunk(generator,generator_context,&generated_data) == SUCCESS),"write_to_chunk call check");

	u_int8_t expected_generation2[] = {
		0x00,0x22,0x00,0x00,
		0x54,0x23,0x12,0x34,
		0x00,0x00,0x00,0x00,
		0x00,0x12,0x23,0x98,
		0xF3,0x20,0x12,0x38,
		0x00,0x33,0xAF,0xF3,
		0x00,0x0A,0xA1,0x1F,
	};
	
	logger->log_chunk(logger,RAW,"generated header",&generated_data);

	tester->assert_true(tester,(memcmp(expected_generation2,generated_data.ptr,sizeof(expected_generation2)) == 0), "compare generated data 2");
	allocator_free_chunk(generated_data);
	
	generator_context->destroy(generator_context);
	global_logger_manager->destroy_logger(global_logger_manager,logger);
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
}
