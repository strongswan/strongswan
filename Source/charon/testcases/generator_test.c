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
#include "../payloads/transform_attribute.h"
#include "../payloads/transform_substructure.h"

/*
 * Described in Header 
 */
void test_generator_with_header_payload(tester_t *tester)
{
	generator_t *generator;
	ike_header_t *header_data;
	chunk_t generated_data;
	status_t status;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"header payload");
	
	header_data = ike_header_create();
	
	header_data->initiator_spi = 1;
	header_data->responder_spi = 2;
	header_data->next_payload = 3;
	header_data->maj_version = 4;
	header_data->min_version = 5;
	header_data->exchange_type = 6;
	header_data->flags.initiator = TRUE;
	header_data->flags.version = FALSE;
	header_data->flags.response = TRUE;
	header_data->message_id = 7;
	header_data->length = 8;
	
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	status = generator->generate_payload(generator,(payload_t *) header_data);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");

	tester->assert_true(tester,(generator->write_to_chunk(generator,&generated_data) == SUCCESS),"write_to_chunk call check");

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
	
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
	
	header_data->initiator_spi = 0x22000054231234;
	header_data->responder_spi = 0x122398;
	header_data->next_payload = 0xF3;
	header_data->maj_version = 0x2;
	header_data->min_version = 0x0;
	header_data->exchange_type = 0x12;
	header_data->flags.initiator = TRUE;
	header_data->flags.version = TRUE;
	header_data->flags.response = TRUE;
	header_data->message_id = 0x33AFF3;
	header_data->length = 0xAA11F;
	
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	status = generator->generate_payload(generator,(payload_t *)header_data);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");
	
	tester->assert_true(tester,(generator->write_to_chunk(generator,&generated_data) == SUCCESS),"write_to_chunk call check");

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

	header_data->destroy(header_data);
	
	global_logger_manager->destroy_logger(global_logger_manager,logger);
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
}

/*
 * Described in header
 */ 
void test_generator_with_transform_attribute(tester_t *tester)
{
	generator_t *generator;
	transform_attribute_t *attribute;
	status_t status;
	chunk_t generated_data;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"transform_attribute payload");
	
	
	/* test empty attribute */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	attribute = transform_attribute_create();
	status = generator->generate_payload(generator,(payload_t *)attribute);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");
	tester->assert_true(tester,(generator->write_to_chunk(generator,&generated_data) == SUCCESS),"write_to_chunk call check");
	logger->log_chunk(logger,RAW,"generated attribute",&generated_data);	

	u_int8_t expected_generation[] = {
		0x80,0x00,0x00,0x00,
	};
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");
	allocator_free_chunk(generated_data);
	tester->assert_true(tester,(attribute->destroy(attribute) == SUCCESS), "attribute destroy call check");
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
	
	/* test attribute with 2 byte data */	
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	attribute = transform_attribute_create();
	u_int16_t dataval = 5768;
	chunk_t data;
	data.ptr = (void *) &dataval;
	data.len = 2;
		
	attribute->set_value(attribute,data);
	
	status = generator->generate_payload(generator,(payload_t *)attribute);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");
	tester->assert_true(tester,(generator->write_to_chunk(generator,&generated_data) == SUCCESS),"write_to_chunk call check");
	logger->log_chunk(logger,RAW,"generated attribute",&generated_data);	

	u_int8_t expected_generation2[] = {
		0x80,0x00,0x88,0x16,
	};
	tester->assert_true(tester,(memcmp(expected_generation2,generated_data.ptr,sizeof(expected_generation2)) == 0), "compare generated data");

	allocator_free_chunk(generated_data);
	tester->assert_true(tester,(attribute->destroy(attribute) == SUCCESS), "attribute destroy call check");
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");



	/* test attribute with 25 byte data */
		generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	attribute = transform_attribute_create();
	char *stringval = "ddddddddddeeeeeeeeeefffff";
	data.ptr = (void *) stringval;
	data.len = 25;
		
	status = attribute->set_value(attribute,data);
	tester->assert_true(tester,(status == SUCCESS),"set_value call check");
	
	status = attribute->set_attribute_type(attribute,456);
	tester->assert_true(tester,(status == SUCCESS),"set_attribute_type call check");


	status = generator->generate_payload(generator,(payload_t *)attribute);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");
	tester->assert_true(tester,(generator->write_to_chunk(generator,&generated_data) == SUCCESS),"write_to_chunk call check");
	logger->log_chunk(logger,RAW,"generated attribute",&generated_data);	

	u_int8_t expected_generation3[] = {
		0x01,0xC8,0x00,0x19,
		0x64,0x64,0x64,0x64,
		0x64,0x64,0x64,0x64,
		0x64,0x64,0x65,0x65,
		0x65,0x65,0x65,0x65,
		0x65,0x65,0x65,0x65,
		0x66,0x66,0x66,0x66,
		0x66
	};
	tester->assert_true(tester,(memcmp(expected_generation3,generated_data.ptr,sizeof(expected_generation3)) == 0), "compare generated data");

	allocator_free_chunk(generated_data);
	tester->assert_true(tester,(attribute->destroy(attribute) == SUCCESS), "attribute destroy call check");
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
		

	global_logger_manager->destroy_logger(global_logger_manager,logger);	
}



/*
 * Described in header
 */ 
void test_generator_with_transform_substructure(tester_t *tester)
{
	generator_t *generator;
	transform_attribute_t *attribute1, *attribute2;
	transform_substructure_t *transform;
	chunk_t data;
	status_t status;
	chunk_t generated_data;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"transform substr.");
	
	/* create generator */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");

	/* create attribute 1 */	
	attribute1 = transform_attribute_create();
	char *stringval = "abcd";
	data.ptr = (void *) stringval;
	data.len = 4;
	status = attribute1->set_value(attribute1,data);
	tester->assert_true(tester,(status == SUCCESS),"set_value call check");
	status = attribute1->set_attribute_type(attribute1,0);
	tester->assert_true(tester,(status == SUCCESS),"set_attribute_type call check");
	logger->log(logger,CONTROL,"attribute1 created");

	/* create attribute 2 */
	attribute2 = transform_attribute_create();
	stringval = "efgh";
	data.ptr = (void *) stringval;
	data.len = 4;
	status = attribute2->set_value(attribute2,data);
	tester->assert_true(tester,(status == SUCCESS),"set_value call check");
	status = attribute2->set_attribute_type(attribute2,0);
	tester->assert_true(tester,(status == SUCCESS),"set_attribute_type call check");
	logger->log(logger,CONTROL,"attribute2 created");

	/* create transform */
	transform = transform_substructure_create();
	tester->assert_true(tester,(transform != NULL), "transform create check");
	status = transform->add_transform_attribute(transform,attribute1);
	tester->assert_true(tester,(status == SUCCESS),"add_transform_attribute call check");
	status = transform->add_transform_attribute(transform,attribute2);
	tester->assert_true(tester,(status == SUCCESS),"add_transform_attribute call check");
	status = transform->set_transform_type(transform,5); /* hex 5 */
	tester->assert_true(tester,(status == SUCCESS),"set_transform_type call check");
	status = transform->set_transform_id(transform,65000); /* hex FDE8 */
	tester->assert_true(tester,(status == SUCCESS),"set_transform_id call check");
	
	
	logger->log(logger,CONTROL,"transform created");

	status = generator->generate_payload(generator,(payload_t *)transform);
	tester->assert_true(tester,(status == SUCCESS),"generate_payload call check");
	tester->assert_true(tester,(generator->write_to_chunk(generator,&generated_data) == SUCCESS),"write_to_chunk call check");
	logger->log_chunk(logger,RAW,"generated transform",&generated_data);	

	u_int8_t expected_generation3[] = {
		0x00,0x00,0x00,0x18,
		0x05,0x00,0xFD,0xE8,
		0x00,0x00,0x00,0x04,
		0x61,0x62,0x63,0x64,
		0x00,0x00,0x00,0x04,
		0x65,0x66,0x67,0x68,
	};
	tester->assert_true(tester,(memcmp(expected_generation3,generated_data.ptr,sizeof(expected_generation3)) == 0), "compare generated data");

	allocator_free_chunk(generated_data);
	tester->assert_true(tester,(transform->destroy(transform) == SUCCESS), "transform destroy call check");
	tester->assert_true(tester,(generator->destroy(generator) == SUCCESS), "generator destroy call check");
	
	
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
}
