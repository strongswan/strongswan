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

#include <globals.h>
#include <encoding/generator.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>
#include <utils/logger.h>
#include <encoding/payloads/encodings.h>
#include <encoding/payloads/ike_header.h>
#include <encoding/payloads/transform_attribute.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/proposal_substructure.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/nonce_payload.h>

/*
 * Described in Header 
 */
void test_generator_with_header_payload(tester_t *tester)
{
	generator_t *generator;
	ike_header_t *header_data;
	chunk_t generated_data;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"header payload");
	
	header_data = ike_header_create();
	header_data->set_initiator_spi(header_data,1);
	header_data->set_responder_spi(header_data,2);
	((payload_t *) header_data)->set_next_type((payload_t *) header_data, 3);
	header_data->set_exchange_type(header_data, 6);
	header_data->set_initiator_flag(header_data, TRUE);
	header_data->set_response_flag(header_data, TRUE);
	header_data->set_message_id(header_data,7);

	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	generator->generate_payload(generator,(payload_t *) header_data);

	generator->write_to_chunk(generator,&generated_data);

	u_int8_t expected_generation[] = {
		0x01,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,
		0x02,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,
		0x03,0x20,0x06,0x28,
		0x00,0x00,0x00,0x07,
		0x00,0x00,0x00,0x1C,
	};

	logger->log_bytes(logger,RAW,"expected header",expected_generation,sizeof(expected_generation));
	tester->assert_true(tester,(generated_data.len == sizeof(expected_generation)), "compare generated data length");
	logger->log_chunk(logger,RAW,"generated header",&generated_data);		
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data 1");
	allocator_free_chunk(&generated_data);
	
	generator->destroy(generator);

	header_data->set_initiator_spi(header_data,0x22000054231234LL);
	header_data->set_responder_spi(header_data,0x122398);
	((payload_t *) header_data)->set_next_type((payload_t *) header_data,0xF3);
	header_data->set_exchange_type(header_data, 0x12);
	header_data->set_initiator_flag(header_data, TRUE);
	header_data->set_response_flag(header_data, TRUE);
	header_data->set_message_id(header_data,0x33AFF3);

	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	generator->generate_payload(generator,(payload_t *)header_data);
	
	generator->write_to_chunk(generator,&generated_data);

	u_int8_t expected_generation2[] = {
		0x34,0x12,0x23,0x54,
		0x00,0x00,0x22,0x00,
		0x98,0x23,0x12,0x00,
		0x00,0x00,0x00,0x00,
		0xF3,0x20,0x12,0x28,
		0x00,0x33,0xAF,0xF3,
		0x00,0x00,0x00,0x1C,
	};

	
	logger->log_bytes(logger,RAW,"expected header",expected_generation2,sizeof(expected_generation2));
	
	logger->log_chunk(logger,RAW,"generated header",&generated_data);

	tester->assert_true(tester,(memcmp(expected_generation2,generated_data.ptr,sizeof(expected_generation2)) == 0), "compare generated data 2");
	allocator_free_chunk(&generated_data);

	header_data->destroy(header_data);
	
	global_logger_manager->destroy_logger(global_logger_manager,logger);
	generator->destroy(generator);
}

/*
 * Described in header
 */ 
void test_generator_with_transform_attribute(tester_t *tester)
{
	generator_t *generator;
	transform_attribute_t *attribute;
	chunk_t generated_data;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"transform_attribute payload");
	
	
	/* test empty attribute */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	attribute = transform_attribute_create();
	generator->generate_payload(generator,(payload_t *)attribute);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated attribute",&generated_data);	

	u_int8_t expected_generation[] = {
		0x80,0x00,0x00,0x00,
	};
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");
	allocator_free_chunk(&generated_data);
	attribute->destroy(attribute);
	generator->destroy(generator);
	
	/* test attribute with 2 byte data */	
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	attribute = transform_attribute_create();
	u_int16_t dataval = 5768;
	chunk_t data;
	data.ptr = (void *) &dataval;
	data.len = 2;
		
	attribute->set_value_chunk(attribute,data);
	
	generator->generate_payload(generator,(payload_t *)attribute);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated attribute",&generated_data);	

	u_int8_t expected_generation2[] = {
		0x80,0x00,0x16,0x88,
	};
	tester->assert_true(tester,(memcmp(expected_generation2,generated_data.ptr,sizeof(expected_generation2)) == 0), "compare generated data");

	allocator_free_chunk(&generated_data);
	attribute->destroy(attribute);
	generator->destroy(generator);



	/* test attribute with 25 byte data */
		generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	attribute = transform_attribute_create();
	char *stringval = "ddddddddddeeeeeeeeeefffff";
	data.ptr = (void *) stringval;
	data.len = 25;
		
	attribute->set_value_chunk(attribute,data);
	
	attribute->set_attribute_type(attribute,456);


	generator->generate_payload(generator,(payload_t *)attribute);
	generator->write_to_chunk(generator,&generated_data);
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

	allocator_free_chunk(&generated_data);
	attribute->destroy(attribute);
	generator->destroy(generator);
		

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
	attribute1->set_value_chunk(attribute1,data);
	attribute1->set_attribute_type(attribute1,0);
	logger->log(logger,CONTROL,"attribute1 created");

	/* create attribute 2 */
	attribute2 = transform_attribute_create();
	stringval = "efgh";
	data.ptr = (void *) stringval;
	data.len = 4;
	attribute2->set_value_chunk(attribute2,data);
	attribute2->set_attribute_type(attribute2,0);
	logger->log(logger,CONTROL,"attribute2 created");

	/* create transform */
	transform = transform_substructure_create();
	tester->assert_true(tester,(transform != NULL), "transform create check");
	transform->add_transform_attribute(transform,attribute1);
	transform->add_transform_attribute(transform,attribute2);
	transform->set_transform_type(transform,5); /* hex 5 */
	transform->set_transform_id(transform,65000); /* hex FDE8 */
	
	
	logger->log(logger,CONTROL,"transform created");

	generator->generate_payload(generator,(payload_t *)transform);
	generator->write_to_chunk(generator,&generated_data);
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

	allocator_free_chunk(&generated_data);
	transform->destroy(transform);
	generator->destroy(generator);
	
	
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
}


/*
 * Described in header
 */ 
void test_generator_with_proposal_substructure(tester_t *tester)
{
	generator_t *generator;
	transform_attribute_t *attribute1, *attribute2, *attribute3;
	transform_substructure_t *transform1, *transform2;
	proposal_substructure_t *proposal;
	chunk_t data;
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
	attribute1->set_value_chunk(attribute1,data);
	attribute1->set_attribute_type(attribute1,0);
	
	logger->log(logger,CONTROL,"attribute1 created");

	/* create attribute 2 */
	attribute2 = transform_attribute_create();
	stringval = "efgh";
	data.ptr = (void *) stringval;
	data.len = 4;
	attribute2->set_value_chunk(attribute2,data);
	attribute2->set_attribute_type(attribute2,0);
	logger->log(logger,CONTROL,"attribute2 created");

	/* create attribute 3 */
	attribute3 = transform_attribute_create();
	stringval = "ijkl";
	data.ptr = (void *) stringval;
	data.len = 4;
	attribute3->set_value_chunk(attribute3,data);
	attribute3->set_attribute_type(attribute3,0);
	logger->log(logger,CONTROL,"attribute3 created");

	/* create transform 1*/
	transform1 = transform_substructure_create();
	tester->assert_true(tester,(transform1 != NULL), "transform create check");
	transform1->add_transform_attribute(transform1,attribute1);
	transform1->add_transform_attribute(transform1,attribute2);
	transform1->set_transform_type(transform1,5); /* hex 5 */
	transform1->set_transform_id(transform1,65000); /* hex FDE8 */
	
	/* create transform 2*/
	transform2 = transform_substructure_create();
	tester->assert_true(tester,(transform2 != NULL), "transform create check");
	transform2->add_transform_attribute(transform2,attribute3);
	transform2->set_transform_type(transform2,3); /* hex 3 */
	transform2->set_transform_id(transform2,4); /* hex 4 */
		
	logger->log(logger,CONTROL,"transforms created");
	
	proposal = proposal_substructure_create();
	tester->assert_true(tester,(proposal != NULL), "proposal create check");
	
	stringval = "ABCDEFGH";
	data.ptr = (void *) stringval;
	data.len = 8;
	
	proposal->add_transform_substructure(proposal,transform1);
	proposal->add_transform_substructure(proposal,transform2);
	proposal->set_spi(proposal,data);
	proposal->set_proposal_number(proposal,7);
	proposal->set_protocol_id(proposal,4);	

	generator->generate_payload(generator,(payload_t *)proposal);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated transform",&generated_data);	

	u_int8_t expected_generation[] = {
		/* proposal header */
		0x00,0x00,0x00,0x38,
		0x07,0x04,0x08,0x02,
		/* SPI */
		0x41,0x42,0x43,0x44,
		0x45,0x46,0x47,0x48,
		/* first transform */
		0x03,0x00,0x00,0x18,
		0x05,0x00,0xFD,0xE8,
		/* first transform attributes */
		0x00,0x00,0x00,0x04,
		0x61,0x62,0x63,0x64,
		0x00,0x00,0x00,0x04,
		0x65,0x66,0x67,0x68,
		/* second transform */
		0x00,0x00,0x00,0x10,
		0x03,0x00,0x00,0x04,
		/* second transform attributes */
		0x00,0x00,0x00,0x04,
		0x69,0x6A,0x6B,0x6C
	};
	logger->log_bytes(logger,RAW,"expected transform",expected_generation,sizeof(expected_generation));	

	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");

	allocator_free_chunk(&generated_data);
	proposal->destroy(proposal);
	generator->destroy(generator);
	
	
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
}

/*
 * Described in header
 */ 
void test_generator_with_sa_payload(tester_t *tester)
{
	generator_t *generator;
	transform_attribute_t *attribute1, *attribute2, *attribute3;
	transform_substructure_t *transform1, *transform2;
	proposal_substructure_t *proposal1, *proposal2;
	sa_payload_t *sa_payload;
	ike_header_t *ike_header;
	
	chunk_t data;
	chunk_t generated_data;
	logger_t *logger;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"Message with SA Payload");
	
	/* create generator */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");

	/* create attribute 1 */	
	attribute1 = transform_attribute_create();
	char *stringval = "abcd";
	data.ptr = (void *) stringval;
	data.len = 4;
	attribute1->set_value_chunk(attribute1,data);
	attribute1->set_attribute_type(attribute1,0);
	logger->log(logger,CONTROL,"attribute1 created");

	/* create attribute 2 */
	attribute2 = transform_attribute_create();
	stringval = "efgh";
	data.ptr = (void *) stringval;
	data.len = 4;
	attribute2->set_value_chunk(attribute2,data);
	attribute2->set_attribute_type(attribute2,0);
	logger->log(logger,CONTROL,"attribute2 created");

	/* create attribute 3 */
	attribute3 = transform_attribute_create();
	stringval = "ijkl";
	data.ptr = (void *) stringval;
	data.len = 4;
	attribute3->set_value_chunk(attribute3,data);
	attribute3->set_attribute_type(attribute3,0);
	logger->log(logger,CONTROL,"attribute3 created");

	/* create transform 1*/
	transform1 = transform_substructure_create();
	tester->assert_true(tester,(transform1 != NULL), "transform create check");
	transform1->add_transform_attribute(transform1,attribute1);
	transform1->add_transform_attribute(transform1,attribute2);
	transform1->set_transform_type(transform1,5); /* hex 5 */
	transform1->set_transform_id(transform1,65000); /* hex FDE8 */
		
	/* create transform 2*/
	transform2 = transform_substructure_create();
	tester->assert_true(tester,(transform2 != NULL), "transform create check");
	transform2->add_transform_attribute(transform2,attribute3);
	transform2->set_transform_type(transform2,3); /* hex 3 */
	transform2->set_transform_id(transform2,4); /* hex 4 */
		
	logger->log(logger,CONTROL,"transforms created");
	
	/* create proposal 1 */
	proposal1 = proposal_substructure_create();
	tester->assert_true(tester,(proposal1 != NULL), "proposal create check");
	
	stringval = "ABCDEFGH";
	data.ptr = (void *) stringval;
	data.len = 8;
	
	proposal1->add_transform_substructure(proposal1,transform1);
	proposal1->add_transform_substructure(proposal1,transform2);
	proposal1->set_spi(proposal1,data);
	proposal1->set_proposal_number(proposal1,7);
	proposal1->set_protocol_id(proposal1,4);
	
	/* create proposal 2 */
	proposal2 = proposal_substructure_create();
	tester->assert_true(tester,(proposal2 != NULL), "proposal create check");
	proposal2->set_proposal_number(proposal2,7);
	proposal2->set_protocol_id(proposal2,5);

	/* create sa_payload */
	sa_payload = sa_payload_create();
	
	sa_payload->add_proposal_substructure(sa_payload,proposal1);
	sa_payload->add_proposal_substructure(sa_payload,proposal2);
	
	ike_header = ike_header_create();
	ike_header->set_initiator_spi(ike_header,0x22000054231234LL);
	ike_header->set_responder_spi(ike_header,0x122398);
	((payload_t *) ike_header)->set_next_type((payload_t *) ike_header,SECURITY_ASSOCIATION);
	ike_header->set_exchange_type(ike_header, 0x12);
	ike_header->set_initiator_flag(ike_header, TRUE);
	ike_header->set_response_flag(ike_header, TRUE);
	ike_header->set_message_id(ike_header,0x33AFF3);

	generator->generate_payload(generator,(payload_t *)ike_header);
	generator->generate_payload(generator,(payload_t *)sa_payload);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated transform",&generated_data);	

	u_int8_t expected_generation[] = {
		/* sa payload header */
		0x34,0x12,0x23,0x54,
		0x00,0x00,0x22,0x00,
		0x98,0x23,0x12,0x00,
		0x00,0x00,0x00,0x00,
		0x21,0x20,0x12,0x28,
		0x00,0x33,0xAF,0xF3,
		0x00,0x00,0x00,0x60,

		/* sa payload header */
		0x00,0x00,0x00,0x44,
		/* proposal header */
		0x00,0x00,0x00,0x38,
		0x07,0x04,0x08,0x02,
		/* SPI */
		0x41,0x42,0x43,0x44,
		0x45,0x46,0x47,0x48,
		/* first transform */
		0x03,0x00,0x00,0x18,
		0x05,0x00,0xFD,0xE8,
		/* first transform attributes */
		0x00,0x00,0x00,0x04,
		0x61,0x62,0x63,0x64,
		0x00,0x00,0x00,0x04,
		0x65,0x66,0x67,0x68,
		/* second transform */
		0x00,0x00,0x00,0x10,
		0x03,0x00,0x00,0x04,
		/* second transform attributes */
		0x00,0x00,0x00,0x04,
		0x69,0x6A,0x6B,0x6C,
		/* proposal header 2*/
		0x00,0x00,0x00,0x08,
		0x07,0x05,0x00,0x00,

	};

	logger->log_bytes(logger,RAW,"expected transform",expected_generation,sizeof(expected_generation));	
	
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");

	allocator_free_chunk(&generated_data);
	ike_header->destroy(ike_header);
	sa_payload->destroy(sa_payload);
	generator->destroy(generator);
		
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
	
}

/*
 * Described in header
 */ 
void test_generator_with_ke_payload(tester_t *tester)
{
	generator_t *generator;
	ke_payload_t *ke_payload;
	logger_t *logger;
	chunk_t generated_data;
	chunk_t key_exchange_data;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"Message with KE Payload");
	
	/* create generator */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	ke_payload = ke_payload_create();
	
	
	key_exchange_data.ptr = "test-text";
	key_exchange_data.len = strlen(key_exchange_data.ptr);
	
	ke_payload->set_key_exchange_data(ke_payload,key_exchange_data);
	
	ke_payload->set_dh_group_number(ke_payload,7777);
	
	generator->generate_payload(generator,(payload_t *)ke_payload);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated payload",&generated_data);	

	u_int8_t expected_generation[] = {
		/* payload header */
		0x00,0x00,0x00,0x11,
		0x1E,0x61,0x00,0x00,
		/* key exchange data */
		0x74,0x65,0x73,0x74,
		0x2D,0x74,0x65,0x78,
		0x74
	};
	
	
	logger->log_bytes(logger,RAW,"expected payload",expected_generation,sizeof(expected_generation));	
	
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");

	allocator_free_chunk(&generated_data);	
	
	ke_payload->destroy(ke_payload);
	generator->destroy(generator);
		
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
	
}

/*
 * Described in header
 */ 
void test_generator_with_notify_payload(tester_t *tester)
{
	generator_t *generator;
	notify_payload_t *notify_payload;
	logger_t *logger;
	chunk_t generated_data;
	chunk_t spi,notification_data;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"Message with Notify Payload");
	
	/* create generator */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	notify_payload = notify_payload_create();
	
	
	spi.ptr = "12345";
	spi.len = strlen(spi.ptr);
	
	notification_data.ptr = "67890";
	notification_data.len = strlen(notification_data.ptr);
	
	notify_payload->set_protocol_id(notify_payload,255);
	notify_payload->set_notify_message_type(notify_payload,63333); /* Hex F765 */
	notify_payload->set_spi(notify_payload,spi);
	notify_payload->set_notification_data(notify_payload,notification_data);
	
	generator->generate_payload(generator,(payload_t *)notify_payload);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated payload",&generated_data);	

	u_int8_t expected_generation[] = {
		/* payload header */
		0x00,0x00,0x00,0x12,
		0xFF,0x05,0xF7,0x65,
		/* spi */
		0x31,0x32,0x33,0x34,
		0x35,
		/* notification data */
		0x36,0x37,0x38,0x39,
		0x30,
	};
	
	logger->log_bytes(logger,RAW,"expected payload",expected_generation,sizeof(expected_generation));	
	
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");

	allocator_free_chunk(&generated_data);	
	
	notify_payload->destroy(notify_payload);
	generator->destroy(generator);
		
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
	
}

/*
 * Described in header
 */ 
void test_generator_with_nonce_payload(tester_t *tester)
{
	generator_t *generator;
	nonce_payload_t *nonce_payload;
	logger_t *logger;
	chunk_t generated_data;
	chunk_t nonce;
	
	logger = global_logger_manager->create_logger(global_logger_manager,TESTER,"Message with Nonce Payload");
	
	/* create generator */
	generator = generator_create();
	tester->assert_true(tester,(generator != NULL), "generator create check");
	
	nonce_payload = nonce_payload_create();
	
	
	nonce.ptr = "1234567890123456";
	nonce.len = strlen("1234567890123456");

	nonce_payload->set_nonce(nonce_payload,nonce);
	
	generator->generate_payload(generator,(payload_t *)nonce_payload);
	generator->write_to_chunk(generator,&generated_data);
	logger->log_chunk(logger,RAW,"generated payload",&generated_data);	
	

	u_int8_t expected_generation[] = {
		/* payload header */
		0x00,0x00,0x00,0x14,
		/* nonce data */
		0x31,0x32,0x33,0x34,
		0x35,0x36,0x37,0x38,
		0x39,0x30,0x31,0x32,
		0x33,0x34,0x35,0x36
	};
	
	logger->log_bytes(logger,RAW,"expected payload",expected_generation,sizeof(expected_generation));	
	
	tester->assert_true(tester,(memcmp(expected_generation,generated_data.ptr,sizeof(expected_generation)) == 0), "compare generated data");

	allocator_free_chunk(&generated_data);
	
	
	nonce_payload->destroy(nonce_payload);
	generator->destroy(generator);
		
	global_logger_manager->destroy_logger(global_logger_manager,logger);	
	
}

