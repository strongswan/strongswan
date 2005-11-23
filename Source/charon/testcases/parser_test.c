/**
 * @file parser_test.h
 * 
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

#include "parser_test.h"

#include <utils/allocator.h>
#include <utils/logger_manager.h>
#include <encoding/generator.h>
#include <encoding/parser.h>
#include <encoding/payloads/encodings.h>
#include <encoding/payloads/ike_header.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/notify_payload.h>


extern logger_manager_t *global_logger_manager;


/*
 * Described in Header 
 */
void test_parser_with_header_payload(tester_t *tester)
{
	parser_t *parser;
	ike_header_t *ike_header;
	status_t status;
	chunk_t header_chunk;
	
	u_int8_t header_bytes[] = {
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x01,
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x02,
		0x03,0x45,0x06,0x28,
		0x00,0x00,0x00,0x07,
		0x00,0x00,0x00,0x1C,
	};
	header_chunk.ptr = header_bytes;
	header_chunk.len = sizeof(header_bytes);

	
	parser = parser_create(header_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, HEADER, (payload_t**)&ike_header);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	if (status != SUCCESS)
	{
		return;	
	}
	
	tester->assert_true(tester,(ike_header->get_initiator_spi(ike_header) == 1),"parsed initiator_spi value");
	tester->assert_true(tester,(ike_header->get_responder_spi(ike_header) == 2),"parsed responder_spi value");
	tester->assert_true(tester,(ike_header->payload_interface.get_next_type((payload_t*)ike_header) == 3),"parsed next_payload value");
	tester->assert_true(tester,(ike_header->get_maj_version(ike_header) == 4),"parsed maj_version value");
	tester->assert_true(tester,(ike_header->get_min_version(ike_header) == 5),"parsed min_version value");
	tester->assert_true(tester,(ike_header->get_exchange_type(ike_header) == 6),"parsed exchange_type value");
	tester->assert_true(tester,(ike_header->get_initiator_flag(ike_header) == TRUE),"parsed flags.initiator value");
	tester->assert_true(tester,(ike_header->get_version_flag(ike_header) == FALSE),"parsed flags.version value");
	tester->assert_true(tester,(ike_header->get_response_flag(ike_header) == TRUE),"parsed flags.response value");
	tester->assert_true(tester,(ike_header->get_message_id(ike_header) == 7),"parsed message_id value");
	tester->assert_true(tester,(ike_header->payload_interface.get_length((payload_t*)ike_header) == 0x1C),"parsed length value");

	ike_header->destroy(ike_header);
}

/*
 * Described in Header 
 */
void test_parser_with_sa_payload(tester_t *tester)
{
	parser_t *parser;
	sa_payload_t *sa_payload;
	status_t status;
	chunk_t sa_chunk;
	linked_list_iterator_t *proposals, *transforms, *attributes;
	
	u_int8_t sa_bytes[] = {
		0x00,0x80,0x00,0x24, /* payload header*/
			0x00,0x00,0x00,0x20,  /* a proposal */
			0x01,0x02,0x04,0x05,
			0x01,0x02,0x03,0x04, /* spi */
				0x00,0x00,0x00,0x14, /* transform */
				0x07,0x00,0x00,0x03,  
					0x80,0x01,0x00,0x05, /* attribute without length */
					0x00,0x03,0x00,0x04, /* attribute with lenngth */
						0x01,0x02,0x03,0x04
								
		
	};
	
	sa_chunk.ptr = sa_bytes;
	sa_chunk.len = sizeof(sa_bytes);

	
	parser = parser_create(sa_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, SECURITY_ASSOCIATION, (payload_t**)&sa_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	if (status != SUCCESS)
	{
		return;	
	}
	
	
	sa_payload->create_proposal_substructure_iterator(sa_payload, &proposals, TRUE);
	while (proposals->has_next(proposals))
	{
		proposal_substructure_t *proposal;
		proposals->current(proposals, (void**)&proposal);
		chunk_t spi;
		u_int8_t spi_should[] = {0x01, 0x02, 0x03, 0x04};
		
		tester->assert_true(tester,(proposal->get_proposal_number(proposal) == 1),"proposal number");
		tester->assert_true(tester,(proposal->get_protocol_id(proposal) == 2),"proposal id");
		spi = proposal->get_spi(proposal);
		tester->assert_false(tester,(memcmp(&spi_should, spi.ptr, spi.len)),"proposal spi");
		
		proposal->create_transform_substructure_iterator(proposal, &transforms, TRUE);
		while(transforms->has_next(transforms))
		{
			transform_substructure_t *transform;
			int loopi;
			transforms->current(transforms, (void**)&transform);
			tester->assert_true(tester,(transform->get_transform_type(transform) == 7),"transform type");
			tester->assert_true(tester,(transform->get_transform_id(transform) == 3),"transform id");
			transform->create_transform_attribute_iterator(transform, &attributes, TRUE);
			loopi = 0;
			while (attributes->has_next(attributes))
			{
				transform_attribute_t *attribute;
				attributes->current(attributes, (void**)&attribute);
				if (loopi == 0)
				{
					u_int8_t value[] = {0x05, 0x00};
					chunk_t attribute_value;
					tester->assert_true(tester,(attribute->get_attribute_type(attribute) == 1),"attribute 1 type");
					attribute_value = attribute->get_value_chunk(attribute);
					tester->assert_false(tester,(memcmp(&value, attribute_value.ptr, attribute_value.len)),"attribute 1 value");
				}
				if (loopi == 1)
				{
					u_int8_t value[] = {0x01, 0x02, 0x03, 0x04};
					chunk_t attribute_value;
					tester->assert_true(tester,(attribute->get_attribute_type(attribute) == 3),"attribute 2 type");
					attribute_value = attribute->get_value_chunk(attribute);
					tester->assert_false(tester,(memcmp(&value, attribute_value.ptr, attribute_value.len)),"attribute 2 value");
				}
				loopi++;
			}
			attributes->destroy(attributes);
		}
		transforms->destroy(transforms);
	}
	proposals->destroy(proposals);
	
	

	sa_payload->destroy(sa_payload);
}

/*
 * Described in Header 
 */
void test_parser_with_nonce_payload(tester_t *tester)
{
	parser_t *parser;
	nonce_payload_t *nonce_payload;
	status_t status;
	chunk_t nonce_chunk, result;
	
	u_int8_t nonce_bytes[] = {
		0x00,0x00,0x00,0x14, /* payload header */
			0x00,0x01,0x02,0x03,  /* 16 Byte nonce */
			0x04,0x05,0x06,0x07,
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	nonce_chunk.ptr = nonce_bytes;
	nonce_chunk.len = sizeof(nonce_bytes);

	parser = parser_create(nonce_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, NONCE, (payload_t**)&nonce_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	if (status != SUCCESS)
	{
		return;	
	}
	nonce_payload->get_nonce(nonce_payload, &result);
	tester->assert_true(tester,(result.len == 16), "parsed nonce lenght");
	tester->assert_false(tester,(memcmp(nonce_bytes + 4, result.ptr, result.len)), "parsed nonce data");
	nonce_payload->destroy(nonce_payload);
	
}

/*
 * Described in Header 
 */
void test_parser_with_ke_payload(tester_t *tester)
{
	parser_t *parser;
	ke_payload_t *ke_payload;
	status_t status;
	chunk_t ke_chunk, result;
	
	u_int8_t ke_bytes[] = {
		0x00,0x00,0x00,0x18, /* payload header */
		0x00,0x03,0x00,0x00, /* dh group 3 */ 
			0x01,0x02,0x03,0x03, /* 16 Byte dh data */
			0x04,0x05,0x06,0x07,
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	ke_chunk.ptr = ke_bytes;
	ke_chunk.len = sizeof(ke_bytes);

	parser = parser_create(ke_chunk); 
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, KEY_EXCHANGE, (payload_t**)&ke_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	if (status != SUCCESS)
	{
		return;	
	}
	tester->assert_true(tester,(ke_payload->get_dh_group_number(ke_payload) == 3), "DH group");
	result = ke_payload->get_key_exchange_data(ke_payload);
	tester->assert_true(tester,(result.len == 16), "parsed key lenght");
	tester->assert_false(tester,(memcmp(ke_bytes + 8, result.ptr, result.len)), "parsed key data");
	ke_payload->destroy(ke_payload);
}


/*
 * Described in Header 
 */
void test_parser_with_notify_payload(tester_t *tester)
{
	parser_t *parser;
	notify_payload_t *notify_payload;
	status_t status;
	chunk_t notify_chunk, result;
	
	u_int8_t notify_bytes[] = {
		0x00,0x00,0x00,0x1C, /* payload header */
		0x03,0x04,0x00,0x01, 
			0x01,0x02,0x03,0x03, /* spi */
			0x04,0x05,0x06,0x07, /* noti dati */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F,
			0x0C,0x0D,0x0E,0x0F
	};
	
	notify_chunk.ptr = notify_bytes;
	notify_chunk.len = sizeof(notify_bytes);

	parser = parser_create(notify_chunk); 
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, NOTIFY, (payload_t**)&notify_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	if (status != SUCCESS)
	{
		return;	
	}
	tester->assert_true(tester,(notify_payload->get_protocol_id(notify_payload) == 3), "Protocol id");
	tester->assert_true(tester,(notify_payload->get_notify_message_type(notify_payload) == 1), "notify message type");
	
	result = notify_payload->get_spi(notify_payload);
	tester->assert_false(tester,(memcmp(notify_bytes + 8, result.ptr, result.len)), "parsed spi");
	
	result = notify_payload->get_notification_data(notify_payload);
	tester->assert_false(tester,(memcmp(notify_bytes + 12, result.ptr, result.len)), "parsed notification data");
	
	notify_payload->destroy(notify_payload);
}
