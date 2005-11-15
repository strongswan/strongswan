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

#include "../generator.h"
#include "../parser.h"
#include "../utils/allocator.h"
#include "../utils/logger_manager.h"
#include "../payloads/encodings.h"
#include "../payloads/ike_header.h"
#include "../payloads/sa_payload.h"


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
	
	u_int8_t sa_bytes[] = {
		0x00,0x80,0x00,0x24, /* payload header*/
			0x00,0x00,0x00,0x20,  /* a proposal */
			0x01,0x02,0x04,0x05,
			0x01,0x02,0x03,0x04, /* spi */
				0x00,0x00,0x00,0x14, /* transform */
				0x02,0x00,0x00,0x03,  
					0x80,0x01,0x00,0x05, /* attribute without length */
					0x00,0x01,0x00,0x04, /* attribute with lenngth */
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
	

	sa_payload->destroy(sa_payload);
}
