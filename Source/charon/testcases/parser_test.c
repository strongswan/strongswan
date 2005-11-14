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
		0x00,0x00,0x00,0x08,
	};
	header_chunk.ptr = header_bytes;
	header_chunk.len = sizeof(header_bytes);

	
	parser = parser_create(header_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	
	status = parser->parse_payload(parser, HEADER, (payload_t**)&ike_header);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	
	tester->assert_true(tester,(ike_header->initiator_spi == 1),"parsed initiator_spi value");
	tester->assert_true(tester,(ike_header->responder_spi == 2),"parsed responder_spi value");
	tester->assert_true(tester,(ike_header->next_payload == 3),"parsed next_payload value");
	tester->assert_true(tester,(ike_header->maj_version == 4),"parsed maj_version value");
	tester->assert_true(tester,(ike_header->min_version == 5),"parsed min_version value");
	tester->assert_true(tester,(ike_header->exchange_type == 6),"parsed exchange_type value");
	tester->assert_true(tester,(ike_header->flags.initiator == TRUE),"parsed flags.initiator value");
	tester->assert_true(tester,(ike_header->flags.version == FALSE),"parsed flags.version value");
	tester->assert_true(tester,(ike_header->flags.response == TRUE),"parsed flags.response value");
	tester->assert_true(tester,(ike_header->message_id == 7),"parsed message_id value");
	tester->assert_true(tester,(ike_header->length == 8),"parsed length value");
	
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	ike_header->destroy(ike_header);
}
