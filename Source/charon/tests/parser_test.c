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

#include "../allocator.h"
#include "parser_test.h"
#include "../tester.h"
#include "../logger.h"
#include "../encodings.h"
#include "../generator.h"
#include "../parser.h"
#include "../encodings/ike_header.h"

extern payload_info_t *payload_infos[];

extern logger_t *global_logger;

/*
 * Described in Header 
 */
void test_parser_with_header_payload(tester_t *tester)
{
	parser_t *parser;
	parser_context_t *parser_context;
	ike_header_t *header_data;
	status_t status;
	chunk_t test_chunk;
	
	u_int8_t test_bytes[] = {
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x01,
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x02,
		0x03,0x45,0x06,0x28,
		0x00,0x00,0x00,0x07,
		0x00,0x00,0x00,0x08,
	};
	test_chunk.ptr = test_bytes;
	test_chunk.len = sizeof(test_bytes);

	
	parser = parser_create(payload_infos);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	
	parser_context = parser->create_context(parser, test_chunk);
	tester->assert_true(tester,(parser_context != NULL), "parser_context create check");

	status = parser->parse_payload(parser, HEADER, (void**)&header_data, parser_context);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	
	tester->assert_true(tester,(header_data->initiator_spi == 1),"parsed initiator_spi value");
	tester->assert_true(tester,(header_data->responder_spi == 2),"parsed responder_spi value");
	tester->assert_true(tester,(header_data->next_payload == 3),"parsed next_payload value");
	tester->assert_true(tester,(header_data->maj_version == 4),"parsed maj_version value");
	tester->assert_true(tester,(header_data->min_version == 5),"parsed min_version value");
	tester->assert_true(tester,(header_data->exchange_type == 6),"parsed exchange_type value");
	tester->assert_true(tester,(header_data->flags.initiator == TRUE),"parsed flags.initiator value");
	tester->assert_true(tester,(header_data->flags.version == FALSE),"parsed flags.version value");
	tester->assert_true(tester,(header_data->flags.response == TRUE),"parsed flags.response value");
	tester->assert_true(tester,(header_data->message_id == 7),"parsed message_id value");
	tester->assert_true(tester,(header_data->length == 8),"parsed length value");
	
	
	parser_context->destroy(parser_context);
	tester->assert_true(tester,(parser->destroy(parser) == SUCCESS), "parser destroy call check");
	
	global_logger->log_bytes(global_logger, RAW, "Header", (void*)header_data, sizeof(ike_header_t));
	
	allocator_free(header_data);
}
