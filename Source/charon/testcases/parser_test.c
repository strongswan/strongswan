/**
 * @file parser_test.c
 * 
 * @brief Tests for the parser_t class.
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
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/vendor_id_payload.h>
#include <encoding/payloads/cp_payload.h>


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
		0x01,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,
		0x02,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,
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
	parser->destroy(parser);
	
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
	chunk_t sa_chunk, sa_chunk2, sa_chunk3;
	iterator_t *proposals, *transforms, *attributes;
    ike_proposal_t *ike_proposals;
    size_t ike_proposal_count;
    child_proposal_t *child_proposals;
    size_t child_proposal_count;
	
	/* first test generic parsing functionality */
		
	u_int8_t sa_bytes[] = {
		0x00,0x80,0x00,0x24, /* payload header*/
			0x00,0x00,0x00,0x20,  /* a proposal */
			0x01,0x02,0x04,0x05,
			0x01,0x02,0x03,0x04, /* spi */
				0x00,0x00,0x00,0x14, /* transform */
				0x07,0x00,0x00,0x03,  
					0x80,0x01,0x00,0x05, /* attribute without length */
					0x00,0x03,0x00,0x04, /* attribute with length */
						0x01,0x02,0x03,0x04
								
		
	};
	
	sa_chunk.ptr = sa_bytes;
	sa_chunk.len = sizeof(sa_bytes);

	
	parser = parser_create(sa_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, SECURITY_ASSOCIATION, (payload_t**)&sa_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	
	
	proposals = sa_payload->create_proposal_substructure_iterator(sa_payload, TRUE);
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
		
		transforms = proposal->create_transform_substructure_iterator(proposal, TRUE);
		while(transforms->has_next(transforms))
		{
			transform_substructure_t *transform;
			int loopi;
			transforms->current(transforms, (void**)&transform);
			tester->assert_true(tester,(transform->get_transform_type(transform) == 7),"transform type");
			tester->assert_true(tester,(transform->get_transform_id(transform) == 3),"transform id");
			attributes = transform->create_transform_attribute_iterator(transform, TRUE);
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
	
	
	
	/* now test SA functionality after parsing an SA payload*/
	
	u_int8_t sa_bytes2[] = {
		0x00,0x00,0x00,0x6C, /* payload header*/
			0x02,0x00,0x00,0x34,  /* a proposal */
			0x01,0x01,0x00,0x04,
				0x03,0x00,0x00,0x0C, /* transform 1 */
				0x01,0x00,0x00,0x01,  
					0x80,0x0E,0x00,0x14, /* keylength attribute with 20 bytes length */
				0x03,0x00,0x00,0x0C, /* transform 2 */
				0x02,0x00,0x00,0x01,  
					0x80,0x0E,0x00,0x14, /* keylength attribute with 20 bytes length */
				0x03,0x00,0x00,0x0C, /* transform 3 */
				0x03,0x00,0x00,0x01,  
					0x80,0x0E,0x00,0x14, /* keylength attribute with 20 bytes length */
				0x00,0x00,0x00,0x08, /* transform 4 */
				0x04,0x00,0x00,0x01, 
			0x00,0x00,0x00,0x34,  /* a proposal */
			0x01,0x01,0x00,0x04,
				0x03,0x00,0x00,0x0C, /* transform 1 */
				0x01,0x00,0x00,0x02,  
					0x80,0x0E,0x00,0x10, /* keylength attribute with 16 bytes length */
				0x03,0x00,0x00,0x0C, /* transform 2 */
				0x02,0x00,0x00,0x02,  
					0x80,0x0E,0x00,0x10, /* keylength attribute with 16 bytes length */
				0x03,0x00,0x00,0x0C, /* transform 3 */
				0x03,0x00,0x00,0x02,  
					0x80,0x0E,0x00,0x10, /* keylength attribute with 16 bytes length */
				0x00,0x00,0x00,0x08, /* transform 4 */
				0x04,0x00,0x00,0x02, 		
	};
	
	sa_chunk2.ptr = sa_bytes2;
	sa_chunk2.len = sizeof(sa_bytes2);
		
	parser = parser_create(sa_chunk2);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, SECURITY_ASSOCIATION, (payload_t**)&sa_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}

	status = sa_payload->payload_interface.verify(&(sa_payload->payload_interface));
	tester->assert_true(tester,(status == SUCCESS),"verify call check");

	status = sa_payload->get_ike_proposals (sa_payload, &ike_proposals, &ike_proposal_count);	
	tester->assert_true(tester,(status == SUCCESS),"get ike proposals call check");	
	
	tester->assert_true(tester,(ike_proposal_count == 2),"ike proposal count check");
	tester->assert_true(tester,(ike_proposals[0].encryption_algorithm == 1),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[0].encryption_algorithm_key_length == 20),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[0].integrity_algorithm == 1),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[0].integrity_algorithm_key_length == 20),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[0].pseudo_random_function == 1),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[0].pseudo_random_function_key_length == 20),"ike proposal content check");		
	tester->assert_true(tester,(ike_proposals[0].diffie_hellman_group == 1),"ike proposal content check");	
	
	tester->assert_true(tester,(ike_proposals[1].encryption_algorithm == 2),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[1].encryption_algorithm_key_length == 16),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[1].integrity_algorithm == 2),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[1].integrity_algorithm_key_length == 16),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[1].pseudo_random_function == 2),"ike proposal content check");	
	tester->assert_true(tester,(ike_proposals[1].pseudo_random_function_key_length == 16),"ike proposal content check");		
	tester->assert_true(tester,(ike_proposals[1].diffie_hellman_group == 2),"ike proposal content check");	
	
	
	if (status == SUCCESS)
	{
		allocator_free(ike_proposals);
	}
	sa_payload->destroy(sa_payload);
	
	/* now test SA functionality after parsing an SA payload with child sa proposals*/
	u_int8_t sa_bytes3[] = {
		0x00,0x00,0x00,0xA0, /* payload header*/

			/* suite 1 */
			0x02,0x00,0x00,0x28,  /* a proposal */
			0x01,0x02,0x04,0x03,
			0x01,0x01,0x01,0x01,
				0x03,0x00,0x00,0x0C, /* transform 1 */
				0x03,0x00,0x00,0x01,  
					0x80,0x0E,0x00,0x14, /* keylength attribute with 20 bytes length */

				0x03,0x00,0x00,0x08, /* transform 2 */
				0x04,0x00,0x00,0x0E,  

				0x00,0x00,0x00,0x08, /* transform 3 */
				0x05,0x00,0x00,0x01,  


			0x02,0x00,0x00,0x20,  /* a proposal */
			0x01,0x03,0x04,0x02,
			0x02,0x02,0x02,0x02,
			
				0x03,0x00,0x00,0x0C, /* transform 1 */
				0x01,0x00,0x00,0x0C,  
					0x80,0x0E,0x00,0x20, /* keylength attribute with 32 bytes length */
					
				0x00,0x00,0x00,0x08, /* transform 2 */
				0x04,0x00,0x00,0x02,  

			/* suite 2 */
			0x02,0x00,0x00,0x28,  /* a proposal */
			0x02,0x02,0x04,0x03,
			0x01,0x01,0x01,0x01,
				0x03,0x00,0x00,0x0C, /* transform 1 */
				0x03,0x00,0x00,0x01,  
					0x80,0x0E,0x00,0x14, /* keylength attribute with 20 bytes length */

				0x03,0x00,0x00,0x08, /* transform 2 */
				0x04,0x00,0x00,0x0E,  

				0x00,0x00,0x00,0x08, /* transform 3 */
				0x05,0x00,0x00,0x01,  


			0x00,0x00,0x00,0x2C,  /* a proposal */
			0x02,0x03,0x04,0x03,
			0x02,0x02,0x02,0x02,
			
				0x03,0x00,0x00,0x0C, /* transform 1 */
				0x01,0x00,0x00,0x0C,  
					0x80,0x0E,0x00,0x20, /* keylength attribute with 32 bytes length */
					
				0x03,0x00,0x00,0x0C, /* transform 2 */
				0x03,0x00,0x00,0x01,  
					0x80,0x0E,0x00,0x14, /* keylength attribute with 20 bytes length */
					
				0x00,0x00,0x00,0x08, /* transform 3 */
				0x04,0x00,0x00,0x02,
	};
	
	sa_chunk3.ptr = sa_bytes3;
	sa_chunk3.len = sizeof(sa_bytes3);
		
	parser = parser_create(sa_chunk3);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, SECURITY_ASSOCIATION, (payload_t**)&sa_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}

	status = sa_payload->payload_interface.verify(&(sa_payload->payload_interface));
	tester->assert_true(tester,(status == SUCCESS),"verify call check");

	status = sa_payload->get_ike_proposals (sa_payload, &ike_proposals, &ike_proposal_count);	
	tester->assert_false(tester,(status == SUCCESS),"get ike proposals call check");
	
	status = sa_payload->get_child_proposals (sa_payload, &child_proposals, &child_proposal_count);	
	tester->assert_true(tester,(status == SUCCESS),"get child proposals call check");	
	

	tester->assert_true(tester,(child_proposal_count == 2),"child proposal count check");
	tester->assert_true(tester,(child_proposals[0].ah.is_set == TRUE),"is ah set check");
	tester->assert_true(tester,(child_proposals[0].ah.integrity_algorithm == AUTH_HMAC_MD5_96),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[0].ah.integrity_algorithm_key_size == 20),"integrity_algorithm_key_size check");
	tester->assert_true(tester,(child_proposals[0].ah.diffie_hellman_group == MODP_2048_BIT),"diffie_hellman_group check");
	tester->assert_true(tester,(child_proposals[0].ah.extended_sequence_numbers == EXT_SEQ_NUMBERS),"extended_sequence_numbers check");
	tester->assert_true(tester,(child_proposals[0].ah.spi[0] == 1),"spi check");
	tester->assert_true(tester,(child_proposals[0].ah.spi[1] == 1),"spi check");
	tester->assert_true(tester,(child_proposals[0].ah.spi[2] == 1),"spi check");
	tester->assert_true(tester,(child_proposals[0].ah.spi[3] == 1),"spi check");
	
	tester->assert_true(tester,(child_proposals[0].esp.is_set == TRUE),"is ah set check");
	tester->assert_true(tester,(child_proposals[0].esp.encryption_algorithm == ENCR_AES_CBC),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[0].esp.encryption_algorithm_key_size == 32),"integrity_algorithm_key_size check");
	tester->assert_true(tester,(child_proposals[0].esp.diffie_hellman_group == MODP_1024_BIT),"diffie_hellman_group check");
	tester->assert_true(tester,(child_proposals[0].esp.integrity_algorithm == AUTH_UNDEFINED),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[0].esp.spi[0] == 2),"spi check");
	tester->assert_true(tester,(child_proposals[0].esp.spi[1] == 2),"spi check");
	tester->assert_true(tester,(child_proposals[0].esp.spi[2] == 2),"spi check");
	tester->assert_true(tester,(child_proposals[0].esp.spi[3] == 2),"spi check");

	tester->assert_true(tester,(child_proposals[1].ah.is_set == TRUE),"is ah set check");
	tester->assert_true(tester,(child_proposals[1].ah.integrity_algorithm == AUTH_HMAC_MD5_96),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[1].ah.integrity_algorithm_key_size == 20),"integrity_algorithm_key_size check");
	tester->assert_true(tester,(child_proposals[1].ah.diffie_hellman_group == MODP_2048_BIT),"diffie_hellman_group check");
	tester->assert_true(tester,(child_proposals[1].ah.extended_sequence_numbers == EXT_SEQ_NUMBERS),"extended_sequence_numbers check");
	tester->assert_true(tester,(child_proposals[1].ah.spi[0] == 1),"spi check");
	tester->assert_true(tester,(child_proposals[1].ah.spi[1] == 1),"spi check");
	tester->assert_true(tester,(child_proposals[1].ah.spi[2] == 1),"spi check");
	tester->assert_true(tester,(child_proposals[1].ah.spi[3] == 1),"spi check");	

	tester->assert_true(tester,(child_proposals[1].esp.is_set == TRUE),"is ah set check");
	tester->assert_true(tester,(child_proposals[1].esp.encryption_algorithm == ENCR_AES_CBC),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[1].esp.encryption_algorithm_key_size == 32),"integrity_algorithm_key_size check");
	tester->assert_true(tester,(child_proposals[1].esp.diffie_hellman_group == MODP_1024_BIT),"diffie_hellman_group check");
	tester->assert_true(tester,(child_proposals[1].esp.integrity_algorithm == AUTH_HMAC_MD5_96),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[1].esp.integrity_algorithm_key_size == 20),"integrity_algorithm check");
	tester->assert_true(tester,(child_proposals[1].esp.spi[0] == 2),"spi check");
	tester->assert_true(tester,(child_proposals[1].esp.spi[1] == 2),"spi check");
	tester->assert_true(tester,(child_proposals[1].esp.spi[2] == 2),"spi check");
	tester->assert_true(tester,(child_proposals[1].esp.spi[3] == 2),"spi check");

	if (status == SUCCESS)
	{
		allocator_free(child_proposals);
	}

	
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
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	nonce_payload->get_nonce(nonce_payload, &result);
	tester->assert_true(tester,(result.len == 16), "parsed nonce lenght");
	tester->assert_false(tester,(memcmp(nonce_bytes + 4, result.ptr, result.len)), "parsed nonce data");
	nonce_payload->destroy(nonce_payload);
	allocator_free_chunk(&result);
}

/*
 * Described in Header 
 */
void test_parser_with_id_payload(tester_t *tester)
{
	parser_t *parser;
	id_payload_t *id_payload;
	status_t status;
	chunk_t id_chunk, result;
	
	u_int8_t id_bytes[] = {
		0x00,0x00,0x00,0x14, /* payload header */
		0x05,0x01,0x02,0x03,
			0x04,0x05,0x06,0x07,/* 12 Byte nonce */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	id_chunk.ptr = id_bytes;
	id_chunk.len = sizeof(id_bytes);

	parser = parser_create(id_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, ID_INITIATOR, (payload_t**)&id_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	result = id_payload->get_data_clone(id_payload);
	tester->assert_true(tester,(id_payload->get_initiator(id_payload) == TRUE), "is IDi payload");
	tester->assert_true(tester,(id_payload->get_id_type(id_payload) == ID_IPV6_ADDR), "is ID_IPV6_ADDR ID type");
	tester->assert_true(tester,(result.len == 12), "parsed data lenght");
	tester->assert_false(tester,(memcmp(id_bytes + 8, result.ptr, result.len)), "parsed nonce data");
	id_payload->destroy(id_payload);
	allocator_free_chunk(&result);
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
	parser->destroy(parser);
	
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
	parser->destroy(parser);
	
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

/*
 * Described in Header 
 */
void test_parser_with_auth_payload(tester_t *tester)
{
	parser_t *parser;
	auth_payload_t *auth_payload;
	status_t status;
	chunk_t auth_chunk, result;
	
	u_int8_t auth_bytes[] = {
		0x00,0x00,0x00,0x14, /* payload header */
		0x03,0x01,0x02,0x03,
			0x04,0x05,0x06,0x07,/* 12 Byte nonce */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	auth_chunk.ptr = auth_bytes;
	auth_chunk.len = sizeof(auth_bytes);

	parser = parser_create(auth_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, AUTHENTICATION, (payload_t**)&auth_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	result = auth_payload->get_data_clone(auth_payload);
	tester->assert_true(tester,(auth_payload->get_auth_method(auth_payload) == DSS_DIGITAL_SIGNATURE), "is DSS_DIGITAL_SIGNATURE method");
	tester->assert_true(tester,(result.len == 12), "parsed data lenght");
	tester->assert_false(tester,(memcmp(auth_bytes + 8, result.ptr, result.len)), "parsed nonce data");
	auth_payload->destroy(auth_payload);
	allocator_free_chunk(&result);
}

/*
 * Described in Header 
 */
void test_parser_with_ts_payload(tester_t *tester)
{
	parser_t *parser;
	ts_payload_t *ts_payload;
	status_t status;
	chunk_t ts_chunk;
	traffic_selector_substructure_t *ts1, *ts2;
	host_t *start_host1, *start_host2, *end_host1, *end_host2;
	iterator_t *iterator;
	
	u_int8_t ts_bytes[] = {
		/* payload header */
		0x00,0x00,0x00,0x28,
		0x02,0x00,0x00,0x00,
		
			/* traffic selector 1 */
			0x07,0x00,0x00,0x10,
			0x01,0xF4,0x01,0xF4,
			0xC0,0xA8,0x01,0x00,
			0xC0,0xA8,0x01,0xFF,

			/* traffic selector 2 */
			0x07,0x03,0x00,0x10,
			0x00,0x00,0xFF,0xFF,
			0x00,0x00,0x00,0x00,
			0xFF,0xFF,0xFF,0xFF,			
	};
	
	ts_chunk.ptr = ts_bytes;
	ts_chunk.len = sizeof(ts_bytes);

	parser = parser_create(ts_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, TRAFFIC_SELECTOR_RESPONDER, (payload_t**)&ts_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	
	iterator = ts_payload->create_traffic_selector_substructure_iterator(ts_payload,TRUE);
	
	tester->assert_true(tester,(iterator->has_next(iterator)), "has next check");

	/* check first ts */
	iterator->current(iterator,(void **)&ts1);
	tester->assert_true(tester,(ts1->get_protocol_id(ts1) == 0), "ip protocol id check");
	start_host1 = ts1->get_start_host(ts1);
	end_host1 = ts1->get_end_host(ts1);
	tester->assert_true(tester,(start_host1->get_port(start_host1) == 500), "start port check");
	tester->assert_true(tester,(end_host1->get_port(end_host1) == 500), "start port check");
	tester->assert_true(tester,(memcmp(start_host1->get_address(start_host1),"192.168.1.0",strlen("192.168.1.0")) == 0), "start address check");
	tester->assert_true(tester,(memcmp(end_host1->get_address(end_host1),"192.168.1.255",strlen("192.168.1.255")) == 0), "end address check");
	
	start_host1->destroy(start_host1);
	end_host1->destroy(end_host1);

	tester->assert_true(tester,(iterator->has_next(iterator)), "has next check");

	/* check second ts */

	iterator->current(iterator,(void **)&ts2);
	
	tester->assert_true(tester,(ts2->get_protocol_id(ts2) == 3), "ip protocol id check");
	start_host2 = ts2->get_start_host(ts2);
	end_host2 = ts2->get_end_host(ts2);
	tester->assert_true(tester,(start_host2->get_port(start_host2) == 0), "start port check");
	tester->assert_true(tester,(end_host2->get_port(end_host2) == 65535), "start port check");
	tester->assert_true(tester,(memcmp(start_host2->get_address(start_host2),"0.0.0.0",strlen("0.0.0.0")) == 0), "start address check");
	tester->assert_true(tester,(memcmp(end_host2->get_address(end_host2),"255.255.255.255",strlen("255.255.255.255")) == 0), "end address check");
	start_host2->destroy(start_host2);	
	end_host2->destroy(end_host2);
	
	
	
	tester->assert_false(tester,(iterator->has_next(iterator)), "has next check");
	
	iterator->destroy(iterator);
	
	ts_payload->destroy(ts_payload);
}

/*
 * Described in Header 
 */
void test_parser_with_cert_payload(tester_t *tester)
{
	parser_t *parser;
	cert_payload_t *cert_payload;
	status_t status;
	chunk_t cert_chunk, result;
	
	u_int8_t cert_bytes[] = {
		0x00,0x00,0x00,0x11, /* payload header */
		0x03,
			0x04,0x05,0x06,0x07,/* 12 Byte nonce */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	cert_chunk.ptr = cert_bytes;
	cert_chunk.len = sizeof(cert_bytes);

	parser = parser_create(cert_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, CERTIFICATE, (payload_t**)&cert_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	result = cert_payload->get_data_clone(cert_payload);
	tester->assert_true(tester,(cert_payload->get_cert_encoding(cert_payload) == DNS_SIGNED_KEY), "is DNS_SIGNED_KEY encoding");
	tester->assert_true(tester,(result.len == 12), "parsed data lenght");
	tester->assert_false(tester,(memcmp(cert_bytes + 5, result.ptr, result.len)), "parsed data");
	cert_payload->destroy(cert_payload);
	allocator_free_chunk(&result);
}

/*
 * Described in Header 
 */
void test_parser_with_certreq_payload(tester_t *tester)
{
	parser_t *parser;
	certreq_payload_t *certreq_payload;
	status_t status;
	chunk_t certreq_chunk, result;
	
	u_int8_t certreq_bytes[] = {
		0x00,0x00,0x00,0x11, /* payload header */
		0x03,
			0x04,0x05,0x06,0x07,/* 12 Byte data */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	certreq_chunk.ptr = certreq_bytes;
	certreq_chunk.len = sizeof(certreq_bytes);

	parser = parser_create(certreq_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, CERTIFICATE_REQUEST, (payload_t**)&certreq_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	result = certreq_payload->get_data_clone(certreq_payload);
	tester->assert_true(tester,(certreq_payload->get_cert_encoding(certreq_payload) == DNS_SIGNED_KEY), "is DNS_SIGNED_KEY encoding");
	tester->assert_true(tester,(result.len == 12), "parsed data lenght");
	tester->assert_false(tester,(memcmp(certreq_bytes + 5, result.ptr, result.len)), "parsed data");
	certreq_payload->destroy(certreq_payload);
	allocator_free_chunk(&result);
}

/*
 * Described in Header 
 */
void test_parser_with_delete_payload(tester_t *tester)
{
	parser_t *parser;
	delete_payload_t *delete_payload;
	status_t status;
	chunk_t delete_chunk, result;
	
	u_int8_t delete_bytes[] = {
		0x00,0x00,0x00,0x14, /* payload header */
		0x03,0x03,0x00,0x04,
			0x04,0x05,0x06,0x07,/* 12 Byte data */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	delete_chunk.ptr = delete_bytes;
	delete_chunk.len = sizeof(delete_bytes);

	parser = parser_create(delete_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, DELETE, (payload_t**)&delete_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	result = delete_payload->get_spis(delete_payload);
	tester->assert_true(tester,(delete_payload->get_protocol_id(delete_payload) == ESP), "is ESP protocol");
	tester->assert_true(tester,(delete_payload->get_spi_size(delete_payload) == 3), "SPI size check");
	tester->assert_true(tester,(delete_payload->get_spi_count(delete_payload) == 4), "SPI count check");
	tester->assert_true(tester,(result.len == 12), "parsed data lenght");
	tester->assert_false(tester,(memcmp(delete_bytes + 8, result.ptr, result.len)), "parsed data");
	tester->assert_true(tester,(((payload_t *)delete_payload)->verify((payload_t *)delete_payload) == SUCCESS), "verify check");
	
	delete_payload->destroy(delete_payload);
}


/*
 * Described in Header 
 */
void test_parser_with_vendor_id_payload(tester_t *tester)
{
	parser_t *parser;
	vendor_id_payload_t *vendor_id_payload;
	status_t status;
	chunk_t vendor_id_chunk, result;
	
	u_int8_t vendor_id_bytes[] = {
		0x00,0x00,0x00,0x10, /* payload header */
			0x04,0x05,0x06,0x07,/* 12 Byte data */
			0x08,0x09,0x0A,0x2B,
			0x0C,0x0D,0x0E,0x0F
	};
	
	vendor_id_chunk.ptr = vendor_id_bytes;
	vendor_id_chunk.len = sizeof(vendor_id_bytes);

	parser = parser_create(vendor_id_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, VENDOR_ID, (payload_t**)&vendor_id_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");
	parser->destroy(parser);
	
	if (status != SUCCESS)
	{
		return;	
	}
	result = vendor_id_payload->get_data(vendor_id_payload);
	tester->assert_true(tester,(result.len == 12), "parsed data lenght");
	tester->assert_false(tester,(memcmp(vendor_id_bytes + 4, result.ptr, result.len)), "parsed data");
	tester->assert_true(tester,(((payload_t *)vendor_id_payload)->verify((payload_t *)vendor_id_payload) == SUCCESS), "verify check");
	
	vendor_id_payload->destroy(vendor_id_payload);
}

/*
 * Described in Header 
 */
void test_parser_with_cp_payload(tester_t *tester)
{
	parser_t *parser;
	cp_payload_t *cp_payload;
	configuration_attribute_t *attribute;
	status_t status;
	chunk_t cp_chunk;
	iterator_t *iterator;
	
	/* first test generic parsing functionality */
		
	u_int8_t cp_bytes[] = {
		/* cp payload header */
		0x00,0x00,0x00,0x18,
		0x05,0x00,0x00,0x00,
		/* configuration attribute 1*/
		0x00,0x03,0x00,0x04,
		0x61,0x62,0x63,0x64,
		/* configuration attribute 2*/
		0x00,0x04,0x00,0x04,
		0x65,0x66,0x67,0x68,
	};
	
	cp_chunk.ptr = cp_bytes;
	cp_chunk.len = sizeof(cp_bytes);

	
	parser = parser_create(cp_chunk);
	tester->assert_true(tester,(parser != NULL), "parser create check");
	status = parser->parse_payload(parser, CONFIGURATION, (payload_t**)&cp_payload);
	tester->assert_true(tester,(status == SUCCESS),"parse_payload call check");

	iterator = cp_payload->create_configuration_attribute_iterator(cp_payload,TRUE);
	
	tester->assert_true(tester,(iterator->has_next(iterator)),"has_next call check");
	
	iterator->current(iterator,(void **)&attribute);


	tester->assert_true(tester,(attribute->get_attribute_type(attribute) == 3),"get type check");	
	tester->assert_true(tester,(attribute->get_attribute_length(attribute) == 4),"get type check");

	tester->assert_true(tester,(iterator->has_next(iterator)),"has_next call check");

	iterator->current(iterator,(void **)&attribute);
	

	tester->assert_true(tester,(attribute->get_attribute_type(attribute) == 4),"get type check");	
	tester->assert_true(tester,(attribute->get_attribute_length(attribute) == 4),"get type check");
	
	iterator->current(iterator,(void **)&attribute);
	
	tester->assert_false(tester,(iterator->has_next(iterator)),"has_next call check");
	
	
	iterator->destroy(iterator);

	if (status != SUCCESS)
	{
		return;	
	}

	cp_payload->destroy(cp_payload);
	parser->destroy(parser);

}
