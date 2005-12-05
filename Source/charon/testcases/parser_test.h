/**
 * @file parser_test.h
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

#ifndef PARSER_TEST_H_
#define PARSER_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a header payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_header_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a sa payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_sa_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a nonce payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_nonce_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a ID payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_id_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a ke payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_ke_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a notify payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_notify_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a AUTH payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_auth_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a TS payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_ts_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a CERT payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_cert_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a CERTREQ payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_certreq_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a CERTREQ payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_delete_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a VENDOR ID payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_vendor_id_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a CP payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_cp_payload(tester_t *tester);

/**
 * @brief Test function used to test the parser_t functionality when 
 * parsing a EAP payload.
 *
 * @param tester 	associated tester_t object
 * 
 * @ingroup testcases
 */
void test_parser_with_eap_payload(tester_t *tester);



#endif /*PARSER_TEST_H_*/
