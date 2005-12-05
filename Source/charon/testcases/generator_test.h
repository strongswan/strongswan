/**
 * @file generator.h
 * 
 * @brief Tests for the generator_t class.
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

#ifndef GENERATOR_TEST_H_
#define GENERATOR_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function used to test the generator with header payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_header_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with transform attribute payload.
 *
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_transform_attribute(tester_t *tester);


/**
 * @brief Test function used to test the generator with transform substructure payload.
 *
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_transform_substructure(tester_t *tester);

/**
 * @brief Test function used to test the generator with proposal substructure payload.
 *
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_proposal_substructure(tester_t *tester);

/**
 * @brief Test function used to test the generator with SA payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_sa_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with KE payload.
 *
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_ke_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with Notify payload.
 *
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_notify_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with Nonce payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_nonce_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with ID payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_id_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with AUTH payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_auth_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with TS payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_ts_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with CERT payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_cert_payload(tester_t *tester);


/**
 * @brief Test function used to test the generator with CERTREQ payload.
 * 
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_generator_with_certreq_payload(tester_t *tester);


#endif /*GENERATOR_TEST_H_*/
