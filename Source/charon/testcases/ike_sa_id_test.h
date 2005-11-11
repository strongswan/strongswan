/**
 * @file ike_sa_id_test.h
 * 
 * @brief Tests to test the IKE_SA Identifier class ike_sa_id_test_t
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
 
#ifndef IKE_SA_ID_TEST_H_
#define IKE_SA_ID_TEST_H_

#include "../tester.h"

/**
 * @brief Test function used to test the ike_sa_id functionality
 * 
 * Tests are performed using one thread to test the 
 * features of the ike_sa_id_t.
 *
 * @param tester associated tester object
 */
void test_ike_sa_id(tester_t *tester);

#endif /*IKE_SA_ID_TEST_H_*/
