/**
 * @file ike_sa_manager_test.c
 *
 * @brief Tests for the ike_sa_manager_t class.
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

#ifndef IKE_SA_MANAGER_TEST_H_
#define IKE_SA_MANAGER_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function used to test the ike_sa_manager_t functionality.
 *
 * @param tester associated tester_t object
 * 
 * @ingroup testcases
 */
void test_ike_sa_manager(tester_t *tester);



#endif /*IKE_SA_MANAGER_TEST_H_*/
