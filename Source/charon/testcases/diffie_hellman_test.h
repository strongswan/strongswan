/**
 * @file diffie_hellman_test.h
 * 
 * @brief Tests to test the Diffie Hellman object diffie_hellman_t
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

#ifndef DIFFIE_HELLMAN_TEST_H_
#define DIFFIE_HELLMAN_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function used to test the diffie_hellman_t functionality
 * 
 * Tests are performed using one thread
 *
 * @param tester associated tester object
 */
void test_diffie_hellman(tester_t *tester);

#endif /*DIFFIE_HELLMAN_TEST_H_*/
