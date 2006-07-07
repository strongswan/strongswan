/**
 * @file packet_test.h
 *
 * @brief Tests for the packet_t class.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#ifndef PACKET_TEST_H_
#define PACKET_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function used to test the packet_t functionality.
 *
 * @param tester 	associated protected_tester_t object
 * 
 * @ingroup testcases
 */
void test_packet(protected_tester_t *tester);

#endif /*PACKET_TEST_H_*/
