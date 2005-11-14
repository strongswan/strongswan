/**
 * @file generator.h
 * 
 * @brief Tests to test the Generator class generator_t
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

#include "../utils/tester.h"

/**
 * @brief Test function used to test the generator with header payload
 * 
 *
 * @param tester associated tester object
 */
void test_generator_with_header_payload(tester_t *tester);

/**
 * @brief Test function used to test the generator with transform attribute payload
 * 
 *
 * @param tester associated tester object
 */
void test_generator_with_transform_attribute(tester_t *tester);

#endif /*GENERATOR_TEST_H_*/
