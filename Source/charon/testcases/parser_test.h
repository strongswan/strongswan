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

#ifndef PARSER_TEST_H_
#define PARSER_TEST_H_

#include "../utils/tester.h"


void test_parser_with_header_payload(tester_t *tester);

void test_parser_with_sa_payload(tester_t *tester);



#endif /*PARSER_TEST_H_*/
