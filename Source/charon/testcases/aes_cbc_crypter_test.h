/**
 * @file aes_cbc_crypter_test.h
 * 
 * @brief Tests for the aes_cbc_crypter_t class.
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

#ifndef _AES_CBC_CRYPTER_TEST_H_
#define _AES_CBC_CRYPTER_TEST_H_

#include <transforms/crypters/aes_cbc_crypter.h>
#include <utils/tester.h>

/**
 * @brief Test function used to test the aes_cbc_crypter_t class.
 *
 * @param tester associated tester object
 * 
 * @ingroup testcases
 */
void test_aes_cbc_crypter(tester_t *tester);

#endif //_AES_CBC_CRYPTER_TEST_H_
