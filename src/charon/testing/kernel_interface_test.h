/**
 * @file kernel_interface_test.h
 * 
 * @brief Tests for the kernel_interface_t class.
 * 
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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
 
#ifndef KERNEL_INTERFACE_TEST_H_
#define KERNEL_INTERFACE_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function used to test the kernel_interface functionality.
 *
 * @param tester associated tester object
 * 
 * @ingroup testcases
 */
void test_kernel_interface(protected_tester_t *tester);

/**
 * @brief Test function used to test the kernel_interface functionality. Incldes NAT-T configuration.
 *
 * @param tester associated tester object
 *
 * @ingroup testcases
 */
void test_kernel_interface_with_nat(protected_tester_t *tester);

/**
 * @brief Test function used to test the hosts update functionality in kernel_interface_t.
 *
 * @param tester associated tester object
 *
 * @ingroup testcases
 */
void test_kernel_interface_update_hosts(protected_tester_t *tester);


#endif /*KERNEL_INTERFACE_TEST_H_*/
