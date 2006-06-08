/**
 * @file kernel_interface_test.h
 * 
 * @brief Tests for the kernel_interface_t class.
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

#include <unistd.h>

#include "kernel_interface_test.h"

#include <daemon.h>
#include <threads/kernel_interface.h>
#include <utils/logger.h>
#include <utils/host.h>


/* 
 * described in Header-File
 */
void test_kernel_interface(protected_tester_t *tester)
{
	kernel_interface_t *kernel_interface;
	u_int32_t spi;
	host_t *me, *other, *left, *right;
	status_t status;
	
	u_int8_t enc_key_bytes[] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	
	u_int8_t inc_key_bytes[] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	
	chunk_t enc_key,inc_key;
	enc_key.ptr = enc_key_bytes;
	enc_key.len = sizeof(enc_key_bytes);
	inc_key.ptr = inc_key_bytes;
	inc_key.len = sizeof(inc_key_bytes);
	
	
	
	kernel_interface = kernel_interface_create();
	
	me = host_create(AF_INET, "192.168.0.2", 0);
	other = host_create(AF_INET, "192.168.0.3", 0);
	 
	status = kernel_interface->get_spi(kernel_interface, me, other, 50, 1234, &spi);
	tester->assert_true(tester, status == SUCCESS, "spi get");
	
	status = kernel_interface->add_sa(kernel_interface, me, other, spi, 50, 1234, 5, 10, ENCR_AES_CBC, enc_key,AUTH_UNDEFINED,inc_key,TRUE);	
	tester->assert_true(tester, status == SUCCESS, "add sa");
	
	left = host_create(AF_INET, "10.1.0.0", 0);
	right = host_create(AF_INET, "10.2.0.0", 0);
	
	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_OUT, 0, TRUE, FALSE, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy OUT");
	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_IN, 0, TRUE, FALSE, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy IN");
	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_FWD, 0, TRUE, FALSE, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy FWD");
	
	me->destroy(me);
	other->destroy(other);
	left->destroy(left);
	right->destroy(right);
	
	sleep(15);
	
	kernel_interface->destroy(kernel_interface);
	
}
