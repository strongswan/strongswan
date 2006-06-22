/**
 * @file kernel_interface_test.h
 * 
 * @brief Tests for the kernel_interface_t class.
 * 
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

 
#include "kernel_interface_test.h"

#include <daemon.h>
#include <threads/kernel_interface.h>
#include <utils/logger.h>
#include <utils/host.h>


/**
 * @brief private method to test kernel_interface with optional NAT-T configuration data
 */
 void private_test_kernel_interface(protected_tester_t *tester, natt_conf_t *natt)
{
	kernel_interface_t *kernel_interface;
	u_int32_t spi;
	host_t *me, *other, *left, *right;
	status_t status;
	prf_plus_t *prf_plus;
	prf_t *prf;
	u_int8_t key_bytes[] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	chunk_t key = chunk_from_buf(key_bytes);
	algorithm_t int_alg = {AUTH_HMAC_MD5_96, 0};
	algorithm_t enc_alg = {ENCR_AES_CBC, 128};
	
	prf = prf_create(PRF_HMAC_MD5);
	prf->set_key(prf, key);
	prf_plus = prf_plus_create(prf, key);


	kernel_interface = kernel_interface_create();
	
	me = host_create(AF_INET, "192.168.0.2", 0);
	other = host_create(AF_INET, "192.168.0.3", 0);

	status = kernel_interface->get_spi(kernel_interface, me, other, PROTO_ESP, 1234, &spi);
	tester->assert_true(tester, status == SUCCESS, "spi get");

	status = kernel_interface->add_sa(kernel_interface, me, other, spi, PROTO_ESP, 1234, 5, 10, &enc_alg, &int_alg, prf_plus, natt, TRUE);
	tester->assert_true(tester, status == SUCCESS, "add sa");

	left = host_create(AF_INET, "10.1.0.0", 0);
	right = host_create(AF_INET, "10.2.0.0", 0);

	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_OUT, 0, PROTO_ESP, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy");
	
	status = kernel_interface->del_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_OUT, 0);
	tester->assert_true(tester, status == SUCCESS, "del policy");

	status = kernel_interface->del_sa(kernel_interface, other, spi, PROTO_ESP);
	tester->assert_true(tester, status == SUCCESS, "del sa");

	me->destroy(me);
	other->destroy(other);
	left->destroy(left);
	right->destroy(right);

	kernel_interface->destroy(kernel_interface);
}

/* 
 * described in Header-File
 */
void test_kernel_interface(protected_tester_t *tester)
{
	private_test_kernel_interface(tester, NULL);
}

/*
 * described in Header-File
 */
void test_kernel_interface_with_nat(protected_tester_t *tester)
{
	natt_conf_t natt;
	natt.sport = 4500;
	natt.dport = 9876;
	
	private_test_kernel_interface(tester, &natt);
}

void test_kernel_interface_update_hosts(protected_tester_t *tester)
{
	kernel_interface_t *kernel_interface;
	u_int32_t spi;
	host_t *me, *other, *new_me, *new_other, *left, *right;
	status_t status;
	prf_plus_t *prf_plus;
	prf_t *prf;
	u_int8_t key_bytes[] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	chunk_t key = chunk_from_buf(key_bytes);
	algorithm_t int_alg = {AUTH_HMAC_MD5_96, 0};
	algorithm_t enc_alg = {ENCR_AES_CBC, 128};
	
	prf = prf_create(PRF_HMAC_MD5);
	prf->set_key(prf, key);
	prf_plus = prf_plus_create(prf, key);

	kernel_interface = kernel_interface_create();
	
	me = host_create(AF_INET, "192.168.0.2", 0);
	other = host_create(AF_INET, "192.168.0.3", 0);

	natt_conf_t natt;
	natt.sport = 4500;
	natt.dport = 9876;

	status = kernel_interface->get_spi(kernel_interface, me, other, PROTO_ESP, 1234, &spi);
	tester->assert_true(tester, status == SUCCESS, "spi get");
	
	status = kernel_interface->add_sa(kernel_interface, me, other, spi, PROTO_ESP, 1234, 5, 10, &enc_alg, &int_alg, prf_plus, &natt, TRUE);
	tester->assert_true(tester, status == SUCCESS, "add sa");

	left = host_create(AF_INET, "10.1.0.0", 0);
	right = host_create(AF_INET, "10.2.0.0", 0);

	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_OUT, 0, PROTO_ESP, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy OUT");
	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_IN, 0, PROTO_ESP, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy IN");
	status = kernel_interface->add_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_FWD, 0, PROTO_ESP, 1234);
	tester->assert_true(tester, status == SUCCESS, "add policy FWD");

	new_me = host_create(AF_INET, "192.168.1.12", 4500);
	new_other = host_create(AF_INET, "192.168.1.13", 6543);
	
	status = kernel_interface->update_sa_hosts(kernel_interface, me, other, new_me, new_other, me->get_differences(me, new_me), other->get_differences(other, new_other), spi, PROTO_ESP);
	tester->assert_true(tester, status == SUCCESS, "update hosts on sa");
	
	status = kernel_interface->del_policy(kernel_interface, me, other, left, right, 16, 16, XFRM_POLICY_OUT, 0);
	tester->assert_true(tester, status == SUCCESS, "del policy");

	status = kernel_interface->del_sa(kernel_interface, other, spi, PROTO_ESP);
	tester->assert_true(tester, status == SUCCESS, "del sa");

	me->destroy(me);
	other->destroy(other);
	new_me->destroy(new_me);
	new_other->destroy(new_other);
	left->destroy(left);
	right->destroy(right);

	sleep(15);
	
	kernel_interface->destroy(kernel_interface);
}
