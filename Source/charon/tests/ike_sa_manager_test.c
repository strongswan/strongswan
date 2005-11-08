/**
 * @file ike_sa_manager_test.c
 * 
 * @brief Tests to test the IKE_SA-Manager type ike_sa_manager_t
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

#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "ike_sa_manager_test.h"
#include "../types.h"
#include "../tester.h"
#include "../ike_sa_manager.h"


static struct ike_sa_manager_test_struct_s {
	tester_t *tester;
	ike_sa_manager_t *isam;
} globals;

static void sa_blocker_thread(ike_sa_id_t *ike_sa_id)
{
	ike_sa_t *ike_sa;
	ike_sa_manager_t *isam;
	tester_t *tester;
	status_t status;
	
	isam = globals.isam;
	tester = globals.tester;
	status = isam->checkout_ike_sa(isam, ike_sa_id, &ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "checkout_ike_sa as blocker");
	sleep(1);
	status = isam->checkin_ike_sa(isam, ike_sa);
	
	
}

void test_ike_sa_manager(tester_t *tester)
{
	status_t status;
	spi_t initiator, responder;
	ike_sa_id_t *ike_sa_id;
	ike_sa_t *ike_sa;
	ike_sa_manager_t *isam;
	pthread_t threads[3];
	
	isam = ike_sa_manager_create();
	
	/* we play initiator for IKE_SA_INIT first */
	memset(&initiator, 0, sizeof(initiator));
	memset(&responder, 0, sizeof(responder));
	
	ike_sa_id = ike_sa_id_create(initiator, responder, INITIATOR);

	status = isam->checkout_ike_sa(isam, ike_sa_id, &ike_sa);
	
	tester->assert_true(tester, (status == SUCCESS), "checkout_ike_sa as initiator");
	pthread_create(&threads[0], NULL, (void*(*)(void*))sa_blocker_thread, (void*)ike_sa_id);
	
	
	status = isam->checkin_ike_sa(isam, ike_sa);
	
	pthread_join(threads[0], NULL);
	
	
	ike_sa_id->destroy(ike_sa_id);
	isam->destroy(isam);
}
