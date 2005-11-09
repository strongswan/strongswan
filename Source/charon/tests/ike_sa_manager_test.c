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
} td;

static void successful_thread(ike_sa_id_t *ike_sa_id)
{
	ike_sa_t *ike_sa;
	status_t status;
	
	status = td.isam->checkout(td.isam, ike_sa_id, &ike_sa);
	td.tester->assert_true(td.tester, (status == SUCCESS), "checkout of a blocked ike_sa");
	usleep(10000);
	status = td.isam->checkin(td.isam, ike_sa);
	td.tester->assert_true(td.tester, (status == SUCCESS), "checkin of a requested ike_sa");
}

static void failed_thread(ike_sa_id_t *ike_sa_id)
{
	ike_sa_t *ike_sa;
	status_t status;
	
	status = td.isam->checkout(td.isam, ike_sa_id, &ike_sa);
	td.tester->assert_true(td.tester, (status == NOT_FOUND), "IKE_SA already deleted");
}

void test_ike_sa_manager(tester_t *tester)
{
	status_t status;
	spi_t initiator, responder;
	ike_sa_id_t *ike_sa_id;
	ike_sa_t *ike_sa;
	int thread_count = 200;
	int sa_count = 50;
	int i;
	pthread_t threads[thread_count];
	
	td.tester = tester;
	td.isam = ike_sa_manager_create();
	tester->assert_true(tester, (status == SUCCESS), "ike_sa_manager creation");
	
	
	
	
	
	/* First Test:
	 * we play initiator for IKE_SA_INIT first 
	 * create an IKE_SA, 
	 * 
	 */
	memset(&initiator, 0, sizeof(initiator));
	memset(&responder, 0, sizeof(responder));
	
	ike_sa_id = ike_sa_id_create(initiator, responder, INITIATOR);

	status = td.isam->checkout(td.isam, ike_sa_id, &ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "checkout unexisting IKE_SA");
	/* for testing purposes, we manipulate the responder spi.
	 * this is usually done be the response from the communication partner, 
	 * but we don't have one...
	 */
	ike_sa_id->destroy(ike_sa_id);
	ike_sa_id = ike_sa->get_id(ike_sa);
	responder.low = 123;
	ike_sa_id->set_responder_spi(ike_sa_id, responder);	
	/* check in, so we should have a "completed" sa, specified by ike_sa_id */
	status = td.isam->checkin(td.isam, ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "checkin modified IKE_SA");
	
	/* now we check it out and start some other threads */
	status = td.isam->checkout(td.isam, ike_sa_id, &ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "checkout existing IKE_SA 1");
	
	
	
	for (i = 0; i < thread_count; i++) 
	{
		if (pthread_create(&threads[i], NULL, (void*(*)(void*))successful_thread, (void*)ike_sa_id))
		{
			/* failed, decrease list */
			thread_count--;
			i--;	
		}
	}
	sleep(1);
	
	
	status = td.isam->checkin(td.isam, ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "checkin IKE_SA");
	
		
	sleep(1);
	/* we now delete the IKE_SA, while it is requested by the threads.
	 * this should block until the have done their work.*/
	status = td.isam->delete(td.isam, ike_sa_id);
	tester->assert_true(tester, (status == SUCCESS), "delete IKE_SA by id");


	for (i = 0; i < thread_count; i++) 
	{
		pthread_join(threads[i], NULL);
	}
	
	//ike_sa_id->destroy(ike_sa_id);
	
	
	
	
	
 	/* Second Test:
	 * now we simulate our partner initiates an IKE_SA_INIT,
	 * so we are the responder.
	 * 
	 */
	
	memset(&initiator, 0, sizeof(initiator));
	memset(&responder, 0, sizeof(responder));
	
	initiator.low = 123;
	ike_sa_id = ike_sa_id_create(initiator, responder, RESPONDER);
	
	status = td.isam->checkout(td.isam, ike_sa_id, &ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "checkout unexisting IKE_SA 2");
	for (i = 0; i < thread_count; i++) 
	{
		if (pthread_create(&threads[i], NULL, (void*(*)(void*))failed_thread, (void*)ike_sa_id))
		{
			/* failed, decrease list */
			thread_count--;
			i--;	
		}
	}
	/* let them go acquiring */
	sleep(1);
	
	/* this time, we delete the ike_sa while its checked out */
	td.isam->checkin_and_delete(td.isam, ike_sa);
	tester->assert_true(tester, (status == SUCCESS), "delete IKE_SA by SA");
	
	for (i = 0; i < thread_count; i++) 
	{
		pthread_join(threads[i], NULL);
	}
	
	//ike_sa_id->destroy(ike_sa_id);
	
	/* Third Test:
	 * put in a lot of IKE_SAs, check it out, set a thread waiting
	 * and destroy the manager...
	 */
		
	memset(&initiator, 0, sizeof(initiator));
	memset(&responder, 0, sizeof(responder));
	
	thread_count = sa_count;
	
	for (i = 0; i < sa_count; i++) 
	{
		initiator.low = i + 1;
		ike_sa_id = ike_sa_id_create(initiator, responder, RESPONDER);
		
		status = td.isam->checkout(td.isam, ike_sa_id, &ike_sa);
		tester->assert_true(tester, (status == SUCCESS), "checkout unexisting IKE_SA 3");

		if (pthread_create(&threads[i], NULL, (void*(*)(void*))failed_thread, (void*)ike_sa_id))
		{
			/* failed, decrease list */
			thread_count--;
		}
		//ike_sa_id->destroy(ike_sa_id);
	}
	
	/* let them go acquiring */
	sleep(1);
	
	status = td.isam->destroy(td.isam);
	tester->assert_true(tester, (status == SUCCESS), "ike_sa_manager destruction");
	
	for (i = 0; i < thread_count; i++) 
	{
		pthread_join(threads[i], NULL);
	}
	
}

