/**
 * @file tests.h
 * 
 * @brief Lists all the tests to be processed by the tester object
 * 
 * New tests have to be added here!
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

#ifndef TESTS_H_
#define TESTS_H_

#include "../tester.h"
#include "linked_list_test.h"
#include "thread_pool_test.h"
#include "job_queue_test.h"
#include "event_queue_test.h"


/**
 * @brief these tests are getting performed by the tester
 */
test_t *tests[] ={
	&linked_list_test,
	&linked_list_iterator_test,
	&linked_list_insert_and_remove_test,
	&thread_pool_test,
	&job_queue_test1,
	&event_queue_test,
	NULL
};

#endif /*TESTS_H_*/
