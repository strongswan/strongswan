/**
 * @file event_queue_test.h
 * 
 * @brief Tests to test the Event-Queue type event_queue_t
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
 
#ifndef EVENT_QUEUE_TEST_H_
#define EVENT_QUEUE_TEST_H_

#include "../tester.h"

/**
 * @brief Test function used to test the event_queue functionality
 * 
 * Tests are performed using one thread
 *
 * @param tester associated tester object
 */
void test_event_queue(tester_t *tester);

/**
 * Test for event_queue_t
 */
test_t event_queue_test = {test_event_queue,"Event-Queue Test"};

#endif /*EVENT_QUEUE_TEST_H_*/
