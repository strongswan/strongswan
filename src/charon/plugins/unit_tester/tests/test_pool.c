/*
 * Copyright (C) 2008 Martin Willi
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

#include <time.h>
#include <pthread.h>

#include <library.h>

#define ALLOCS 1000
#define THREADS 20

static void* testing(void *thread)
{
	int i;
	host_t *addr[ALLOCS];
	identification_t *id[ALLOCS];

	/* prepare identities */
	for (i = 0; i < ALLOCS; i++)
	{
		char buf[256];

		snprintf(buf, sizeof(buf), "%d-%d@strongswan.org", (uintptr_t)thread, i);
		id[i] = identification_create_from_string(buf);
	}

	/* allocate addresses */
	for (i = 0; i < ALLOCS; i++)
	{
		addr[i] = lib->attributes->acquire_address(lib->attributes,
												   "test", id[i], NULL);
		if (!addr[i])
		{
			return (void*)FALSE;
		}
	}

	/* release addresses */
	for (i = 0; i < ALLOCS; i++)
	{
		lib->attributes->release_address(lib->attributes,
										 "test", addr[i], id[i]);
	}

	/* cleanup */
	for (i = 0; i < ALLOCS; i++)
	{
		addr[i]->destroy(addr[i]);
		id[i]->destroy(id[i]);
	}
	return (void*)TRUE;
}


/*******************************************************************************
 * SQL pool performance test
 ******************************************************************************/
bool test_pool()
{
	uintptr_t i;
	void *res;
	pthread_t thread[THREADS];

	for (i = 0; i < THREADS; i++)
	{
		if (pthread_create(&thread[i], NULL, (void*)testing, (void*)i) < 0)
		{
			return FALSE;
		}
	}
	for (i = 0; i < THREADS; i++)
	{
		pthread_join(thread[i], &res);
		if (res == NULL)
		{
			return FALSE;
		}
	}
	return TRUE;
}

