/*
 * Copyright (C) 2009 Martin Willi
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

#include <library.h>
#include <daemon.h>

#include <time.h>

static void start_timing(struct timespec *start)
{
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, start);
}

static double end_timing(struct timespec *start)
{
	struct timespec end;
	
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	return (end.tv_nsec - start->tv_nsec) / 1000000000.0 +
			(end.tv_sec - start->tv_sec) * 1.0;
}


/*******************************************************************************
 * public key sign/verify speed test
 ******************************************************************************/
bool test_dh_speed()
{
	struct {
		diffie_hellman_group_t group;
		int rounds;
	} groups[] = {
		{ MODP_768_BIT,  600},
		{ MODP_1024_BIT, 400},
		{ MODP_1536_BIT, 200},
		{ MODP_2048_BIT, 100},
		{ ECP_192_BIT,   800},
		{ ECP_224_BIT,   600},
		{ ECP_256_BIT,   400},
		{ ECP_384_BIT,   200},
		{ ECP_521_BIT,   100},
	};
	int group, round;
	
	for (group = 0; group < countof(groups); group++)
	{
		diffie_hellman_t *l[groups[group].rounds], *r;
		chunk_t chunk;
		struct timespec timing;
		
		r = lib->crypto->create_dh(lib->crypto, groups[group].group);
		if (!r)
		{
			DBG1(DBG_CFG, "skipping dh group %N, not supported",
				 diffie_hellman_group_names, groups[group].group);
			continue;
		}
		
		DBG1(DBG_CFG, "testing dh group %N:",
			 diffie_hellman_group_names, groups[group].group);
		
		start_timing(&timing);
		for (round = 0; round < groups[group].rounds; round++)
		{
			l[round] = lib->crypto->create_dh(lib->crypto, groups[group].group);
		}
		DBG1(DBG_CFG, "  %.0f A = g^a/s",
			 groups[group].rounds / end_timing(&timing));
		
		for (round = 0; round < groups[group].rounds; round++)
		{
			l[round]->get_my_public_value(l[round], &chunk);
			r->set_other_public_value(r, chunk);
			chunk_free(&chunk);
		}
		
		r->get_my_public_value(r, &chunk);
		start_timing(&timing);
		for (round = 0; round < groups[group].rounds; round++)
		{
			l[round]->set_other_public_value(l[round], chunk);
		}
		DBG1(DBG_CFG, "  %.0f S = B^a/s",
			 groups[group].rounds / end_timing(&timing));
		chunk_free(&chunk);
		
		for (round = 0; round < groups[group].rounds; round++)
		{
			l[round]->destroy(l[round]);
		}
		r->destroy(r);
	}
	return TRUE;
}

