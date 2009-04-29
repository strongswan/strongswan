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

#include <daemon.h>
#include <library.h>
#include <utils/mutex.h>

#include <unistd.h>
#include <sched.h>
#include <pthread.h>

static bool test_monobit(chunk_t data)
{
	int i, j, bits = 0;
	
	for (i = 0; i < data.len; i++)
	{
		for (j = 0; j < 8; j++)
		{
			if (data.ptr[i] & (1<<j))
			{
				bits++;
			}
		}
	}
	DBG1(DBG_CFG, "  Monobit: %d/%d bits set", bits, data.len * 8);
	if (bits > 9654 && bits < 10346)
	{
		return TRUE;
	}
	return FALSE;
}

static bool test_poker(chunk_t data)
{
	int i, counter[16];
	double sum = 0.0;
	
	memset(counter, 0, sizeof(counter));
	
	for (i = 0; i < data.len; i++)
	{
		counter[data.ptr[i] & 0x0F]++;
		counter[(data.ptr[i] & 0xF0) >> 4]++;
	}
	
	for (i = 0; i < countof(counter); i++)
	{
		sum += (counter[i] * counter[i]) / 5000.0 * 16.0;
	}
	sum -= 5000.0;
	DBG1(DBG_CFG, "  Poker: %f", sum);
	if (sum > 1.03 && sum < 57.4)
	{
		return TRUE;
	}
	return FALSE;
}

static bool test_runs(chunk_t data)
{
	int i, j, zero_runs[7], one_runs[7], zero = 0, one = 0, longrun = 0;
	bool ok = TRUE;
	
	memset(one_runs, 0, sizeof(zero_runs));
	memset(zero_runs, 0, sizeof(one_runs));
	
	for (i = 0; i < data.len; i++)
	{
		for (j = 0; j < 8; j++)
		{
			if (data.ptr[i] & (1<<j))
			{
				if (one)
				{
					if (++one >= 34)
					{
						longrun++;
						break;
					}
				}
				else
				{
					zero_runs[min(6, zero)]++;
					zero = 0;
					one = 1;
				}
			}
			else
			{
				if (zero)
				{
					if (++zero >= 34)
					{
						longrun++;
						break;
					}
				}
				else
				{
					one_runs[min(6, one)]++;
					one = 0;
					zero = 1;
				}
			}
		}
	}
	
	DBG1(DBG_CFG, "  Runs: zero: %d/%d/%d/%d/%d/%d, one: %d/%d/%d/%d/%d/%d, "
		 "longruns: %d",
		 zero_runs[1], zero_runs[2], zero_runs[3],
		 zero_runs[4], zero_runs[5], zero_runs[6],
		 one_runs[1], one_runs[2], one_runs[3],
		 one_runs[4], one_runs[5], one_runs[6],
		 longrun);
	
	if (longrun)
	{
		return FALSE;
	}
	
	for (i = 1; i < countof(zero_runs); i++)
	{
		switch (i)
		{
			case 1:
				ok &= zero_runs[i] > 2267 && zero_runs[i] < 2733;
				ok &= one_runs[i] > 2267 && one_runs[i] < 2733;
				break;
			case 2:
				ok &= zero_runs[i] > 1079 && zero_runs[i] < 1421;
				ok &= one_runs[i] > 1079 && one_runs[i] < 1421;
				break;
			case 3:
				ok &= zero_runs[i] > 502 && zero_runs[i] < 748;
				ok &= one_runs[i] > 502 && one_runs[i] < 748;
				break;
			case 4:
				ok &= zero_runs[i] > 223 && zero_runs[i] < 402;
				ok &= one_runs[i] > 223 && one_runs[i] < 402;
				break;
			case 5:
				ok &= zero_runs[i] > 90 && zero_runs[i] < 223;
				ok &= one_runs[i] > 90 && one_runs[i] < 223;
				break;
			case 6:
				ok &= zero_runs[i] > 90 && zero_runs[i] < 223;
				ok &= one_runs[i] > 90 && one_runs[i] < 223;
				break;
		}
		if (!ok)
		{
			return FALSE;
		}
	}
	return TRUE;
}

static bool test_rng_quality(rng_quality_t quality)
{
	rng_t *rng;
	chunk_t chunk;
	
	rng = lib->crypto->create_rng(lib->crypto, quality);
	if (!rng)
	{
		return FALSE;
	}
	DBG1(DBG_CFG, "%N", rng_quality_names, quality);
	rng->allocate_bytes(rng, 2500, &chunk);
	
	if (!test_monobit(chunk))
	{
		return FALSE;
	}
	if (!test_poker(chunk))
	{
		return FALSE;
	}
	if (!test_runs(chunk))
	{
		return FALSE;
	}
	
	free(chunk.ptr);
	rng->destroy(rng);
	return TRUE;
}

/**
 * run a test using given values
 */
bool test_rng()
{
	if (!test_rng_quality(RNG_WEAK))
	{
		return FALSE;
	}
	if (!test_rng_quality(RNG_STRONG))
	{
		return FALSE;
	}
	if (!test_rng_quality(RNG_TRUE))
	{
		return FALSE;
	}
	return TRUE; 
}

