/**
 * @file eap_sim.h
 *
 * @brief Interface of eap_sim_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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
#include <stdio.h>
#include <errno.h>

#include <daemon.h>

#define IMSI_LEN 64
#define RAND_LEN 16
#define SRES_LEN 4
#define KC_LEN 8

typedef struct triplet_t triplet_t;

struct triplet_t {
	unsigned char imsi[IMSI_LEN];
	unsigned char rand[RAND_LEN];
	unsigned char sres[SRES_LEN];
	unsigned char kc[KC_LEN];
};

static triplet_t *triplets = NULL;
static int triplet_count = 0;

#define TRIPLET_FILE IPSEC_CONFDIR "/ipsec.d/triplets.dat"

/**
 * convert a single HEX char to its integer value
 */
static int hexchr(char chr)
{
	switch (chr)
	{
		case '0'...'9':
			return chr - '0';
		case 'A'...'F':
			return 10 + chr - 'A';
		case 'a'...'f':
			return 10 + chr - 'a';
	}
	return 0;
}

/**
 * convert a HEX string into a char array bin, limited by array length len
 */
static void hex2bin(char *hex, unsigned char *bin, size_t len)
{
	char *pos;
	int i, even = 1;
	
	pos = hex - 1;
	/* find the end, as we convert bottom up */
	while (TRUE)
	{
		switch (*(pos+1))
		{
			case '0'...'9':
			case 'A'...'F':
			case 'a'...'f':
				pos++;
				continue;
		}
		break;
	}
	/* convert two hex chars into a single bin byte */
	for (i = 0; pos >= hex && i < len; pos--)
	{
		if (even)
		{
			bin[len - 1 - i] = hexchr(*pos);
		}
		else
		{
			bin[len - 1 - i] |= 16 * hexchr(*pos);
			i++;
		}
		even = !even;
	}
}

/**
 * free up allocated triplets
 */
static void __attribute__ ((destructor)) free_triplets()
{
	free(triplets);
}

/**
 * read the triplets from the file, using freeradius triplet file syntax:
 * http://www.freeradius.org/radiusd/doc/rlm_sim_triplets
 */
static void __attribute__ ((constructor)) read_triplets()
{
	char line[512], *data[4], *pos;
	FILE *file;
	int i, nr = 0;
	triplet_t *triplet;
	
	file = fopen(TRIPLET_FILE, "r");
	if (file == NULL)
	{
		DBG1(DBG_CFG, "opening triplet file %s failed: %s",
			 TRIPLET_FILE, strerror(errno));
		return;
	}
	
	if (triplets)
	{
		free(triplets);
		triplets = NULL;
		triplet_count = 0;
	}
	
	/* read line by line */
	while (fgets(line, sizeof(line), file))
	{
		nr++;
		/* skip comments, empty lines */
		switch (line[0])
		{
			case '\n':
			case '\r':
			case '#':
			case '\0':
				continue;
			default:
				break;
		}
		/* read comma separated values */
		pos = line;
		for (i = 0; i < 4; i++)
		{
			data[i] = pos;
			pos = strchr(pos, ',');
			if (pos)
			{
				*pos = '\0';
				pos++;
			}
			else if (i != 3)
			{
				DBG1(DBG_CFG, "error in triplet file, line %d", nr);
				fclose(file);
				return;
			}
		}
		/* allocate new triplet */
		triplet_count++;
		triplets = realloc(triplets, triplet_count * sizeof(triplet_t));
		triplet = &triplets[triplet_count - 1];
		memset(triplet, 0, sizeof(triplet_t));
		
		/* convert/copy triplet data */
		for (i = 0; i < IMSI_LEN - 1; i++)
		{
			switch (data[0][i])
			{
				case '\n':
				case '\r':
				case '\0':
					break;
				default:
					triplet->imsi[i] = data[0][i];
					continue;
			}
			break;
		}
		hex2bin(data[1], triplet->rand, RAND_LEN);
		hex2bin(data[2], triplet->sres, SRES_LEN);
		hex2bin(data[3], triplet->kc, KC_LEN);
		
		DBG4(DBG_CFG, "triplet: imsi %b\nrand %b\nsres %b\nkc %b",
			 triplet->imsi, IMSI_LEN, triplet->rand, RAND_LEN,
			 triplet->sres, SRES_LEN, triplet->kc, KC_LEN);
	}
	fclose(file);
	DBG2(DBG_CFG, "read %d triplets from %s", triplet_count, TRIPLET_FILE);
}

/**
 * Run the sim algorithm, see eap_sim.h
 */
int sim_run_alg(const unsigned char *rand, int rand_length,
				unsigned char *sres, int *sres_length, 
				unsigned char *kc, int *kc_length)
{
	int current;
	
	if (rand_length != RAND_LEN ||
		*sres_length < SRES_LEN ||
		*kc_length < KC_LEN)
	{
		return 1;
	}
	
	for (current = 0; current < triplet_count; current++)
	{
		if (memcmp(triplets[current].rand, rand, RAND_LEN) == 0)
		{
			memcpy(sres, triplets[current].sres, SRES_LEN);
			memcpy(kc, triplets[current].kc, KC_LEN);
			*sres_length = SRES_LEN;
			*kc_length = KC_LEN;
			return 0;
		}
	}
	return 2;
}

/**
 * Get a single triplet, see_eap_sim.h
 */
int sim_get_triplet(char *imsi,
					unsigned char *rand, int *rand_length,
					unsigned char *sres, int *sres_length, 
					unsigned char *kc, int *kc_length)
{
	int current;
	triplet_t *triplet;
	static int skip = -1;
	
	DBG2(DBG_CFG, "getting triplet for %s", imsi);
	
	if (*rand_length < RAND_LEN ||
		*sres_length < SRES_LEN ||
		*kc_length < KC_LEN)
	{
		return 1;
	}
	if (triplet_count == 0)
	{
		return 2;
	}
	for (current = 0; current < triplet_count; current++)
	{
		triplet = &triplets[current];
	
		if (streq(imsi, triplet->imsi))
		{
			/* skip triplet if already used */
			if (skip >= current)
			{
				continue;
			}
			*rand_length = RAND_LEN;
			*sres_length = SRES_LEN;
			*kc_length = KC_LEN;
			memcpy(rand, triplet->rand, RAND_LEN);
			memcpy(sres, triplet->sres, SRES_LEN);
			memcpy(kc, triplet->kc, KC_LEN);
			/* remember used triplet */
			skip = current;
			return 0;
		}
	}
	if (skip > -1)
	{
		/* no triplet left, reuse triplets */
		skip = -1;
		return sim_get_triplet(imsi, rand, rand_length,
							   sres, sres_length, kc, kc_length);
	}
	return 2;
}

