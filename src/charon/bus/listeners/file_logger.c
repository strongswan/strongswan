/**
 * @file file_logger.c
 *
 * @brief Implementation of file_logger_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include <stdio.h>
#include <string.h>

#include "file_logger.h"


typedef struct private_file_logger_t private_file_logger_t;

/**
 * Private data of a file_logger_t object
 */
struct private_file_logger_t {
	
	/**
	 * Public data.
	 */
	file_logger_t public;
	
	/**
	 * output file
	 */
	FILE *out;
	
	/**
	 * Maximum level to log
	 */
	level_t levels[DBG_MAX];
};


/**
 * Implementation of bus_listener_t.signal.
 */
static bool signal_(private_file_logger_t *this, signal_t signal, level_t level,
					int thread, ike_sa_t* ike_sa, char *format, va_list args)
{
	if (level <= this->levels[SIG_TYPE(signal)])
	{
		char buffer[8192];
		char *current = buffer, *next;
		
		/* write in memory buffer first */
		vsnprintf(buffer, sizeof(buffer), format, args);
		
		/* prepend a prefix in front of every line */
		while (current)
		{
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			fprintf(this->out, "%.2d[%N] %s\n", thread, signal_names, signal, current);
			current = next;
		}
	}
	/* always stay registered */
	return TRUE;
}

/**
 * Implementation of file_logger_t.set_level.
 */
static void set_level(private_file_logger_t *this, signal_t signal, level_t level)
{
	if (signal == SIG_ANY)
	{
		int i;
		for (i = 0; i < DBG_MAX; i++)
		{
			this->levels[i] = level;
		}
	}
	else
	{
		
		this->levels[SIG_TYPE(signal)] = level;
	}
}

/**
 * Implementation of file_logger_t.destroy.
 */
static void destroy(private_file_logger_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
file_logger_t *file_logger_create(FILE *out)
{
	private_file_logger_t *this = malloc_thing(private_file_logger_t);
	
	/* public functions */
	this->public.listener.signal = (bool(*)(bus_listener_t*,signal_t,level_t,int,ike_sa_t*,char*,va_list))signal_;
	this->public.set_level = (void(*)(file_logger_t*,signal_t,level_t))set_level;
	this->public.destroy = (void(*)(file_logger_t*))destroy;
	
	/* private variables */
	this->out = out;
	set_level(this, SIG_ANY, LEVEL_SILENT);
	
	return &this->public;
}
