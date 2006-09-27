/**
 * @file stream_logger.c
 *
 * @brief Implementation of stream_logger_t.
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

#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "stream_logger.h"


typedef struct private_stream_logger_t private_stream_logger_t;

/**
 * @brief Private data of a stream_logger_t object.
 */
struct private_stream_logger_t {
	
	/**
	 * Public data
	 */
	stream_logger_t public;
	
	/**
	 * Maximum level to log
	 */
	level_t max;
	
	/**
	 * stream to write log output to
	 */
	FILE *out;
};

/**
 * Implementation of bus_listener_t.signal.
 */
static void signal_(private_stream_logger_t *this, int thread,
					ike_sa_t* ike_sa, signal_t signal, level_t level,
					char *format, va_list args)
{
	FILE *o = this->out;
	
	flockfile(o);
	
	if (level <= this->max)
	{
		/* then print the info */
		switch (signal)
		{
			case SIG_IKE_UP:
			{
				if (level == LEV_SUCCESS)
				{
					fprintf(o, "established: %H[%D]...%H[%D]\n",
							ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
							ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
				}
				else
				{
					fprintf(o, "establishing failed: %H[%D]...%H[%D]:\n",
							ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
							ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
					fprintf(o, "  ");
					vfprintf(o, format, args);
					fprintf(o, "\n");
				}
				break;
			}
			case SIG_DBG_IKE:
			case SIG_DBG_CHD:
			case SIG_DBG_JOB:
			case SIG_DBG_CFG:
			case SIG_DBG_KNL:
			case SIG_DBG_NET:
			case SIG_DBG_ENC:
			{
				vfprintf(o, format, args);
				fprintf(o, "\n");
				break;
			}
			default:
				break;
		}
	}
	
	funlockfile(o);
}

/**
 * Implementation of stream_logger_t.set_level.
 */
static void set_level(private_stream_logger_t *this, signal_t signal, level_t max)
{
	this->max = max;
}

/**
 * Implementation of stream_logger_t.destroy.
 */
static void destroy(private_stream_logger_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
stream_logger_t *stream_logger_create(FILE *out)
{
	private_stream_logger_t *this = malloc_thing(private_stream_logger_t);
	
	/* public functions */
	this->public.listener.signal = (void(*)(bus_listener_t*,int,ike_sa_t*,signal_t,level_t,char*,va_list))signal_;
	this->public.set_level = (void(*)(stream_logger_t*,signal_t,level_t))set_level;
	this->public.destroy = (void(*)(stream_logger_t*))destroy;
	
	/* private variables */
	this->max = LEV_DBG4;
	this->out = out;
	
	return &this->public;
}
