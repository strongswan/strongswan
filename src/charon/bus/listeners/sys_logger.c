/**
 * @file sys_logger.c
 *
 * @brief Implementation of sys_logger_t.
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

/* for open_memstream() */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "sys_logger.h"

#include <bus/listeners/stream_logger.h>


typedef struct private_sys_logger_t private_sys_logger_t;

/**
 * Private data of a sys_logger_t object
 */
struct private_sys_logger_t {
	
	/**
	 * Public data.
	 */
	sys_logger_t public;
	
	/**
	 * syslog facility to use
	 */
	int facility;
	
	/**
	 * Internal used stream logger that does the dirty work
	 */
	stream_logger_t *logger;
	
	/**
	 * Memory stream used for stream_logger
	 */
	FILE *stream;
	
	/**
	 * Underlying buffer for stream
	 */
	char buffer[4096];
};


/**
 * Implementation of bus_listener_t.signal.
 */
static void signal_(private_sys_logger_t *this, int thread, ike_sa_t* ike_sa,
					signal_t signal, level_t level,
					char *format, va_list args)
{
	char line[512];
	char *prefix;
	FILE *reader;
	
	switch (signal)
	{
		case SIG_IKE_UP:
		case SIG_IKE_DOWN:
		case SIG_IKE_REKEY:
		case SIG_DBG_IKE:
			prefix = "IKE";
			break;
		case SIG_DBG_CHD:
			prefix = "CHD";
			break;
		case SIG_DBG_JOB:
			prefix = "JOG";
			break;
		case SIG_DBG_CFG:
			prefix = "CFG";
			break;
		case SIG_DBG_KNL:
			prefix = "KNL";
			break;
		case SIG_DBG_NET:
			prefix = "NET";
			break;
		case SIG_DBG_ENC:
			prefix = "ENC";
			break;
		default:
			prefix = "???";
			break;
	}
	
	flockfile(this->stream);
	/* reset memory stream */
	rewind(this->stream);
	memset(this->buffer, '\0', sizeof(this->buffer));
	/* log to memstream */
	this->logger->listener.signal(&this->logger->listener, thread, ike_sa,
								  signal, level, format, args);
	/* flush is needed to append a '\0' */
	fflush(this->stream);
	
	/* create a reader stream that reads out line by line */
	reader = fmemopen(this->buffer, sizeof(this->buffer), "r");
	
	while (fgets(line, sizeof(line), reader))
	{
		if (line[0] == '\0')
		{
			/* abort on EOF */
			break;
		}
		else if (line[0] != '\n')
		{
			syslog(this->facility|LOG_INFO, "%.2d[%s] %s", thread, prefix, line);
		}
	}
	fclose(reader);
	funlockfile(this->stream);
}

/**
 * Implementation of sys_logger_t.set_level.
 */
static void set_level(private_sys_logger_t *this, signal_t signal, level_t max)
{
	this->logger->set_level(this->logger, signal, max);
}

/**
 * Implementation of sys_logger_t.destroy.
 */
static void destroy(private_sys_logger_t *this)
{
	closelog();
	fclose(this->stream);
	this->logger->destroy(this->logger);
	free(this);
}

/*
 * Described in header.
 */
sys_logger_t *sys_logger_create(int facility)
{
	private_sys_logger_t *this = malloc_thing(private_sys_logger_t);
	
	/* public functions */
	this->public.listener.signal = (void(*)(bus_listener_t*,int,ike_sa_t*,signal_t,level_t,char*,va_list))signal_;
	this->public.set_level = (void(*)(sys_logger_t*,signal_t,level_t))set_level;
	this->public.destroy = (void(*)(sys_logger_t*))destroy;
	
	/* private variables */
	this->facility = facility;
	this->stream = fmemopen(this->buffer, sizeof(this->buffer), "w");
	if (this->stream == NULL)
	{
		/* fallback to stderr */
		this->stream = stderr;
	}
	this->logger = stream_logger_create(this->stream);
	
	return &this->public;
}
