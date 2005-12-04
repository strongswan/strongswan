/**
 * @file logger.c
 * 
 * @brief Implementation of logger_t.
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

#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#include "logger.h"

#include <daemon.h>
#include <utils/allocator.h>

/**
 * Maximum length of al log entry (only used for logger_s.log)
 */
#define MAX_LOG 8192

typedef struct private_logger_t private_logger_t;

/**
 * @brief The logger object's private data.
 */
struct private_logger_t {
	/**
	 * Public data
	 */
	logger_t public;
	/**
	 * Detail-level of logger.
	 */
	logger_level_t level;
	/**
	 * Name of logger.
	 */
	char *name;
	/**
	 * File to write log output to.
	 * NULL for syslog.
	 */
	FILE *output;
	
	/**
	 * Should a thread_id be included in the log?
	 */
	bool log_thread_id;
	
	/**
	 * Applies a prefix to string and stores it in buffer.
	 * 
	 * @warning: buffer must be at least have MAX_LOG size.
	 */
	void (*prepend_prefix) (private_logger_t *this, logger_level_t loglevel, char *string, char *buffer);
};

/**
 * Implementation of private_logger_t.prepend_prefix.
 */
static void prepend_prefix(private_logger_t *this, logger_level_t loglevel, char *string, char *buffer)
{
	char log_type, log_details;
	if (loglevel & CONTROL)
	{
		log_type = '~';
	}
	else if (loglevel & ERROR)
	{
		log_type = '!';
	}
	else if (loglevel & RAW)
	{
		log_type = '#';
	}
	else if (loglevel & PRIVATE)
	{
		log_type = '?';
	}
	else
	{
		log_type = '-';
	}
	
	if (loglevel & (ALL - MOST))
	{
		log_details = '3';
	}
	else if (loglevel & (MOST - MORE))
	{
		log_details = '2';
	}
	else if (loglevel & MORE)
	{
		log_details = '1';
	}
	else
	{
		log_details = '0';
	}
	
	if (this->log_thread_id)
	{
		snprintf(buffer, MAX_LOG, "[%c%c] [%s] @%u %s", log_type, log_details, this->name, (int)pthread_self(), string);
	}
	else
	{
		snprintf(buffer, MAX_LOG, "[%c%c] [%s] %s", log_type, log_details, this->name, string);
	}
}

/**
 * Implementation of logger_t.log.
 *
 * Yes, logg is wrong written :-).
 */
static void logg(private_logger_t *this, logger_level_t loglevel, char *format, ...)
{
	if ((this->level & loglevel) == loglevel)
	{
		char buffer[MAX_LOG];
		va_list args;
		

		if (this->output == NULL)
		{
			/* syslog */
			this->prepend_prefix(this, loglevel, format, buffer);
			va_start(args, format);
			vsyslog(LOG_INFO, buffer, args);
			va_end(args);
		}
		else
		{
			/* File output */
			this->prepend_prefix(this, loglevel, format, buffer);
			va_start(args, format);
			vfprintf(this->output, buffer, args);
			va_end(args);
			fprintf(this->output, "\n");
		}

	}
}

/**
 * Implementation of logger_t.log_bytes.
 */
static void log_bytes(private_logger_t *this, logger_level_t loglevel, char *label, char *bytes, size_t len)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	
	/* since me can't do multi-line output to syslog, 
	 * we must do multiple syslogs. To avoid
	 * problems in output order, lock this by a mutex.
	 */
	pthread_mutex_lock(&mutex);
	
	if ((this->level & loglevel) == loglevel)
	{
		char buffer[MAX_LOG];
		char *format;
		char *buffer_pos;
		char *bytes_pos, *bytes_roof;
		int i;
		
		
		format = "%s (%d bytes)";
		this->prepend_prefix(this, loglevel, format, buffer);

		if (this->output == NULL)
		{
			syslog(LOG_INFO, buffer, label, len);	
		}
		else
		{
			fprintf(this->output, buffer, label, len);
			fprintf(this->output, "\n");
		}
	
		bytes_pos = bytes;
		bytes_roof = bytes + len;
		buffer_pos = buffer;

		for (i = 1; bytes_pos < bytes_roof; i++)
		{
			static char hexdig[] = "0123456789ABCDEF";
			*buffer_pos++ = hexdig[(*bytes_pos >> 4) & 0xF];
			*buffer_pos++ = hexdig[ *bytes_pos       & 0xF];
			if ((i % 16) == 0) 
			{
				*buffer_pos++ = '\0';
				buffer_pos = buffer;
				if (this->output == NULL)
				{
					syslog(LOG_INFO, "| %s", buffer);	
				}
				else
				{
					fprintf(this->output, "| %s\n", buffer);
				}
			}
			else if ((i % 8) == 0)
			{
				*buffer_pos++ = ' ';
				*buffer_pos++ = ' ';
				*buffer_pos++ = ' ';
			}
			else if ((i % 4) == 0)
			{
				*buffer_pos++ = ' ';
				*buffer_pos++ = ' ';
			}
			else 
			{	
				*buffer_pos++ = ' ';
			}
			
			bytes_pos++;
		}
		
		*buffer_pos++ = '\0';
		if (buffer_pos > buffer + 1)
		{
			buffer_pos = buffer;
			if (this->output == NULL)
			{		
				syslog(LOG_INFO, "| %s", buffer);
			}
			else
			{
				fprintf(this->output, "| %s\n", buffer);
			}
		}
	}
	pthread_mutex_unlock(&mutex);
}


/**
 * Implementation of logger_t.log_chunk.
 */
static void log_chunk(logger_t *this, logger_level_t loglevel, char *label, chunk_t *chunk)
{
	this->log_bytes(this, loglevel, label, chunk->ptr, chunk->len);
}


/**
 * Implementation of logger_t.enable_level.
 */
static void enable_level(private_logger_t *this, logger_level_t log_level)
{
	this->level |= log_level;
}

/**
 * Implementation of logger_t.disable_level.
 */
static void disable_level(private_logger_t *this, logger_level_t log_level)
{
	this->level &= ~log_level;
}

/**
 * Implementation of logger_t.destroy.
 */
static void destroy(private_logger_t *this)
{
	allocator_free(this->name);
	allocator_free(this);
}

/*
 * Described in header.
 */	
logger_t *logger_create(char *logger_name, logger_level_t log_level, bool log_thread_id, FILE * output)
{
	private_logger_t *this = allocator_alloc_thing(private_logger_t);
	
	if (logger_name == NULL)
	{
		logger_name = "";
	}
	
	this->public.log = (void(*)(logger_t*,logger_level_t,char*,...))logg;
	this->public.log_bytes = (void(*)(logger_t*, logger_level_t, char*,char*,size_t))log_bytes;
	this->public.log_chunk = log_chunk;
	this->public.enable_level = (void(*)(logger_t*,logger_level_t))enable_level;
	this->public.disable_level = (void(*)(logger_t*,logger_level_t))disable_level;
	this->public.destroy = (void(*)(logger_t*))destroy;

	this->prepend_prefix = prepend_prefix;

	/* private variables */
	this->level = log_level;
	this->log_thread_id = log_thread_id;
	this->name = allocator_alloc(strlen(logger_name) + 1);

	strcpy(this->name,logger_name);
	this->output = output;
	
	if (output == NULL)
	{
		openlog(DAEMON_NAME, 0, LOG_DAEMON);
	}
	
	return (logger_t*)this;
}
