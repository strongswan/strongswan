/**
 * @file logger.c
 * 
 * @brief Implementation of logger_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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


/**
 * Maximum length of a log entry (only used for logger_s.log).
 */
#define MAX_LOG 8192

/**
 * Maximum number of logged bytes per line
 */
#define MAX_BYTES 16

typedef struct private_logger_t private_logger_t;

/**
 * @brief Private data of a logger_t object.
 */
struct private_logger_t {
	/**
	 * Public data.
	 */
	logger_t public;
	/**
	 * Detail-level of logger.
	 */
	log_level_t level;
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
};

/**
 * thread local storage for get_thread_number
 */
static pthread_key_t thread_ids;
static void make_key(void)
{
	pthread_key_create(&thread_ids, NULL);
}

/**
 * Get a unique thread number for a calling thread. Since
 * pthread_self returns large and ugly numbers, use this function
 * for logging; these numbers are incremental starting at 1
 */
static int get_thread_number(void)
{
	static int current_num = 0;
	static pthread_once_t key_once = PTHREAD_ONCE_INIT;
	int stored_num;
	
	pthread_once(&key_once, make_key);
	stored_num = (int)pthread_getspecific(thread_ids);
	if (stored_num == 0)
	{
		pthread_setspecific(thread_ids, (void*)++current_num);
		return current_num;
	}
	else
	{
		return stored_num;
	}
}

/**
 * prepend the logging prefix to string and store it in buffer
 */
static void prepend_prefix(private_logger_t *this, log_level_t loglevel, const char *string, char *buffer)
{
	char thread_id[3] = "";
	char log_type, log_details;
	char *separator = (strlen(this->name) == 0)? "" : ":";

	if (loglevel & CONTROL)
	{
		log_type = 'C';
	}
	else if (loglevel & ERROR)
	{
		log_type = 'E';
	}
	else if (loglevel & RAW)
	{
		log_type = 'R';
	}
	else if (loglevel & PRIVATE)
	{
		log_type = 'P';
	}
	else if (loglevel & AUDIT)
	{
		log_type = 'A';
	}
	else
	{
		log_type = '-';
	}
	
	if (loglevel & (LEVEL3 - LEVEL2))
	{
		log_details = '3';
	}
	else if (loglevel & (LEVEL2 - LEVEL1))
	{
		log_details = '2';
	}
	else if (loglevel & LEVEL1)
	{
		log_details = '1';
	}
	else
	{
		log_details = '0';
	}
	
	if (this->log_thread_id)
	{
		snprintf(thread_id, sizeof(thread_id), "%02d", get_thread_number());
	}
	snprintf(buffer, MAX_LOG, "%s[%c%c%s%s] %s",
			 thread_id, log_type, log_details, separator, this->name, string);
}

/**
 * Convert a charon-loglevel to a syslog priority
 */
static int get_priority(log_level_t loglevel)
{
	if (loglevel & ERROR)
	{
		return LOG_AUTHPRIV|LOG_ERR;
	}
	if (loglevel & AUDIT)
	{
		return LOG_AUTHPRIV|LOG_INFO;
	}
	return LOG_AUTHPRIV|LOG_DEBUG;
}

/**
 * Implementation of logger_t.log.
 *
 * Yes, logg is written wrong :-).
 */
static void logg(private_logger_t *this, log_level_t loglevel, const char *format, ...)
{
	if ((this->level & loglevel) == loglevel)
	{
		char buffer[MAX_LOG];
		va_list args;
		

		if (this->output == NULL)
		{
			/* syslog */
			prepend_prefix(this, loglevel, format, buffer);
			va_start(args, format);
			vsyslog(get_priority(loglevel), buffer, args);
			va_end(args);
		}
		else
		{
			/* File output */
			prepend_prefix(this, loglevel, format, buffer);
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
static void log_bytes(private_logger_t *this, log_level_t loglevel, const char *label, const char *bytes, size_t len)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	if ((this->level & loglevel) == loglevel)
	{
		char thread_id[3] = "";
		char buffer[MAX_LOG];
		char ascii_buffer[MAX_BYTES+1];

		char *buffer_pos = buffer;
		const char format[] = "%s  %d bytes @ %p";
		const char *bytes_pos  = bytes;
		const char *bytes_roof = bytes + len;

		int line_start = 0;
		int i = 0;

		/* since me can't do multi-line output to syslog, 
		* we must do multiple syslogs. To avoid
		* problems in output order, lock this by a mutex.
		*/
		pthread_mutex_lock(&mutex);

		prepend_prefix(this, loglevel, format, buffer);
		
		if (this->log_thread_id)
		{
			snprintf(thread_id, sizeof(thread_id), "%02d", get_thread_number());
		}

		if (this->output == NULL)
		{
			syslog(get_priority(loglevel), buffer, label, len, bytes);
		}
		else
		{
			fprintf(this->output, buffer, label, len, bytes);
			fprintf(this->output, "\n");
		}

		while (bytes_pos < bytes_roof)
		{
			static char hexdig[] = "0123456789ABCDEF";

			*buffer_pos++ = hexdig[(*bytes_pos >> 4) & 0xF];
			*buffer_pos++ = hexdig[ *bytes_pos       & 0xF];

			ascii_buffer[i++] = (*bytes_pos > 31 && *bytes_pos < 127)
				? *bytes_pos : '.';

			if (++bytes_pos == bytes_roof || i == MAX_BYTES) 
			{
				int padding = 3 * (MAX_BYTES - i);

				while (padding--)
				{
					*buffer_pos++ = ' ';
				}
				*buffer_pos++ = '\0';
				ascii_buffer[i] = '\0';

				if (this->output == NULL)
				{
					syslog(get_priority(loglevel), "%s[  :%5d]   %s  %s", thread_id, line_start, buffer, ascii_buffer);	
				}
				else
				{
					fprintf(this->output, "%s[  :%5d]   %s  %s\n", thread_id, line_start, buffer, ascii_buffer);
				}
				buffer_pos = buffer;
				line_start += MAX_BYTES;
				i = 0;
			}
			else 
			{	
				*buffer_pos++ = ' ';
			}
		}
		pthread_mutex_unlock(&mutex);
	}
}

/**
 * Implementation of logger_t.log_chunk.
 */
static void log_chunk(logger_t *this, log_level_t loglevel, const char *label, chunk_t chunk)
{
	this->log_bytes(this, loglevel, label, chunk.ptr, chunk.len);
}

/**
 * Implementation of logger_t.enable_level.
 */
static void enable_level(private_logger_t *this, log_level_t log_level)
{
	this->level |= log_level;
}

/**
 * Implementation of logger_t.disable_level.
 */
static void disable_level(private_logger_t *this, log_level_t log_level)
{
	this->level &= ~log_level;
}

/**
 * Implementation of logger_t.set_output.
 */
static void set_output(private_logger_t *this, FILE * output)
{
	this->output = output;
}

/**
 * Implementation of logger_t.get_level.
 */
static log_level_t get_level(private_logger_t *this)
{
	return this->level;
}

/**
 * Implementation of logger_t.destroy.
 */
static void destroy(private_logger_t *this)
{
	free(this->name);
	free(this);
}

/*
 * Described in header.
 */	
logger_t *logger_create(char *logger_name, log_level_t log_level, bool log_thread_id, FILE * output)
{
	private_logger_t *this = malloc_thing(private_logger_t);
	
	/* public functions */
	this->public.log = (void(*)(logger_t*,log_level_t,const char*,...))logg;
	this->public.log_bytes = (void(*)(logger_t*, log_level_t, const char*, const char*,size_t))log_bytes;
	this->public.log_chunk = log_chunk;
	this->public.enable_level = (void(*)(logger_t*,log_level_t))enable_level;
	this->public.disable_level = (void(*)(logger_t*,log_level_t))disable_level;
	this->public.get_level = (log_level_t(*)(logger_t*))get_level;
	this->public.set_output = (void(*)(logger_t*,FILE*))set_output;
	this->public.destroy = (void(*)(logger_t*))destroy;

	if (logger_name == NULL)
	{
		logger_name = "";
	}

	/* private variables */
	this->level = log_level;
	this->log_thread_id = log_thread_id;
	this->name = malloc(strlen(logger_name) + 1);

	strcpy(this->name,logger_name);
	this->output = output;
	
	return (logger_t*)this;
}
