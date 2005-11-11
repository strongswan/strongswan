/**
 * @file logger.c
 * 
 * @brief Logger object, allows fine-controlled logging
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

#include "logger.h"
#include "daemon.h"
#include "types.h"
#include "allocator.h"

/**
 * Maximum length of al log entry (only used for logger_s.log)
 */
#define MAX_LOG 8192

/**
 * @brief The logger object.
 */
typedef struct private_logger_s private_logger_t;
struct private_logger_s { 	
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
	 * File to write log output to .
	 * NULL for syslog.
	 */
	FILE *output;
	
	/* private functions */
	/**
	 * Logs a message to the associated log file.
	 */
	void (*log_to_file) (private_logger_t *this, char *format, ...);
};

/**
 * Implements logger_t-function log.
 * @see logger_s.log.
 * 
 * Yes, logg is wrong written :-).
 */
static status_t logg(private_logger_t *this, logger_level_t loglevel, char *format, ...)
{
	if ((this->level & loglevel) == loglevel)
	{
		char buffer[MAX_LOG];
		va_list args;

		if (this->output == NULL)
		{
			/* syslog */
			snprintf(buffer, MAX_LOG, "%s: %s", this->name, format);
			va_start(args, format);
			vsyslog(LOG_INFO, buffer, args);
			va_end(args);
		}
		else
		{
			/* File output */
			snprintf(buffer, MAX_LOG, "File %s: %s", this->name, format);
			va_start(args, format);
			this->log_to_file(this, buffer, args);
			va_end(args);
		}

	}
	return SUCCESS;
}

/**
 * Implements private_logger_t-function log_to_file.
 * @see private_logger_s.log_to_file.
 */
static void log_to_file(private_logger_t *this,char *format, ...)
{
	char buffer[MAX_LOG];
	va_list args;
	time_t current_time;
	current_time = time(NULL);
			
	snprintf(buffer, MAX_LOG, "%s\n", format);
	va_start(args, format);
	vfprintf(this->output, buffer, args);
	va_end(args);
}

/**
 * Implements logger_t-function destroy.
 * @see logger_s.log_bytes.
 */
static status_t log_bytes(private_logger_t *this, logger_level_t loglevel, char *label, char *bytes, size_t len)
{
	if ((this->level & loglevel) == loglevel)
	{
		char buffer[64];
		char *buffer_pos;
		char *bytes_pos, *bytes_roof;
		int i;

		if (this->output == NULL)
		{
			syslog(LOG_INFO, "%s: %s (%d bytes)", this->name, label, len);	
		}else
		{
			this->log_to_file(this,"%s: %s (%d bytes)", this->name, label, len);
		}
	
		bytes_pos = bytes;
		bytes_roof = bytes + len;
		buffer_pos = buffer;

		for (i = 1; bytes_pos < bytes_roof; i++)
		{
			static const char hexdig[] = "0123456789ABCDEF";
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
					this->log_to_file(this, "| %s", buffer);
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
		buffer_pos = buffer;
		if (this->output == NULL)
		{		
			syslog(LOG_INFO, "| %s", buffer);
		}
		else
		{
			this->log_to_file(this, "| %s", buffer);
		}
	}

	return SUCCESS;
}


/**
 * Implements logger_t-function log_chunk.
 * @see logger_s.log_chunk.
 */
static status_t log_chunk(logger_t *this, logger_level_t loglevel, char *label, chunk_t *chunk)
{
	this->log_bytes(this, loglevel, label, chunk->ptr, chunk->len);
	return SUCCESS;
}


/**
 * Implements logger_t-function enable_level.
 * @see logger_s.enable_level.
 */
static status_t enable_level(private_logger_t *this, logger_level_t log_level)
{
	this->level |= log_level;
	return SUCCESS;
}

/**
 * Implements logger_t-function disable_level.
 * @see logger_s.disable_level.
 */
static status_t disable_level(private_logger_t *this, logger_level_t log_level)
{
	this->level &= ~log_level;
	return SUCCESS;
}

/**
 * Implements logger_t-function destroy.
 * @see logger_s.destroy.
 */
static status_t destroy(private_logger_t *this)
{
	allocator_free(this->name);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in Header
 */	
logger_t *logger_create(char *logger_name, logger_level_t log_level,FILE * output)
{
	private_logger_t *this = allocator_alloc_thing(private_logger_t);
		
	if (this == NULL)
	{
		return NULL;	
	}
	
	if (logger_name == NULL)
	{
		logger_name = "";
	}
	
	this->public.log = (status_t(*)(logger_t*,logger_level_t,char*,...))logg;
	this->public.log_bytes = (status_t(*)(logger_t*, logger_level_t, char*,char*,size_t))log_bytes;
	this->public.log_chunk = log_chunk;
	this->public.enable_level = (status_t(*)(logger_t*,logger_level_t))enable_level;
	this->public.disable_level = (status_t(*)(logger_t*,logger_level_t))disable_level;
	this->public.destroy = (status_t(*)(logger_t*))destroy;

	this->log_to_file = log_to_file;

	/* private variables */
	this->level = log_level;
	this->name = allocator_alloc(strlen(logger_name) + 1);
	if (this->name == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	strcpy(this->name,logger_name);
	this->output = output;

	
	if (output == NULL)
	{
		openlog(DEAMON_NAME, 0, LOG_DAEMON);
	}
	
	return (logger_t*)this;
}
