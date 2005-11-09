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



#include "logger.h"
#include "types.h"
#include "allocator.h"

#include <syslog.h>
#include <stdarg.h>



/**
 * @brief The logger object
 */
typedef struct private_logger_s private_logger_t;
struct private_logger_s { 	
	/**
	 * Public data
	 */
	logger_t public;
	/**
	 * fd to log, NULL for syslog
	 */
	FILE *target;
	/**
	 * detail-level of logger
	 */
	logger_level_t level;
	/**
	 * name of logger
	 */
	char *name;
};



static status_t logg(private_logger_t *this, logger_level_t loglevel, char *format, ...)
{
	if ((this->level & loglevel) == loglevel)
	{
		va_list args;
		va_start(args, format);
		
		if (this->target)
		{
			fprintf(this->target, format, args);
			fprintf(this->target, "\n");
		}
		else
		{
			syslog(LOG_INFO, format, args);
		}	
		va_end(args);	
	}
	
	
	return SUCCESS;
}
	
static status_t enable_level(private_logger_t *this, logger_level_t log_level)
{
	this->level |= log_level;
	return SUCCESS;
}
	
static status_t disable_level(private_logger_t *this, logger_level_t log_level)
{
	this->level &= (~log_level);
	return SUCCESS;
}
	
static status_t destroy(private_logger_t *this)
{
	if (this->target)
	{
		fclose(this->target);
	}
	allocator_free(this);
	return SUCCESS;
}


logger_t *logger_create(char *logger_name, char *file, logger_level_t log_level)
{
	private_logger_t *this = allocator_alloc_thing(private_logger_t);
		
	if (this == NULL)
	{
		return NULL;	
	}
	
	this->public.log = (status_t(*)(logger_t*,logger_level_t,char*,...))logg;
	this->public.enable_level = (status_t(*)(logger_t*,logger_level_t))enable_level;
	this->public.disable_level = (status_t(*)(logger_t*,logger_level_t))disable_level;
	this->public.destroy = (status_t(*)(logger_t*))destroy;

	this->level = log_level;
	this->name = logger_name;
	
	/* use system logger ? */
	if (file)
	{
		this->target = fopen(file, "a");
		if (this->target == NULL) 
		{
			allocator_free(this);
			return NULL;	
		}
	}
	else
	{
		this->target = NULL;
		openlog("charon", 0, LOG_DAEMON);
	}
	
	return (logger_t*)this;
}


