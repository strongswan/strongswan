/**
 * @file logger.h
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

#ifndef LOGGER_H_
#define LOGGER_H_

#include "types.h"

/**
 * Log Levels supported by the logger object
 */
typedef enum logger_level_e logger_level_t;

enum logger_level_e {
	/**
	 * basic control messages
	 */
	CONTROL = 1,
	/**
	 * detailed control messages
	 */
	CONTROL_MORE = 2,
	/**
	 * raw data dumps not containing private data
	 */
	RAW = 4,
	/**
	 * private data dumps
	 */
	PRIVATE = 8
};

/**
 * @brief The logger object
 */
typedef struct logger_s logger_t;
struct logger_s { 
	
	/**
	 * loggs an entry
	 * 
	 * function is used like printf
	 * 
	 * @param this logger_t-object
	 * @param loglevel loglevel of specific log entry
	 * @param format printf like format string
	 * @param ... printf like parameters 
	 * @return SUCCESS
	 */
	status_t (*log) (logger_t *this, logger_level_t log_level, char *format, ...);

	/**
	 * enables a loglevel for the current logger_t-object
	 * 
	 * @param this logger_t-object
	 * @param log_level loglevel to enable
	 * @return SUCCESS
	 */
	status_t (*enable_level) (logger_t *this, logger_level_t log_level);

	/**
	 * disables a loglevel for the current logger_t-object
	 * 
	 * @param this logger_t-object
	 * @param log_level loglevel to disable
	 * @return SUCCESS
	 */	
	status_t (*disable_level) (logger_t *this, logger_level_t log_level);
	
	/**
	 * @brief destroys a logger_t object
	 * 
	 * @param this logger_t object
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (logger_t *this);
};

/**
 * Constructor to create a logger_t-object
 * 
 * @param logger_name Name for the logger_t-object
 * @param file FILE pointer to write the log-messages to. If NULL
 * 		  syslogger is used.
 * @param log_level to assign to the new logger_t-object
 * @return logger_t-object or NULL if failed
 */
logger_t *logger_create(char *logger_name, char *file, logger_level_t log_level);

#endif /*LOGGER_H_*/

