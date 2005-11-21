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

#include <stdio.h>
#include "../types.h"

/**
 * @brief Log Levels supported by the logger object
 * 
 * Logleves are devided in two types:
 * - One to specify the type log
 * - One to specify the detail-level of the log
 * Use combinations of these to build detailed loglevels, such
 * as CONTROL|MORE fore a detailed cotrol level, or
 * use RAW| to see all raw data dumps (except private)
 */
typedef enum logger_level_e logger_level_t;
enum logger_level_e {
	/**
	 * control flow
	 */
	CONTROL = 1,
	/**
	 * error reporting
	 */
	ERROR = 2,
	/**
	 * raw data dumps
	 */
	RAW = 4,
	/**
	 * private data dumps
	 */
	PRIVATE = 8,
	
	/**
	 * use more detailed output for those above
	 */
	MORE = 16, 
	/**
	 * use even more detailed output
	 */
	MOST = MORE + 32,
	/**
	 * use full detailed output
	 */
	ALL = MOST + 64,
	
	/**
	 * Summary for all types with all detail-levels
	 */
	FULL = ALL + CONTROL + ERROR + RAW + PRIVATE
};

/**
 * @brief The logger object
 */
typedef struct logger_s logger_t;
struct logger_s {

	/**
	 * @brief Log an entry, using printf()-like params.
	 *
	 * The specefied loglevels must ALL be activated that
	 * the log is done.
	 *
	 * @param this 		logger_t object
	 * @param loglevel 	or'ed set of loglevels
	 * @param format 	printf like format string
	 * @param ... 		printf like parameters
	 * @return
	 * 					- SUCCESS in any case
	 */
	status_t (*log) (logger_t *this, logger_level_t log_level, char *format, ...);

	/**
	 * @brief Log some bytes, useful for debugging.
	 *
	 * The specefied loglevels must ALL be activated that
	 * the log is done.
	 *
	 * @param this 		logger_t object
	 * @param loglevel 	or'ed set of loglevels
	 * @param label 	a labeling name, logged with the bytes
	 * @param bytes 	pointer to the bytes to dump
	 * @param len	 	number of bytes to dump
	 * @return
	 * 					- SUCCESS in any case
	 */
	status_t (*log_bytes) (logger_t *this, logger_level_t loglevel, char *label, char *bytes, size_t len);

	/**
	 * @brief Log a chunk, useful for debugging.
	 *
	 * The specefied loglevels must ALL be activated that
	 * the log is done.
	 *
	 * @param this 		logger_t object
	 * @param loglevel 	or'ed set of loglevels
	 * @param label 	a labeling name, logged with the bytes
	 * @param chunk		pointer to a chunk to log
	 * @return
	 * 					- SUCCESS in any case
	 */
	status_t (*log_chunk) (logger_t *this, logger_level_t loglevel, char *label, chunk_t *chunk);

	/**
	 * @brief Enables a loglevel for the current logger_t object.
	 *
	 * @param 			this logger_t object
	 * @param 			log_level loglevel to enable
	 * @return
	 * 					- SUCCESS in any case
	 */
	status_t (*enable_level) (logger_t *this, logger_level_t log_level);

	/**
	 * @brief Disables a loglevel for the current logger_t object.
	 *
	 * @param 			this logger_t object
	 * @param 			log_level loglevel to enable
	 * @return
	 * 					- SUCCESS in any case
	 */
	status_t (*disable_level) (logger_t *this, logger_level_t log_level);

	/**
	 * @brief destroys a logger_t object.
	 *
	 * @param this		logger_t object
	 * @return
	 * 		 			- SUCCESS in any case
	 */
	status_t (*destroy) (logger_t *this);
};

/**
 * @brief Constructor to create a logger_t object.
 *
 * @param logger_name 	Name for the logger_t object
 * @param log_level		or'ed set of log_levels to assign to the new logger_t object
 * @param output			FILE * if log has to go on a file output, NULL for syslog
 * @return 				logger_t object or NULL if failed
 */
logger_t *logger_create(char *logger_name, logger_level_t log_level, bool log_thread_id, FILE * output);


#endif /*LOGGER_H_*/
