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


typedef enum logger_level_e logger_level_t;
enum logger_level_e {
	CONTROL = 1,
	CONTROL_MORE = 2,
	RAW = 4,
	PRIVATE = 8
};




/**
 * @brief The logger object
 */
typedef struct logger_s logger_t;
struct logger_s { 	
	status_t (*log) (logger_t *this, logger_level_t loglevel, char *format, ...);
	
	status_t (*enable_level) (logger_t *this, logger_level_t log_level);
	
	status_t (*disable_level) (logger_t *this, logger_level_t log_level);
	
	/**
	 * @brief Destroys a generator object
	 * 
	 * @param generator generator object
	 * @return SUCCESSFUL if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (logger_t *this);
};

/**
 * Constructor to create a logger
 * 
 */
logger_t *logger_create(char *logger_name, char *file, logger_level_t log_level);

#endif /*LOGGER_H_*/

