/**
 * @file optionsfrom.h
 * 
 * @brief Read command line options from a file
 * 
 */

/*
 * Copyright (C) 2007-2008 Andreas Steffen
 *
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
 *
 * RCSID $Id$
 */

#ifndef OPTIONSFROM_H_
#define OPTIONSFROM_H_

typedef struct options_t options_t;

/**
 * @brief options object.
 * 
 * @b Constructors:
 *  - options_create()
 *
 * @ingroup utils
 */
struct options_t {
	/**
	 * @brief Check if the PKCS#7 contentType is data
	 *
	 * @param this			calling object
	 * @param filename		file containing the options
	 * @param argcp			pointer to argc
	 * @param argvp			pointer to argv[]
	 * @param optind		current optind, number of next argument
	 * @return				TRUE if optionsfrom parsing successful
	 */
	bool (*from) (options_t * this, char *filename, int *argcp, char **argvp[], int optind);

	/**
	 * @brief Destroys the options_t object.
	 *
	 * @param this			options_t object to destroy
	 */
	void (*destroy) (options_t *this);
};

/**
 * @brief Create an options object.
 *
 * @return					created options_t object
 *
 * @ingroup utils
 */
options_t *options_create(void);

#endif /*OPTIONSFROM_H_*/
