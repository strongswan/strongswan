/**
 * @file definitions.h
 * 
 * @brief general purpose definitions and macros
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

#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_


#define MAPPING_END -1

/**
 * @brief mapping entry, where enum-to-string mappings are stored
 */
typedef struct mapping_s mapping_t;
struct mapping_s
{
	/**
	 * enumeration value
	 */
	int value;
	/**
	 * mapped string
	 */
	char *string;
};


/**
 * @brief find a mapping_string in the mapping[]
 * 
 * @param mappings		mappings array
 * @param value			enum-value to get the string from
 * 
 */
char *mapping_find(mapping_t *mappings, int value);


#endif /*DEFINITIONS_H_*/
