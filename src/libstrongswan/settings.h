/*
 * Copyright (C) 2008 Martin Willi
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

/**
 * @defgroup settings settings
 * @{ @ingroup libstrongswan
 */

#ifndef SETTINGS_H_
#define SETTINGS_H_

typedef struct settings_t settings_t;

#include "utils.h"
#include "utils/enumerator.h"

/**
 * Generic configuration options read from a config file.
 *
 * The syntax is quite simple:
 *
 * settings := (section|keyvalue)*
 * section  := name { settings }
 * keyvalue := key = value\n
 *
 * E.g.:
 * @code
	a = b
	section-one {
		somevalue = asdf
		subsection {
			othervalue = xxx
		}
		yetanother = zz
	}
	section-two {
	}
	@endcode
 *
 * The values are accessed using the get() functions using dotted keys, e.g.
 *   section-one.subsection.othervalue
 *
 * Currently only a limited set of printf format specifiers are supported
 * (namely %s, %d and %N, see implementation for details).
 */
struct settings_t {

	/**
	 * Get a settings value as a string.
	 *
	 * @param key		key including sections, printf style format
	 * @param def		value returned if key not found
	 * @param ...		argument list for key
	 * @return			value pointing to internal string
	 */
	char* (*get_str)(settings_t *this, char *key, char *def, ...);

	/**
	 * Get a boolean yes|no, true|false value.
	 *
	 * @param key		key including sections, printf style format
	 * @param def		value returned if key not found
	 * @param ...		argument list for key
	 * @return			value of the key
	 */
	bool (*get_bool)(settings_t *this, char *key, bool def, ...);

	/**
	 * Get an integer value.
	 *
	 * @param key		key including sections, printf style format
	 * @param def		value returned if key not found
	 * @param ...		argument list for key
	 * @return			value of the key
	 */
	int (*get_int)(settings_t *this, char *key, int def, ...);

	/**
	 * Get an double value.
	 *
	 * @param key		key including sections, printf style format
	 * @param def		value returned if key not found
	 * @param ...		argument list for key
	 * @return			value of the key
	 */
	double (*get_double)(settings_t *this, char *key, double def, ...);

	/**
	 * Get a time value.
	 *
	 * @param key		key including sections, printf style format
	 * @param def		value returned if key not found
	 * @param ...		argument list for key
	 * @return			value of the key
	 */
	u_int32_t (*get_time)(settings_t *this, char *key, u_int32_t def, ...);

	/**
	 * Create an enumerator over subsection names of a section.
	 *
	 * @param section	section including parents, printf style format
	 * @param ...		argument list for key
	 * @return			enumerator over subsection names
	 */
	enumerator_t* (*create_section_enumerator)(settings_t *this,
											   char *section, ...);

	/**
	 * Create an enumerator over key/value pairs in a section.
	 *
	 * @param section	section name to list key/value pairs of, printf style
	 * @param ...		argmuent list for section
	 * @return			enumerator over (char *key, char *value)
	 */
	enumerator_t* (*create_key_value_enumerator)(settings_t *this,
												 char *section, ...);

	/**
	 * Load settings from the files matching the given pattern.
	 *
	 * Existing sections are extended, existing values replaced, by those found
	 * in the loaded files.
	 *
	 * @note If any of the files matching the pattern fails to load, no settings
	 * are added at all. So it's all or nothing.
	 *
	 * @param pattern	file pattern
	 * @return			TRUE, if settings were loaded successfully
	 */
	bool (*load_files)(settings_t *this, char *pattern);

	/**
	 * Load settings from the files matching the given pattern.
	 *
	 * Existing sections are extended, existing values replaced, by those found
	 * in the loaded files.
	 *
	 * All settings are loaded relative to the given section.
	 *
	 * @note If any of the files matching the pattern fails to load, no settings
	 * are added at all. So it's all or nothing.
	 *
	 * @param pattern	file pattern
	 * @param section	section name of parent section, printf style
	 * @param ...		argument list for section
	 * @return			TRUE, if section is found and settings were loaded successfully
	 */
	bool (*load_files_section)(settings_t *this, char *pattern,
							   char *section, ...);

	/**
	 * Destroy a settings instance.
	 */
	void (*destroy)(settings_t *this);
};

/**
 * Load settings from a file.
 *
 * @param file			file to read settings from, NULL for default
 * @return				settings object
 */
settings_t *settings_create(char *file);

#endif /** SETTINGS_H_ @}*/
