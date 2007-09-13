/**
 * @file dict.h
 * 
 * @brief Interface of dict_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef DICT_H_
#define DICT_H_

#include <library.h>

typedef struct dict_t dict_t;

/**
 * @brief Dictionary type, key value stuff.
 */
struct dict_t {

	/**
	 * @brief Set a value in the dict.
	 *
	 * @param key		key to set
	 * @param value		value, NULL to unset key
	 * @return
	 */
	void (*set)(dict_t *this, void *key, void *value);
	
	/**
	 * @brief Get a value form the dict.
	 *
	 * @param key		key to get value of
	 * @return			assigned value, NULL if not found
	 */
	void* (*get)(dict_t *this, void *key);
		
	/**
     * @brief Destroy a dict instance.
     */
    void (*destroy)(dict_t *this);
};

/**
 * @brief Key comparator function for strings
 */
bool dict_streq(void *a, void *b);

/**
 * @brief Create a dict instance.
 *
 * @param free_key		TRUE to free() keys on destruction
 * @param 
 */
dict_t *dict_create(bool(*key_comparator)(void*,void*),
					void(*key_destructor)(void*),
					void(*value_destructor)(void*));

#endif /* DICT_H_ */
