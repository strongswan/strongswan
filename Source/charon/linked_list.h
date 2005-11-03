/**
 * @file linked_list.h
 * 
 * @brief Generic Double Linked List
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

#ifndef LINKED_LIST_H_
#define LINKED_LIST_H_

#include "types.h"


/**
 * @brief Double Linked List Element type
 */
typedef struct linked_list_element_s linked_list_element_t;

struct linked_list_element_s {
	linked_list_element_t *previous;
	linked_list_element_t *next;
	/* value of a list item */
	void *value;
	
	/**
	 * @brief Destroys a linked_list_element object
	 * 
	 * @param linked_list_element_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (linked_list_element_t *this);
};

/**
 * @brief Creates an empty linked list object
 *
 * @param value value of item
 * 
 * @return linked_list_element object
 */
linked_list_element_t *linked_list_element_create(void *value);


/**
 * @brief Double Linked List type
 */
typedef struct linked_list_s linked_list_t;


struct linked_list_s {
	/* item count */
	int count;
	linked_list_element_t *first;
	linked_list_element_t *last;
	
	/**
	 * @brief inserts a new item at the beginning of the list
	 * 
	 * @param linked_list calling object
	 * @param item value to insert in list
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_first) (linked_list_t *linked_list, void *item);
	
	/**
	 * @brief removes the first item in the list and returns its value
	 * 
	 * @param linked_list calling object
	 * @param item returned value of first item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Returns the value of the first list item without removing it
	 * 
	 * @param linked_list calling object
	 * @param item returned value of first item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief inserts a new item at the end of the list
	 * 
	 * @param linked_list calling object
	 * @param item value to insert in list
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_last) (linked_list_t *linked_list, void *item);
	
	/**
	 * @brief removes the last item in the list and returns its value
	 * 
	 * @param linked_list calling object
	 * @param item returned value of last item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove_last) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Returns the value of the last list item without removing it
	 * 
	 * @param linked_list calling object
	 * @param item returned value of last item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_last) (linked_list_t *linked_list, void **item);
	
	/**
	 * @brief Destroys a linked_list object
	 * 
	 * @param linked_list calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (linked_list_t *linked_list);
};

/**
 * @brief
 * 
 * Creates an empty linked list object
 */
linked_list_t *linked_list_create(void);


#endif /*LINKED_LIST_H_*/
