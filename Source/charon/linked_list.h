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

#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

#include "types.h"

/**
 * @brief Element of the linked_list.
 * 
 * This element holds a pointer to the value of the list item itself.
 */
typedef struct linked_list_element_s linked_list_element_t;

struct linked_list_element_s {

	/**
	 * value of a list item
	 */
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
 * @param[in] value value of item to be set
 * 
 * @warning only the pointer to the value is stored
 * 
 * @return linked_list_element object
 */
linked_list_element_t *linked_list_element_create(void *value);

/**
 * @brief Iterator for a linked list
 * 
 * This element holds a pointer to the current element in the linked list
 * 
 * @warning the iterator is NOT thread-save
 */
typedef struct linked_list_iterator_s linked_list_iterator_t;

struct linked_list_iterator_s {

	/**
	 * @brief returns TRUE if more elements are available
	 * 
	 * @param this calling object
	 * @param[out] has_next if more elements are avaiable TRUE is set, FALSE otherwise
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*has_next) (linked_list_iterator_t *this, bool * has_next);

	/**
	 * @brief returns the current element at the iterator position
	 * 
	 * @param this calling object
	 * @param[out] element element is set to the current element in iterator
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*current) (linked_list_iterator_t *this, linked_list_element_t **element);

	/**
	 * @brief Resets a linked_list_iterator object
	 * 
	 * @param this calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*reset) (linked_list_iterator_t *this);

	/**
	 * @brief Destroys a linked_list_iterator object
	 * 
	 * @param this calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (linked_list_iterator_t *this);
};

/**
 * @brief Double Linked List (named only as linked list)
 *
 * @warning Access to an object of this type is not thread-save
 * 
 * @see job_queue_t
 * @see event_queue_t
 * @see send_queue_t
 */
typedef struct linked_list_s linked_list_t;


struct linked_list_s {

	/**
	 * @brief gets the count of items in the list
	 * 
	 * @param linked_list calling object
	 * @param[in] count place where the count is written
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_count) (linked_list_t *linked_list, int *count);
	
	/**
	 * @brief creates a iterator for the given list
	 * 
	 * @warning has to get destroyed
	 * 
	 * @param linked_list calling object
	 * @param[out] iterator place where the iterator is written
	 * @param[in] forward iterator direction (TRUE: front to end)
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*create_iterator) (linked_list_t *linked_list, linked_list_iterator_t **iterator,bool forward);

	/**
	 * @brief inserts a new item at the beginning of the list
	 * 
	 * @param linked_list calling object
	 * @param[in] item value to insert in list
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_first) (linked_list_t *linked_list, void *item);
	
	/**
	 * @brief inserts a new item before the given element
	 * 
	 * @param linked_list calling object
	 * @param element new element is inserted before this element
	 * @param[in] item value to insert in list
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_before) (linked_list_t *linked_list, linked_list_element_t *element, void *item);

	/**
	 * @brief inserts a new item after the given element
	 * 
	 * @param linked_list calling object
	 * @param element new element is inserted after this element
	 * @param[in] item value to insert in list
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_after) (linked_list_t *linked_list, linked_list_element_t *element, void *item);

	/**
	 * @brief removes an element from list
	 * 
	 * @param linked_list calling object
	 * @param element element to remove
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove) (linked_list_t *linked_list, linked_list_element_t *element);

	/**
	 * @brief removes the first item in the list and returns its value
	 * 
	 * @param linked_list calling object
	 * @param[in] item returned value of first item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief returns the value of the first list item without removing it
	 * 
	 * @param linked_list calling object
	 * @param[out] item returned value of first item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief inserts a new item at the end of the list
	 * 
	 * @param linked_list calling object
	 * @param[in] item value to insert into list
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_last) (linked_list_t *linked_list, void *item);
	
	/**
	 * @brief removes the last item in the list and returns its value
	 * 
	 * @param linked_list calling object
	 * @param[out] item returned value of last item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove_last) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Returns the value of the last list item without removing it
	 * 
	 * @param linked_list calling object
	 * @param[out] item returned value of last item
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_last) (linked_list_t *linked_list, void **item);
	
	/**
	 * @brief Destroys a linked_list object
	 * 
	 * @warning all items are removed before deleting the list. The
	 *          associated values are NOT destroyed. 
	 * 			Destroying an list which is not empty may cause
	 * 			memory leaks!
	 * 
	 * @param linked_list calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (linked_list_t *linked_list);
};

/**
 * @brief Creates an empty linked list object
 */
linked_list_t *linked_list_create(void);


#endif /*LINKED_LIST_H_*/
