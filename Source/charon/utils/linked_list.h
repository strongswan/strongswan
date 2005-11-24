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

#include <types.h>
#include <utils/iterator.h>


typedef struct linked_list_t linked_list_t;

/**
 * @brief Double Linked List (named only as linked list).
 *
 * @warning Access to an object of this type is not thread-save
 * 
 * @see job_queue_t
 * @see event_queue_t
 * @see send_queue_t
 */
struct linked_list_t {

	/**
	 * @brief gets the count of items in the list
	 * 
	 * @param linked_list calling object
	 * @return number of items in list
	 */
	int (*get_count) (linked_list_t *linked_list);
	
	/**
	 * @brief creates a iterator for the given list
	 * 
	 * @warning has to get destroyed
	 * 
	 * @param linked_list calling object
	 * @param[out] iterator place where the iterator is written
	 * @param[in] forward iterator direction (TRUE: front to end)
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*create_iterator) (linked_list_t *linked_list, iterator_t **iterator,bool forward);

	/**
	 * @brief inserts a new item at the beginning of the list
	 * 
	 * @param linked_list calling object
	 * @param[in] item value to insert in list
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_first) (linked_list_t *linked_list, void *item);

	/**
	 * @brief removes the first item in the list and returns its value
	 * 
	 * @param linked_list calling object
	 * @param[in] item returned value of first item
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief returns the value of the first list item without removing it
	 * 
	 * @param linked_list calling object
	 * @param[out] item returned value of first item
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief inserts a new item at the end of the list
	 * 
	 * @param linked_list calling object
	 * @param[in] item value to insert into list
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*insert_last) (linked_list_t *linked_list, void *item);
	
	/**
	 * @brief removes the last item in the list and returns its value
	 * 
	 * @param linked_list calling object
	 * @param[out] item returned value of last item
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*remove_last) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Returns the value of the last list item without removing it
	 * 
	 * @param linked_list calling object
	 * @param[out] item returned value of last item
	 * @return SUCCESS if succeeded, FAILED otherwise
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
	 * @return SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (linked_list_t *linked_list);
};

/**
 * @brief Creates an empty linked list object
 */
linked_list_t *linked_list_create(void);


#endif /*LINKED_LIST_H_*/
