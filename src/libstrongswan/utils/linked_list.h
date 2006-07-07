/**
 * @file linked_list.h
 * 
 * @brief Interface of linked_list_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 * @brief Class implementing a double linked list (named only as linked list).
 *
 * @warning Access to an object of this type is not thread-save.
 * 
 * @b Costructors:
 * - linked_list_create()
 * 
 * @see		
 * 			- job_queue_t
 * 			- event_queue_t
 * 			- send_queue_t
 * 
 * @ingroup utils
 */
struct linked_list_t {

	/**
	 * @brief Gets the count of items in the list.
	 * 
	 * @param linked_list 	calling object
	 * @return 				number of items in list
	 */
	int (*get_count) (linked_list_t *linked_list);
	
	/**
	 * @brief Creates a iterator for the given list.
	 * 
	 * @warning Created iterator_t object has to get destroyed by the caller.
	 * 
	 * @param linked_list 	calling object
	 * @param forward 		iterator direction (TRUE: front to end)
	 * @return				new iterator_t object
	 */
	iterator_t * (*create_iterator) (linked_list_t *linked_list, bool forward);
	
	/**
	 * @brief Call a function with list element as argument.
	 * 
	 * This method accepts a function, which will be called for 
	 * each list element once. The function must accept the list
	 * element as the first argument. Handy for destruction of
	 * list elements.
	 * 
	 * @todo Additional vararg which are passed to the 
	 *		 function would be nice...
	 * 
	 * @param linked_list 	calling object
	 * @param func			function to call
	 */
	void (*call_on_items) (linked_list_t *linked_list, void(*func)(void*));

	/**
	 * @brief Inserts a new item at the beginning of the list.
	 * 
	 * @param linked_list 	calling object
	 * @param[in] item		item value to insert in list
	 */
	void (*insert_first) (linked_list_t *linked_list, void *item);

	/**
	 * @brief Removes the first item in the list and returns its value.
	 * 
	 * @param linked_list 	calling object
	 * @param[out] item 	returned value of first item, or NULL
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND, if list is empty
	 */
	status_t (*remove_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Returns the value of the first list item without removing it.
	 * 
	 * @param linked_list 	calling object
	 * @param[out] item		item returned value of first item
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND, if list is empty
	 */
	status_t (*get_first) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Inserts a new item at the end of the list.
	 * 
	 * @param linked_list 	calling object
	 * @param[in] item 		item value to insert into list
	 */
	void (*insert_last) (linked_list_t *linked_list, void *item);
	
	/**
	 * @brief Inserts a new item at a given position in the list.
	 * 
	 * @param linked_list 	calling object
	 * @param position		position starting at 0 to insert new entry
	 * @param[in] item		item value to insert into list
	 * @return
	 * 						- SUCCESS
	 * 						- INVALID_ARG if position not existing
	 */
	status_t (*insert_at_position) (linked_list_t *linked_list,size_t position, void *item);
	
	/**
	 * @brief Removes an item from a given position in the list.
	 * 
	 * @param linked_list 	calling object
	 * @param position		position starting at 0 to remove entry from
	 * @param[out] item 	removed item will be stored at this location
	 * @return
	 * 						- SUCCESS
	 * 						- INVALID_ARG if position not existing
	 */
	status_t (*remove_at_position) (linked_list_t *linked_list,size_t position, void **item);

	/**
	 * @brief Get an item from a given position in the list.
	 * 
	 * @param linked_list 	calling object
	 * @param position		position starting at 0 to get entry from
	 * @param[out] item		item will be stored at this location
	 * @return
	 * 						- SUCCESS
	 * 						- INVALID_ARG if position not existing
	 */
	status_t (*get_at_position) (linked_list_t *linked_list,size_t position, void **item);

	/**
	 * @brief Removes the last item in the list and returns its value.
	 * 
	 * @param linked_list 	calling object
	 * @param[out] item		returned value of last item, or NULL
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND if list is empty
	 */
	status_t (*remove_last) (linked_list_t *linked_list, void **item);

	/**
	 * @brief Returns the value of the last list item without removing it.
	 * 
	 * @param linked_list 	calling object
	 * @param[out] item		returned value of last item
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND if list is empty
	 */
	status_t (*get_last) (linked_list_t *linked_list, void **item);
	
	/**
	 * @brief Destroys a linked_list object.
	 * 
	 * @warning All items are removed before deleting the list. The
	 *          associated values are NOT destroyed. 
	 * 			Destroying an list which is not empty may cause
	 * 			memory leaks!
	 * 
	 * @param linked_list 	calling object
	 */
	void (*destroy) (linked_list_t *linked_list);
};

/**
 * @brief Creates an empty linked list object.
 * 
 * @return 		linked_list_t object.
 * 
 * @ingroup utils
 */
linked_list_t *linked_list_create(void);


#endif /*LINKED_LIST_H_*/
