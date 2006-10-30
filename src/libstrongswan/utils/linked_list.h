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

typedef struct linked_list_t linked_list_t;

#include <pthread.h>

#include <types.h>
#include <utils/iterator.h>

/**
 * @brief Class implementing a double linked list.
 *
 * General purpose linked list. This list is not synchronized.
 *
 * @b Costructors:
 * - linked_list_create()
 *
 * @ingroup utils
 */
struct linked_list_t {

	/**
	 * @brief Gets the count of items in the list.
	 * 
	 * @param this 		calling object
	 * @return 			number of items in list
	 */
	int (*get_count) (linked_list_t *this);
	
	/**
	 * @brief Creates a iterator for the given list.
	 * 
	 * @warning Created iterator_t object has to get destroyed by the caller.
	 * 
	 * @param this 		calling object
	 * @param forward 	iterator direction (TRUE: front to end)
	 * @return			new iterator_t object
	 */
	iterator_t *(*create_iterator) (linked_list_t *this, bool forward);
	
	/**
	 * @brief Creates a iterator, locking a mutex.
	 *
	 * The supplied mutex is acquired immediately, and released
	 * when the iterator gets destroyed.
	 * 
	 * @param this	 	calling object
	 * @param mutex 	mutex to use for exclusive access
	 * @return			new iterator_t object
	 */
	iterator_t *(*create_iterator_locked) (linked_list_t *this,
										   pthread_mutex_t *mutex);

	/**
	 * @brief Inserts a new item at the beginning of the list.
	 *
	 * @param this 		calling object
	 * @param[in] item	item value to insert in list
	 */
	void (*insert_first) (linked_list_t *this, void *item);

	/**
	 * @brief Removes the first item in the list and returns its value.
	 * 
	 * @param this 		calling object
	 * @param[out] item returned value of first item, or NULL
	 * @return
	 * 					- SUCCESS
	 * 					- NOT_FOUND, if list is empty
	 */
	status_t (*remove_first) (linked_list_t *this, void **item);

	/**
	 * @brief Returns the value of the first list item without removing it.
	 * 
	 * @param this	 	calling object
	 * @param[out] item	returned value of first item
	 * @return
	 * 					- SUCCESS
	 * 					- NOT_FOUND, if list is empty
	 */
	status_t (*get_first) (linked_list_t *this, void **item);

	/**
	 * @brief Inserts a new item at the end of the list.
	 * 
	 * @param this 		calling object
	 * @param[in] item 	value to insert into list
	 */
	void (*insert_last) (linked_list_t *this, void *item);
	
	/**
	 * @brief Inserts a new item at a given position in the list.
	 * 
	 * @param this		calling object
	 * @param position	position starting at 0 to insert new entry
	 * @param[in] item	value to insert into list
	 * @return
	 * 					- SUCCESS
	 * 					- INVALID_ARG if position not existing
	 */
	status_t (*insert_at_position) (linked_list_t *this,size_t position, void *item);
	
	/**
	 * @brief Removes an item from a given position in the list.
	 * 
	 * @param this	 	calling object
	 * @param position	position starting at 0 to remove entry from
	 * @param[out] item removed item will be stored at this location
	 * @return
	 * 						- SUCCESS
	 * 						- INVALID_ARG if position not existing
	 */
	status_t (*remove_at_position) (linked_list_t *this, size_t position, void **item);

	/**
	 * @brief Get an item from a given position in the list.
	 * 
	 * @param this	 	calling object
	 * @param position	position starting at 0 to get entry from
	 * @param[out] item	item will be stored at this location
	 * @return
	 * 						- SUCCESS
	 * 						- INVALID_ARG if position not existing
	 */
	status_t (*get_at_position) (linked_list_t *this, size_t position, void **item);

	/**
	 * @brief Removes the last item in the list and returns its value.
	 * 
	 * @param this	 	calling object
	 * @param[out] item	returned value of last item, or NULL
	 * @return
	 * 						- SUCCESS
	 * 						- NOT_FOUND if list is empty
	 */
	status_t (*remove_last) (linked_list_t *this, void **item);

	/**
	 * @brief Returns the value of the last list item without removing it.
	 * 
	 * @param this 		calling object
	 * @param[out] item	returned value of last item
	 * @return
	 * 					- SUCCESS
	 * 					- NOT_FOUND if list is empty
	 */
	status_t (*get_last) (linked_list_t *this, void **item);
	
	/**
	 * @brief Invoke a method on all of the contained objects.
	 *
	 * If a linked list contains objects with function pointers,
	 * invoke() can call a method on each of the objects. The
	 * method is specified by an offset of the function pointer,
	 * which can be evalutated at compile time using the offsetof
	 * macro, e.g.: list->invoke(list, offsetof(object_t, method));
	 * 
	 * @param this 		calling object
	 * @param offset	offset of the method to invoke on objects
	 */
	void (*invoke) (linked_list_t *this, size_t offset);
	
	/**
	 * @brief Destroys a linked_list object.
	 * 
	 * @param this		calling object
	 */
	void (*destroy) (linked_list_t *this);
	
	/**
	 * @brief Destroys a list and its objects using the destructor.
	 *
	 * If a linked list and the contained objects should be destroyed, use
	 * destroy_offset. The supplied offset specifies the destructor to
	 * call on each object. The offset may be calculated using the offsetof
	 * macro, e.g.: list->destroy_offset(list, offsetof(object_t, destroy));
	 *
	 * @param this	 	calling object
	 * @param offset	offset of the objects destructor
	 */
	void (*destroy_offset) (linked_list_t *this, size_t offset);
	
	/**
	 * @brief Destroys a list and its contents using a a cleanup function.
	 * 
	 * If a linked list and its contents should get destroyed using a specific
	 * cleanup function, use destroy_function. This is useful when the
	 * list contains malloc()-ed blocks which should get freed,
	 * e.g.: list->destroy_function(list, free);
	 *
	 * @param this 		calling object
	 * @param function	function to call on each object
	 */
	void (*destroy_function) (linked_list_t *this, void (*)(void*));
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
