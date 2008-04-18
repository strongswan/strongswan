/*
 * Copyright (C) 2007-2008 Tobias Brunner
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
 *
 * $Id$
 */
 
/**
 * @defgroup linked_list linked_list
 * @{ @ingroup utils
 */

#ifndef LINKED_LIST_H_
#define LINKED_LIST_H_

typedef struct linked_list_t linked_list_t;

#include <pthread.h>

#include <library.h>
#include <utils/iterator.h>
#include <utils/enumerator.h>


/**
 * Method to match elements in a linked list (used in find_* functions)
 *
 * @param item			current list item
 * @param ...			user supplied data (only pointers, at most 5)
 * @return
 * 						- TRUE, if the item matched
 * 						- FALSE, otherwise
 */
typedef bool (*linked_list_match_t)(void *item, ...);

/**
 * Method to be invoked on elements in a linked list (used in invoke_* functions)
 *
 * @param item			current list item
 * @param ...			user supplied data (only pointers, at most 5)
 */
typedef void (*linked_list_invoke_t)(void *item, ...);

/**
 * Class implementing a double linked list.
 *
 * General purpose linked list. This list is not synchronized.
 */
struct linked_list_t {

	/**
	 * Gets the count of items in the list.
	 * 
	 * @return 			number of items in list
	 */
	int (*get_count) (linked_list_t *this);
	
	/**
	 * Creates a iterator for the given list.
	 * 
	 * @warning Created iterator_t object has to get destroyed by the caller.
	 *
	 * @deprecated Iterator is obsolete and will disappear, it is too
	 * complicated to implement. Use enumerator instead.
	 * 
	 * @param forward 	iterator direction (TRUE: front to end)
	 * @return			new iterator_t object
	 */
	iterator_t *(*create_iterator) (linked_list_t *this, bool forward);
	
	/**
	 * Creates a iterator, locking a mutex.
	 *
	 * The supplied mutex is acquired immediately, and released
	 * when the iterator gets destroyed.
	 * 
	 * @param mutex 	mutex to use for exclusive access
	 * @return			new iterator_t object
	 */
	iterator_t *(*create_iterator_locked) (linked_list_t *this,
										   pthread_mutex_t *mutex);
	
	/**
	 * Create an enumerator over the list.
	 *
	 * The enumerator is a "lightweight" iterator. It only has two methods
	 * and should therefore be much easier to implement.
	 *
	 * @return			enumerator over list items
	 */
	enumerator_t* (*create_enumerator)(linked_list_t *this);
	
	/**
	 * Inserts a new item at the beginning of the list.
	 *
	 * @param item		item value to insert in list
	 */
	void (*insert_first) (linked_list_t *this, void *item);

	/**
	 * Removes the first item in the list and returns its value.
	 * 
	 * @param item 		returned value of first item, or NULL
	 * @return			SUCCESS, or NOT_FOUND if list is empty
	 */
	status_t (*remove_first) (linked_list_t *this, void **item);
	
	/**
	 * Remove an item from the list where the enumerator points to.
	 *
	 * @param enumerator enumerator with position
	 */
	void (*remove_at)(linked_list_t *this, enumerator_t *enumerator);
	
	/**
	 * Remove items from the list matching item.
	 * 
	 * If a compare function is given, it is called for each item, where
	 * the first parameter is the current list item and the second parameter
	 * is the supplied item parameter.
	 * If compare is NULL, compare is is done by pointer.
	 *
	 * @param item		item to remove/pass to comparator
	 * @param compare	compare function, or NULL
	 * @return			number of removed items
	 */
	int (*remove)(linked_list_t *this, void *item, bool (*compare)(void *,void*));
	
	/**
	 * Returns the value of the first list item without removing it.
	 * 
	 * @param this	 	calling object
	 * @param item		returned value of first item
	 * @return			SUCCESS, NOT_FOUND if list is empty
	 */
	status_t (*get_first) (linked_list_t *this, void **item);

	/**
	 * Inserts a new item at the end of the list.
	 * 
	 * @param item 		value to insert into list
	 */
	void (*insert_last) (linked_list_t *this, void *item);

	/**
	 * Removes the last item in the list and returns its value.
	 * 
	 * @param this	 	calling object
	 * @param item		returned value of last item, or NULL
	 * @return			SUCCESS, NOT_FOUND if list is empty
	 */
	status_t (*remove_last) (linked_list_t *this, void **item);

	/**
	 * Returns the value of the last list item without removing it.
	 * 
	 * @param this 		calling object
	 * @param item		returned value of last item
	 * @return			SUCCESS, NOT_FOUND if list is empty
	 */
	status_t (*get_last) (linked_list_t *this, void **item);
	
	/** Find the first matching element in the list.
	 * 
	 * The first object passed to the match function is the current list item,
	 * followed by the user supplied data.
	 * If the supplied function returns TRUE this function returns SUCCESS, and
	 * the current object is returned in the third parameter, otherwise,
	 * the next item is checked.
	 * 
	 * @warning Only use pointers as user supplied data.
	 *
	 * @param match			comparison function to call on each object
	 * @param item			the list item, if found
	 * @param ...			user data to supply to match function (limited to 5 arguments)
	 * @return				SUCCESS if found, NOT_FOUND otherwise
	 */
	status_t (*find_first) (linked_list_t *this, linked_list_match_t match,
							void **item, ...);
	
	/** Find the last matching element in the list.
	 * 
	 * The first object passed to the match function is the current list item,
	 * followed by the user supplied data.
	 * If the supplied function returns TRUE this function returns SUCCESS, and
	 * the current object is returned in the third parameter, otherwise,
	 * the next item is checked.
	 * 
	 * @warning Only use pointers as user supplied data.
	 *
	 * @param match			comparison function to call on each object
	 * @param item			the list item, if found
	 * @param ...			user data to supply to match function (limited to 5 arguments)
	 * @return				SUCCESS if found, NOT_FOUND otherwise
	 */
	status_t (*find_last) (linked_list_t *this, linked_list_match_t match,
						   void **item, ...);
	
	/**
	 * Invoke a method on all of the contained objects.
	 *
	 * If a linked list contains objects with function pointers,
	 * invoke() can call a method on each of the objects. The
	 * method is specified by an offset of the function pointer,
	 * which can be evalutated at compile time using the offsetof
	 * macro, e.g.: list->invoke(list, offsetof(object_t, method));
	 * 
	 * @param offset	offset of the method to invoke on objects
	 * @param ...		user data to supply to called function (limited to 5 arguments)
	 */
	void (*invoke_offset) (linked_list_t *this, size_t offset, ...);
	
	/**
	 * Invoke a function on all of the contained objects.
	 * 
	 * @param function	offset of the method to invoke on objects
	 * @param ...		user data to supply to called function (limited to 5 arguments)
	 */
	void (*invoke_function) (linked_list_t *this, linked_list_invoke_t function, ...);
	
	/**
	 * Clones a list and its objects using the objects' clone method.
	 * 
	 * @param offset	offset ot the objects clone function
	 * @return			cloned list
	 */
	linked_list_t *(*clone_offset) (linked_list_t *this, size_t offset);
	
	/**
	 * Clones a list and its objects using a given function.
	 * 
	 * @param function	function that clones an object
	 * @return			cloned list
	 */
	linked_list_t *(*clone_function) (linked_list_t *this, void*(*)(void*));
	
	/**
	 * Destroys a linked_list object.
	 */
	void (*destroy) (linked_list_t *this);
	
	/**
	 * Destroys a list and its objects using the destructor.
	 *
	 * If a linked list and the contained objects should be destroyed, use
	 * destroy_offset. The supplied offset specifies the destructor to
	 * call on each object. The offset may be calculated using the offsetof
	 * macro, e.g.: list->destroy_offset(list, offsetof(object_t, destroy));
	 *
	 * @param offset	offset of the objects destructor
	 */
	void (*destroy_offset) (linked_list_t *this, size_t offset);
	
	/**
	 * Destroys a list and its contents using a a cleanup function.
	 * 
	 * If a linked list and its contents should get destroyed using a specific
	 * cleanup function, use destroy_function. This is useful when the
	 * list contains malloc()-ed blocks which should get freed,
	 * e.g.: list->destroy_function(list, free);
	 *
	 * @param function	function to call on each object
	 */
	void (*destroy_function) (linked_list_t *this, void (*)(void*));
};

/**
 * Creates an empty linked list object.
 * 
 * @return 		linked_list_t object.
 */
linked_list_t *linked_list_create(void);

#endif /*LINKED_LIST_H_ @} */
