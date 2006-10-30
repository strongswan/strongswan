/**
 * @file iterator.h
 * 
 * @brief Interface iterator_t.
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

#ifndef ITERATOR_H_
#define ITERATOR_H_

typedef struct iterator_t iterator_t;

/**
 * @brief Iterator interface, allows iteration over collections.
 *
 * iterator_t defines an interface for iterating over collections.
 * It allows searching, deleting, updating and inserting.
 *
 * Thanks to JMP for iterator lessons :-)
 *
 * @b Constructors:
 * - via linked_list_t.create_iterator, or
 * - any other class which supports the iterator_t interface
 *
 * @see linked_list_t
 *
 * @ingroup utils 
 */
struct iterator_t {

	/**
	 * @brief Return number of list items.
	 * 
	 * @param this 			calling object
	 * @return				number of list items
	 */
	int (*get_count) (iterator_t *this);
	
	/**
	 * @brief Iterate over all items.
	 * 
	 * The easy way to iterate over items.
	 * 
	 * @param this 			calling object
	 * @param[out] value 	item
	 * @return
	 * 						- TRUE, if there was an element available,
	 * 						- FALSE otherwise
	 */
	bool (*iterate) (iterator_t *this, void** value);
	
	/**
	 * @brief Hook a function into the iterator.
	 *
	 * Sometimes it is useful to hook in an iterator. The hook function is
	 * called before any successful return of iterate(). It takes the
	 * iterator value, may manipulate it (or the references object), and returns
	 * the value that the iterate() function returns.
	 * A value of NULL deactivates the iterator hook.
	 * 
	 * @param this 			calling object
	 * @param hook			iterator hook which manipulates the iterated value
	 */
	void (*set_iterator_hook) (iterator_t *this, void*(*hook)(void*));
	
	/**
	 * @brief Inserts a new item before the given iterator position.
	 * 
	 * The iterator position is not changed after inserting
	 * 
	 * @param this 			calling iterator
	 * @param[in] item 		value to insert in list
	 */
	void (*insert_before) (iterator_t *this, void *item);

	/**
	 * @brief Inserts a new item after the given iterator position.
	 * 
	 * The iterator position is not changed after inserting.
	 * 
	 * @param this 			calling iterator
	 * @param[in] item 		value to insert in list
	 */
	void (*insert_after) (iterator_t *this, void *item);
	
	/**
	 * @brief Replace the current item at current iterator position.
	 * 
	 * The iterator position is not changed after replacing.
	 * 
	 * @param this 			calling iterator
	 * @param[out] old_item	old value will be written here(can be NULL)
	 * @param[in] new_item  new value
	 * 
	 * @return 
	 * 						- SUCCESS
	 * 						- FAILED if iterator is on an invalid position
	 */
	status_t (*replace) (iterator_t *this, void **old_item, void *new_item);

	/**
	 * @brief Removes an element from list at the given iterator position.
	 * 
	 * The iterator is set the the following position:
	 * - to the item before, if available
	 * - it gets reseted, otherwise
	 * 
	 * @param this		 	calling object
	 * @return 
	 * 						- SUCCESS
	 * 						- FAILED if iterator is on an invalid position
	 */
	status_t (*remove) (iterator_t *this);
	
	/**
	 * @brief Resets the iterator position.
	 * 
	 * After reset, the iterator_t objects doesn't point to an element.
	 * A call to iterator_t.has_next is necessary to do any other operations
	 * with the resetted iterator.
	 * 
	 * @param this 			calling object
	 */
	void (*reset) (iterator_t *this);

	/**
	 * @brief Destroys an iterator.
	 * 
	 * @param this 			iterator to destroy
	 * 
	 */
	void (*destroy) (iterator_t *this);
};

#endif /*ITERATOR_H_*/
