/**
 * @file iterator.h
 * 
 * @brief Interface iterator_t.
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

#ifndef ITERATOR_H_
#define ITERATOR_H_

typedef struct iterator_t iterator_t;

/**
 * @brief Iterator interface, allows iteration over collections.
 * 
 * iterator_t defines an interface for iterating over collections.
 * It allows searching, deleting, updating and inserting.
 * 
 * @ingroup utils 
 */
struct iterator_t {

	/**
	 * Moves to the next element, if available.
	 * 
	 * @param this 			calling object
	 * @return
	 * 						- TRUE, if more elements are avaiable,
	 * 						- FALSE otherwise
	 */
	bool (*has_next) (iterator_t *this);

	/**
	 * Returns the current value at the iterator position.
	 * 
	 * @param this 			calling object
	 * @param[out] value 	value is set to the current value at iterator position
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if iterator on an invalid position
	 */
	status_t (*current) (iterator_t *this, void **value);
	
	/**
	 * Inserts a new item before the given iterator position.
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
	 * @brief removes an element from list at the given iterator position.
	 * 
	 * The position of the iterator is set in the following order:
	 * - to the item before, if available
	 * - otherwise to the item after, if available
	 * - otherwise it gets reseted
	 * 
	 * @param linked_list 	calling object
	 * @return 
	 * 						- SUCCESS
	 * 						- FAILED if iterator is on an invalid position
	 */
	status_t (*remove) (iterator_t *iterator);
			  
	/**
	 * @brief Resets the iterator position.
	 * 
	 * After reset, the iterator stands NOT on an element.
	 * A call to has_next is necessary to do any other operations
	 * with the resetted iterator.
	 * 
	 * @param this 			calling object
	 * @return 				SUCCESS in any case
	 */
	void (*reset) (iterator_t *this);

	/**
	 * @brief Destroys an iterator.
	 * 
	 * @param this 			iterator to destroy
	 * @return 				SUCCESS in any case
	 * 
	 */
	void (*destroy) (iterator_t *this);
};

#endif /*ITERATOR_H_*/
