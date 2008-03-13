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
 *
 * $Id$
 */
 
/**
 * @defgroup iterator iterator
 * @{ @ingroup utils
 */

#ifndef ITERATOR_H_
#define ITERATOR_H_

#include <library.h>

typedef enum hook_result_t hook_result_t;

/**
 * Return value of an iterator hook.
 *
 * Returning HOOK_AGAIN is useful to "inject" additional elements in an
 * iteration, HOOK_NEXT is the normal iterator behavior, and HOOK_SKIP may
 * be used to filter elements out.
 */
enum hook_result_t {

	/**
	 * A value was placed in out, hook is called again with the same "in"
	 */
	HOOK_AGAIN,
	
	/**
	 * A value was placed in out, hook is called again with next "in" (if any)
	 */
	HOOK_NEXT,
	
	/**
	 * No value in out, call again with next "in" (if any)
	 */
	HOOK_SKIP,
};

/**
 * Iterator hook function prototype.
 *
 * @param param		user supplied parameter
 * @param in		the value the hook receives from the iterator
 * @param out		the value supplied as a result to the iterator
 * @return			a hook_result_t
 */
typedef hook_result_t (iterator_hook_t)(void *param, void *in, void **out);


typedef struct iterator_t iterator_t;

/**
 * Iterator interface, allows iteration over collections.
 *
 * iterator_t defines an interface for iterating over collections.
 * It allows searching, deleting, updating and inserting.
 *
 * @deprecated Use enumerator instead.
 */
struct iterator_t {

	/**
	 * Return number of list items.
	 * 
	 * @return				number of list items
	 */
	int (*get_count) (iterator_t *this);
	
	/**
	 * Iterate over all items.
	 * 
	 * The easy way to iterate over items.
	 * 
	 * @param value 	item
	 * @return			TRUE, if there was an element available, FALSE otherwise
	 */
	bool (*iterate) (iterator_t *this, void** value);
	
	/**
	 * Hook a function into the iterator.
	 *
	 * Sometimes it is useful to hook in an iterator. The hook function is
	 * called before any successful return of iterate(). It takes the
	 * iterator value, may manipulate it (or the references object), and returns
	 * the value that the iterate() function returns. Depending on the hook
	 * return value, the hook is called again, called with next, or skipped.
	 * A value of NULL deactivates the iterator hook.
	 * If an iterator is hooked, only the iterate() method is valid,
	 * all other methods behave undefined.
	 * 
	 * @param hook		iterator hook which manipulates the iterated value
	 * @param param		user supplied parameter to pass back to the hook
	 */
	void (*set_iterator_hook) (iterator_t *this, iterator_hook_t *hook,
							   void *param);
	
	/**
	 * Inserts a new item before the given iterator position.
	 * 
	 * The iterator position is not changed after inserting
	 * 
	 * @param item 		value to insert in list
	 */
	void (*insert_before) (iterator_t *this, void *item);

	/**
	 * Inserts a new item after the given iterator position.
	 * 
	 * The iterator position is not changed after inserting.
	 * 
	 * @param this 		calling iterator
	 * @param item 		value to insert in list
	 */
	void (*insert_after) (iterator_t *this, void *item);
	
	/**
	 * Replace the current item at current iterator position.
	 * 
	 * The iterator position is not changed after replacing.
	 * 
	 * @param this 		calling iterator
	 * @param old		old value will be written here(can be NULL)
	 * @param new		new value
	 * @return			SUCCESS, FAILED if iterator is on an invalid position
	 */
	status_t (*replace) (iterator_t *this, void **old, void *new);

	/**
	 * Removes an element from list at the given iterator position.
	 * 
	 * The iterator is set the the following position:
	 * - to the item before, if available
	 * - it gets reseted, otherwise
	 * 
	 * @return 				SUCCESS, FAILED if iterator is on an invalid position
	 */
	status_t (*remove) (iterator_t *this);
	
	/**
	 * Resets the iterator position.
	 * 
	 * After reset, the iterator_t objects doesn't point to an element.
	 * A call to iterator_t.has_next is necessary to do any other operations
	 * with the resetted iterator.
	 */
	void (*reset) (iterator_t *this);

	/**
	 * Destroys an iterator.
	 */
	void (*destroy) (iterator_t *this);
};

#endif /*ITERATOR_H_ @} */
