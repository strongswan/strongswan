/*
 * Copyright (C) 2007-2011 Tobias Brunner
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

#include <stdlib.h>

#include "linked_list.h"

typedef struct element_t element_t;

/**
 * This element holds a pointer to the value it represents.
 */
struct element_t {

	/**
	 * Value of a list item.
	 */
	void *value;

	/**
	 * Previous list element.
	 *
	 * NULL if first element in list.
	 */
	element_t *previous;

	/**
	 * Next list element.
	 *
	 * NULL if last element in list.
	 */
	element_t *next;
};

/**
 * Creates an empty linked list object.
 */
element_t *element_create(void *value)
{
	element_t *this;
	INIT(this,
		.value = value,
	);
	return this;
}


typedef struct private_linked_list_t private_linked_list_t;

/**
 * Private data of a linked_list_t object.
 *
 */
struct private_linked_list_t {
	/**
	 * Public part of linked list.
	 */
	linked_list_t public;

	/**
	 * Number of items in the list.
	 */
	int count;

	/**
	 * First element in list.
	 * NULL if no elements in list.
	 */
	element_t *first;

	/**
	 * Last element in list.
	 * NULL if no elements in list.
	 */
	element_t *last;
};


typedef struct private_iterator_t private_iterator_t;

/**
 * Private variables and functions of linked list iterator.
 */
struct private_iterator_t {
	/**
	 * Public part of linked list iterator.
	 */
	iterator_t public;

	/**
	 * Associated linked list.
	 */
	private_linked_list_t * list;

	/**
	 * Current element of the iterator.
	 */
	element_t *current;

	/**
	 * Direction of iterator.
	 */
	bool forward;
};

typedef struct private_enumerator_t private_enumerator_t;

/**
 * linked lists enumerator implementation
 */
struct private_enumerator_t {

	/**
	 * implements enumerator interface
	 */
	enumerator_t enumerator;

	/**
	 * associated linked list
	 */
	private_linked_list_t *list;

	/**
	 * current item
	 */
	element_t *current;
};

METHOD(enumerator_t, enumerate, bool,
	   private_enumerator_t *this, void **item)
{
	if (!this->current)
	{
		this->current = this->list->first;
	}
	else
	{
		this->current = this->current->next;
	}
	if (!this->current)
	{
		return FALSE;
	}
	*item = this->current->value;
	return TRUE;
}

METHOD(linked_list_t, create_enumerator, enumerator_t*,
	   private_linked_list_t *this)
{
	private_enumerator_t *enumerator;

	INIT(enumerator,
		.enumerator = {
			.enumerate = (void*)_enumerate,
			.destroy = (void*)free,
		},
		.list = this,
	);

	return &enumerator->enumerator;
}

METHOD(iterator_t, iterator_get_count, int,
	   private_iterator_t *this)
{
	return this->list->count;
}

METHOD(iterator_t, iterate, bool,
	   private_iterator_t *this, void** value)
{
	if (this->forward)
	{
		this->current = this->current ? this->current->next : this->list->first;
	}
	else
	{
		this->current = this->current ? this->current->previous : this->list->last;
	}
	if (this->current == NULL)
	{
		return FALSE;
	}
	*value = this->current->value;
	return TRUE;
}

METHOD(iterator_t, iterator_reset, void,
	   private_iterator_t *this)
{
	this->current = NULL;
}

METHOD(iterator_t, iterator_remove, status_t,
	   private_iterator_t *this)
{
	element_t *new_current;

	if (this->current == NULL)
	{
		return NOT_FOUND;
	}

	if (this->list->count == 0)
	{
		return NOT_FOUND;
	}
	/* find out the new iterator position, depending on iterator direction */
	if (this->forward && this->current->previous != NULL)
	{
		new_current = this->current->previous;
	}
	else if (!this->forward && this->current->next != NULL)
	{
		new_current = this->current->next;
	}
	else
	{
		new_current = NULL;
	}

	/* now delete the entry :-) */
	if (this->current->previous == NULL)
	{
		if (this->current->next == NULL)
		{
			this->list->first = NULL;
			this->list->last = NULL;
		}
		else
		{
			this->current->next->previous = NULL;
			this->list->first = this->current->next;
		}
	}
	else if (this->current->next == NULL)
	{
		this->current->previous->next = NULL;
		this->list->last = this->current->previous;
	}
	else
	{
		this->current->previous->next = this->current->next;
		this->current->next->previous = this->current->previous;
	}

	this->list->count--;
	free(this->current);
	/* set the new iterator position */
	this->current = new_current;
	return SUCCESS;
}

static void insert_item_before(private_linked_list_t *this, element_t *current,
							   void *item)
{
	if (!current)
	{
		this->public.insert_last(&this->public, item);
		return;
	}
	element_t *element = element_create(item);
	if (current->previous)
	{
		current->previous->next = element;
		element->previous = current->previous;
		current->previous = element;
		element->next = current;
	}
	else
	{
		current->previous = element;
		element->next = current;
		this->first = element;
	}
	this->count++;
}

static void insert_item_after(private_linked_list_t *this, element_t *current,
							  void *item)
{
	if (!current)
	{
		this->public.insert_last(&this->public, item);
		return;
	}
	element_t *element = element_create(item);
	if (current->next)
	{
		current->next->previous = element;
		element->next = current->next;
		current->next = element;
		element->previous = current;
	}
	else
	{
		current->next = element;
		element->previous = current;
		this->last = element;
	}
	this->count++;
}

METHOD(iterator_t, iterator_insert_before, void,
	   private_iterator_t * iterator, void *item)
{
	insert_item_before(iterator->list, iterator->current, item);
}

METHOD(iterator_t, iterator_replace, status_t,
	   private_iterator_t *this, void **old_item, void *new_item)
{
	if (this->current == NULL)
	{
		return NOT_FOUND;
	}
	if (old_item != NULL)
	{
		*old_item = this->current->value;
	}
	this->current->value = new_item;

	return SUCCESS;
}

METHOD(iterator_t, iterator_insert_after, void,
	   private_iterator_t *iterator, void *item)
{
	insert_item_after(iterator->list, iterator->current, item);
}

METHOD(iterator_t, iterator_destroy, void,
	   private_iterator_t *this)
{
	free(this);
}

METHOD(linked_list_t, get_count, int,
	   private_linked_list_t *this)
{
	return this->count;
}

METHOD(linked_list_t, insert_first, void,
	   private_linked_list_t *this, void *item)
{
	element_t *element;

	element = element_create(item);
	if (this->count == 0)
	{
		/* first entry in list */
		this->first = element;
		this->last = element;
		element->previous = NULL;
		element->next = NULL;
	}
	else
	{
		element_t *old_first_element = this->first;
		element->next = old_first_element;
		element->previous = NULL;
		old_first_element->previous = element;
		this->first = element;
	}
	this->count++;
}

/**
 * unlink an element form the list, returns following element
 */
static element_t* remove_element(private_linked_list_t *this,
								 element_t *element)
{
	element_t *next, *previous;

	next = element->next;
	previous = element->previous;
	free(element);
	if (next)
	{
		next->previous = previous;
	}
	else
	{
		this->last = previous;
	}
	if (previous)
	{
		previous->next = next;
	}
	else
	{
		this->first = next;
	}
	if (--this->count == 0)
	{
		this->first = NULL;
		this->last = NULL;
	}
	return next;
}

METHOD(linked_list_t, get_first, status_t,
	   private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return NOT_FOUND;
	}
	*item = this->first->value;
	return SUCCESS;
}

METHOD(linked_list_t, remove_first, status_t,
	   private_linked_list_t *this, void **item)
{
	if (get_first(this, item) == SUCCESS)
	{
		remove_element(this, this->first);
		return SUCCESS;
	}
	return NOT_FOUND;
}

METHOD(linked_list_t, insert_last, void,
	   private_linked_list_t *this, void *item)
{
	element_t *element = element_create(item);

	if (this->count == 0)
	{
		/* first entry in list */
		this->first = element;
		this->last = element;
		element->previous = NULL;
		element->next = NULL;
	}
	else
	{
		element_t *old_last_element = this->last;
		element->previous = old_last_element;
		element->next = NULL;
		old_last_element->next = element;
		this->last = element;
	}
	this->count++;
}

METHOD(linked_list_t, insert_before, void,
	   private_linked_list_t *this, private_enumerator_t *enumerator,
	   void *item)
{
	insert_item_before(this, enumerator->current, item);
}

METHOD(linked_list_t, insert_after, void,
	   private_linked_list_t *this, private_enumerator_t *enumerator,
	   void *item)
{
	insert_item_after(this, enumerator->current, item);
}

METHOD(linked_list_t, get_last, status_t,
	   private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return NOT_FOUND;
	}
	*item = this->last->value;
	return SUCCESS;
}

METHOD(linked_list_t, remove_last, status_t,
	   private_linked_list_t *this, void **item)
{
	if (get_last(this, item) == SUCCESS)
	{
		remove_element(this, this->last);
		return SUCCESS;
	}
	return NOT_FOUND;
}

METHOD(linked_list_t, remove_, int,
	   private_linked_list_t *this, void *item, bool (*compare)(void*,void*))
{
	element_t *current = this->first;
	int removed = 0;

	while (current)
	{
		if ((compare && compare(current->value, item)) ||
			(!compare && current->value == item))
		{
			removed++;
			current = remove_element(this, current);
		}
		else
		{
			current = current->next;
		}
	}
	return removed;
}

METHOD(linked_list_t, remove_at, void,
	   private_linked_list_t *this, private_enumerator_t *enumerator)
{
	element_t *current;

	if (enumerator->current)
	{
		current = enumerator->current;
		enumerator->current = current->previous;
		remove_element(this, current);
	}
}

METHOD(linked_list_t, find_first, status_t,
	   private_linked_list_t *this, linked_list_match_t match,
	   void **item, void *d1, void *d2, void *d3, void *d4, void *d5)
{
	element_t *current = this->first;

	while (current)
	{
		if ((match && match(current->value, d1, d2, d3, d4, d5)) ||
			(!match && item && current->value == *item))
		{
			if (item != NULL)
			{
				*item = current->value;
			}
			return SUCCESS;
		}
		current = current->next;
	}
	return NOT_FOUND;
}

METHOD(linked_list_t, find_last, status_t,
	   private_linked_list_t *this, linked_list_match_t match,
	   void **item, void *d1, void *d2, void *d3, void *d4, void *d5)
{
	element_t *current = this->last;

	while (current)
	{
		if ((match && match(current->value, d1, d2, d3, d4, d5)) ||
			(!match && item && current->value == *item))
		{
			if (item != NULL)
			{
				*item = current->value;
			}
			return SUCCESS;
		}
		current = current->previous;
	}
	return NOT_FOUND;
}

METHOD(linked_list_t, invoke_offset, void,
	   private_linked_list_t *this, size_t offset,
	   void *d1, void *d2, void *d3, void *d4, void *d5)
{
	element_t *current = this->first;

	while (current)
	{
		linked_list_invoke_t *method = current->value + offset;
		(*method)(current->value, d1, d2, d3, d4, d5);
		current = current->next;
	}
}

METHOD(linked_list_t, invoke_function, void,
	   private_linked_list_t *this, linked_list_invoke_t fn,
	   void *d1, void *d2, void *d3, void *d4, void *d5)
{
	element_t *current = this->first;

	while (current)
	{
		fn(current->value, d1, d2, d3, d4, d5);
		current = current->next;
	}
}

METHOD(linked_list_t, clone_offset, linked_list_t*,
	   private_linked_list_t *this, size_t offset)
{
	linked_list_t *clone = linked_list_create();
	element_t *current = this->first;

	while (current)
	{
		void* (**method)(void*) = current->value + offset;
		clone->insert_last(clone, (*method)(current->value));
		current = current->next;
	}

	return clone;
}

METHOD(linked_list_t, clone_function, linked_list_t*,
	   private_linked_list_t *this, void* (*fn)(void*))
{
	linked_list_t *clone = linked_list_create();
	element_t *current = this->first;

	while (current)
	{
		clone->insert_last(clone, fn(current->value));
		current = current->next;
	}

	return clone;
}

METHOD(linked_list_t, destroy, void,
	   private_linked_list_t *this)
{
	void *value;
	/* Remove all list items before destroying list */
	while (remove_first(this, &value) == SUCCESS)
	{
		/* values are not destroyed so memory leaks are possible
		 * if list is not empty when deleting */
	}
	free(this);
}

METHOD(linked_list_t, destroy_offset, void,
	   private_linked_list_t *this, size_t offset)
{
	element_t *current = this->first, *next;

	while (current)
	{
		void (**method)(void*) = current->value + offset;
		(*method)(current->value);
		next = current->next;
		free(current);
		current = next;
	}
	free(this);
}

METHOD(linked_list_t, destroy_function, void,
	   private_linked_list_t *this, void (*fn)(void*))
{
	element_t *current = this->first, *next;

	while (current)
	{
		fn(current->value);
		next = current->next;
		free(current);
		current = next;
	}
	free(this);
}

METHOD(linked_list_t, create_iterator, iterator_t*,
	   private_linked_list_t *linked_list, bool forward)
{
	private_iterator_t *this;

	INIT(this,
		.public = {
			.get_count = _iterator_get_count,
			.iterate = _iterate,
			.insert_before = _iterator_insert_before,
			.insert_after = _iterator_insert_after,
			.replace = _iterator_replace,
			.remove = _iterator_remove,
			.reset = _iterator_reset,
			.destroy = _iterator_destroy,
		},
		.forward = forward,
		.list = linked_list,
	);

	return &this->public;
}

/*
 * Described in header.
 */
linked_list_t *linked_list_create()
{
	private_linked_list_t *this;

	INIT(this,
		.public = {
			.get_count = _get_count,
			.create_iterator = _create_iterator,
			.create_enumerator = _create_enumerator,
			.get_first = _get_first,
			.get_last = _get_last,
			.find_first = (void*)_find_first,
			.find_last = (void*)_find_last,
			.insert_first = _insert_first,
			.insert_last = _insert_last,
			.insert_after = (void*)_insert_after,
			.insert_before = (void*)_insert_before,
			.remove_first = _remove_first,
			.remove_last = _remove_last,
			.remove = _remove_,
			.remove_at = (void*)_remove_at,
			.invoke_offset = (void*)_invoke_offset,
			.invoke_function = (void*)_invoke_function,
			.clone_offset = _clone_offset,
			.clone_function = _clone_function,
			.destroy = _destroy,
			.destroy_offset = _destroy_offset,
			.destroy_function = _destroy_function,
		},
	);

	return &this->public;
}
