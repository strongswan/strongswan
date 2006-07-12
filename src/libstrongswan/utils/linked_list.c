/**
 * @file linked_list.c
 *
 * @brief Implementation of linked_list_t.
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

#include <stdlib.h>

#include "linked_list.h"



typedef struct linked_list_element_t linked_list_element_t;

/**
 * @brief Element in a linked list.
 *
 * This element holds a pointer to the value it represents.
 */
struct linked_list_element_t {

	/**
	 * Value of a list item.
	 */
	void *value;

	/**
	 * Previous list element.
	 * 
	 * NULL if first element in list.
	 */
	linked_list_element_t *previous;
	
	/**
	 * Next list element.
	 * 
	 * NULL if last element in list.
	 */
	linked_list_element_t *next;
};

/**
 * Creates an empty linked list object.
 */
linked_list_element_t *linked_list_element_create(void *value)
{
	linked_list_element_t *this = malloc_thing(linked_list_element_t);
	
	this->previous = NULL;
	this->next = NULL;
	this->value = value;
	
	return (this);
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
	linked_list_element_t *first;
	
	/**
	 * Last element in list.
	 * NULL if no elements in list.
	 */
	linked_list_element_t *last;
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
	linked_list_element_t *current;

	/**
	 * Direction of iterator.
	 */
	bool forward;
};

/**
 * Implementation of iterator_t.get_count.
 */
static int get_list_count(private_iterator_t *this)
{
	return this->list->count;
}

/**
 * Implementation of iterator_t.iterate.
 */
static bool iterate(private_iterator_t *this, void** value)
{
	if (this->list->count == 0)
	{
		return FALSE;
	}
	if (this->current == NULL)
	{
		this->current = (this->forward) ? this->list->first : this->list->last;
		*value = this->current->value;
		return TRUE;
	}
	if (this->forward)
	{
		if (this->current->next == NULL)
		{
			return FALSE;
		}
		this->current = this->current->next;
		*value = this->current->value;
		return TRUE;
	}
	/* backward */
	if (this->current->previous == NULL)
	{
		return FALSE;
	}
	this->current = this->current->previous;
	*value = this->current->value;
	return TRUE;
}

/**
 * Implementation of iterator_t.has_next.
 */
static bool iterator_has_next(private_iterator_t *this)
{
	if (this->list->count == 0)
	{
		return FALSE;
	}
	if (this->current == NULL)
	{
		this->current = (this->forward) ? this->list->first : this->list->last;
		return TRUE;
	}
	if (this->forward)
	{
		if (this->current->next == NULL)
		{
			return FALSE;
		}
		this->current = this->current->next;
		return TRUE;
	}
	/* backward */
	if (this->current->previous == NULL)
	{
		return FALSE;
	}
	this->current = this->current->previous;
	return TRUE;
}

/**
 * Implementation of iterator_t.current.
 */
static status_t iterator_current(private_iterator_t *this, void **value)
{
	if (this->current == NULL)
	{
		return NOT_FOUND;
	}
	*value = this->current->value;
	return SUCCESS;
}

/**
 * Implementation of iterator_t.reset.
 */
static void iterator_reset(private_iterator_t *this)
{
	this->current = NULL;
}

/**
 * Implementation of iterator_t.remove.
 */
static status_t remove(private_iterator_t *this)
{
	linked_list_element_t *new_current;

	if (this->current == NULL)
	{
		return NOT_FOUND;
	}

	if (this->list->count == 0)
	{
		return NOT_FOUND;
	}
	/* find out the new iterator position */
	if (this->current->previous != NULL)
	{
		new_current = this->current->previous;
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

/**
 * Implementation of iterator_t.insert_before.
 */
static void insert_before(private_iterator_t * iterator, void *item)
{
	if (iterator->current == NULL)
	{
		iterator->list->public.insert_first(&(iterator->list->public), item);
	}
	
	linked_list_element_t *element = linked_list_element_create(item);
	if (iterator->current->previous == NULL)
	{
		iterator->current->previous = element;
		element->next = iterator->current;
		iterator->list->first = element;
	}
	else
	{
		iterator->current->previous->next = element;
		element->previous = iterator->current->previous;
		iterator->current->previous = element;
		element->next = iterator->current;
	}
	iterator->list->count++;
}

/**
 * Implementation of iterator_t.replace.
 */
static status_t replace (private_iterator_t *this, void **old_item, void *new_item)
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

/**
 * Implementation of iterator_t.insert_after.
 */
static void insert_after(private_iterator_t * iterator, void *item)
{
	if (iterator->current == NULL)
	{
		iterator->list->public.insert_first(&(iterator->list->public),item);
		return;
	}
	
	linked_list_element_t *element = linked_list_element_create(item);
	if (iterator->current->next == NULL)
	{
		iterator->current->next = element;
		element->previous = iterator->current;
		iterator->list->last = element;
	}
	else
	{
		iterator->current->next->previous = element;
		element->next = iterator->current->next;
		iterator->current->next = element;
		element->previous = iterator->current;
	}
	iterator->list->count++;
}

/**
 * Implementation of iterator_t.destroy.
 */
static void iterator_destroy(private_iterator_t *this)
{
	free(this);
}

/**
 * Implementation of linked_list_t.get_count.
 */
static int get_count(private_linked_list_t *this)
{
	return this->count;
}

/**
 * Implementation of linked_list_t.call_on_items.
 */
static void call_on_items(private_linked_list_t *this, void(*func)(void*))
{
	iterator_t *iterator;
	void *item;
	
	iterator = this->public.create_iterator(&this->public,TRUE);
	
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, &item);
		(*func)(item);
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of linked_list_t.insert_first.
 */
static void insert_first(private_linked_list_t *this, void *item)
{
	linked_list_element_t *element;
	
	element = linked_list_element_create(item);
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
		linked_list_element_t *old_first_element = this->first;
		element->next = old_first_element;
		element->previous = NULL;
		old_first_element->previous = element;
		this->first = element;
	}
	this->count++;
}

/**
 * Implementation of linked_list_t.remove_first.
 */
static status_t remove_first(private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return NOT_FOUND;
	}
	
	linked_list_element_t *element = this->first;
	if (element->next != NULL)
	{
		element->next->previous = NULL;
	}
	this->first = element->next;
	
	if (item != NULL)
	{
		*item = element->value;
	}
	this->count--;
	free(element);
	return SUCCESS;
}

/**
 * Implementation of linked_list_t.get_first.
 */
static status_t get_first(private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return NOT_FOUND;
	}
	*item = this->first->value;
	return SUCCESS;
}

/**
 * Implementation of linked_list_t.insert_last.
 */
static void insert_last(private_linked_list_t *this, void *item)
{
	linked_list_element_t *element = linked_list_element_create(item);
	
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
		linked_list_element_t *old_last_element = this->last;
		element->previous = old_last_element;
		element->next = NULL;
		old_last_element->next = element;
		this->last = element;
	}
	this->count++;
}

/**
 * Implementation of linked_list_t.remove_last.
 */
static status_t remove_last(private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return NOT_FOUND;
	}
	
	linked_list_element_t *element = this->last;
	
	if (element->previous != NULL)
	{
		element->previous->next = NULL;
	}
	this->last = element->previous;

	if (item != NULL)
	{
		*item = element->value;
	}
	
	this->count--;
	free(element);
	return SUCCESS;
}

/**
 * Implementation of linked_list_t.insert_at_position.
 */
static status_t insert_at_position (private_linked_list_t *this,size_t position, void *item)
{
	linked_list_element_t *current_element;
	int i;
	
	if (this->count <= position)
	{
		return INVALID_ARG;
	}
	
	current_element =  this->first;
	
	for (i = 0; i < position;i++)
	{
		current_element = current_element->next;
	}
	
	if (current_element == NULL)
	{
		this->public.insert_last(&(this->public),item);
		return SUCCESS;
	}
	
	linked_list_element_t *element = linked_list_element_create(item);
	if (current_element->previous == NULL)
	{
		current_element->previous = element;
		element->next = current_element;
		this->first = element;
	}
	else
	{
		current_element->previous->next = element;
		element->previous = current_element->previous;
		current_element->previous = element;
		element->next = current_element;
	}


	this->count++;
	return SUCCESS;
}
	
/**
 * Implementation of linked_list_t.remove_at_position.
 */
static status_t remove_at_position (private_linked_list_t *this,size_t position, void **item)
{
	iterator_t *iterator;
	int i;

	if (this->count <= position)
	{
		return INVALID_ARG;
	}
	
	iterator = this->public.create_iterator(&(this->public),TRUE);
	
	iterator->has_next(iterator);
	for (i = 0; i < position;i++)
	{
		iterator->has_next(iterator);
	}
	iterator->current(iterator,item);
	iterator->remove(iterator);
	iterator->destroy(iterator);

	return SUCCESS;
}

/**
 * Implementation of linked_list_t.get_at_position.
 */
static status_t get_at_position (private_linked_list_t *this,size_t position, void **item)
{
	int i;
	iterator_t *iterator;
	status_t status;
	if (this->count <= position)
	{
		return INVALID_ARG;
	}

	iterator = this->public.create_iterator(&(this->public),TRUE);
	
	iterator->has_next(iterator);
	for (i = 0; i < position;i++)
	{
		iterator->has_next(iterator);
	}
	status = iterator->current(iterator,item);
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of linked_list_t.get_last.
 */
static status_t get_last(private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return NOT_FOUND;
	}

	*item = this->last->value;

	return SUCCESS;
}

/**
 * Implementation of linked_list_t.create_iterator.
 */
static iterator_t *create_iterator (private_linked_list_t *linked_list, bool forward)
{
	private_iterator_t *this = malloc_thing(private_iterator_t);

	this->public.get_count = (bool (*) (iterator_t *this)) get_list_count;
	this->public.iterate = (bool (*) (iterator_t *this, void **value)) iterate;
	this->public.has_next = (bool (*) (iterator_t *this)) iterator_has_next;
	this->public.current = (status_t (*) (iterator_t *this, void **value)) iterator_current;
	this->public.insert_before = (void (*) (iterator_t *this, void *item)) insert_before;
	this->public.insert_after = (void (*) (iterator_t *this, void *item)) insert_after;
	this->public.replace = (status_t (*) (iterator_t *, void **, void *)) replace;
	this->public.remove = (status_t (*) (iterator_t *this)) remove;
	this->public.reset = (void (*) (iterator_t *this)) iterator_reset;
	this->public.destroy = (void (*) (iterator_t *this)) iterator_destroy;

	this->forward = forward;
	this->current = NULL;
	this->list = linked_list;

	return &this->public;
}

/**
 * Implementation of linked_list_t.destroy.
 */
static void linked_list_destroy(private_linked_list_t *this)
{
	void *value;
	/* Remove all list items before destroying list */
	while (this->public.remove_first(&(this->public), &value) != NOT_FOUND)
	{
		/* values are not destroyed so memory leaks are possible
		 * if list is not empty when deleting */
	}
	free(this);
}

/*
 * Described in header.
 */
linked_list_t *linked_list_create()
{
	private_linked_list_t *this = malloc_thing(private_linked_list_t);

	this->public.get_count = (int (*) (linked_list_t *)) get_count;
	this->public.create_iterator = (iterator_t * (*) (linked_list_t *,bool))create_iterator;
	this->public.call_on_items = (void (*) (linked_list_t *, void(*func)(void*)))call_on_items;
	this->public.get_first = (status_t (*) (linked_list_t *, void **item))get_first;
	this->public.get_last = (status_t (*) (linked_list_t *, void **item))get_last;
	this->public.insert_first = (void (*) (linked_list_t *, void *item))insert_first;
	this->public.insert_last = (void (*) (linked_list_t *, void *item))insert_last;
	this->public.remove_first = (status_t (*) (linked_list_t *, void **item))remove_first;
	this->public.remove_last = (status_t (*) (linked_list_t *, void **item))remove_last;
	this->public.insert_at_position = (status_t (*) (linked_list_t *,size_t, void *))insert_at_position;
	this->public.remove_at_position = (status_t (*) (linked_list_t *,size_t, void **))remove_at_position;
	this->public.get_at_position = (status_t (*) (linked_list_t *,size_t, void **))get_at_position;
	this->public.destroy = (void (*) (linked_list_t *))linked_list_destroy;

	this->count = 0;
	this->first = NULL;
	this->last = NULL;

	return &this->public;
}
