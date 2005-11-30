/**
 * @file linked_list.c
 *
 * @brief Implementation of linked_list_t.
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

#include <stdlib.h>

#include "linked_list.h"

#include <utils/allocator.h>


typedef struct linked_list_element_t linked_list_element_t;

/**
 * @brief Element of the linked_list.
 *
 * This element holds a pointer to the value of the list item itself.
 */
struct linked_list_element_t {
	/**
	 * Value of a list item.
	 */
	void *value;

	/**
	 * previous list element
	 * NULL if first element in list
	 */
	linked_list_element_t *previous;
	
	/**
	 * next list element
	 * NULL if last element in list
	 */
	linked_list_element_t *next;

	/**
	 * Destroys a linked_list_element object.
	 *
	 * @param linked_list_element_t 		calling object
	 */
	void (*destroy) (linked_list_element_t *this);
};

/**
 * Implementation of linked_list_element_t.destroy.
 */
static void linked_list_element_destroy(linked_list_element_t *this)
{
	allocator_free(this);
}

/**
 * @brief Creates an empty linked list object.
 *
 * @warning Only the pointer to the value is stored.
 * 
 * @param[in] value 			value of item to be set
 * @return 						linked_list_element_t object
 */

linked_list_element_t *linked_list_element_create(void *value)
{
	linked_list_element_t *this = allocator_alloc_thing(linked_list_element_t);

	this->destroy = linked_list_element_destroy;

	this->previous=NULL;
	this->next=NULL;
	this->value = value;

	return (this);
}


typedef struct private_linked_list_t private_linked_list_t;
/**
 * Private variables and functions of linked list.
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
 * Implementation of iterator_t.has_next.
 */
bool iterator_has_next(private_iterator_t *this)
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
	if (this ->current->previous != NULL)
	{
		new_current = this->current->previous;
	}
	else if (this->current->next != NULL)
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
	this->current->destroy(this->current);
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

	linked_list_element_t *element =(linked_list_element_t *) linked_list_element_create(item);

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
status_t replace (private_iterator_t *this, void **old_item, void *new_item)
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

	linked_list_element_t *element =(linked_list_element_t *) linked_list_element_create(item);

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
	allocator_free(this);
}

/**
 * Implementation of linked_list_t.get_count.
 */
static int get_count(private_linked_list_t *this)
{
	return this->count;
}


/**
 * Implementation of linked_list_t.insert_first.
 */
static void insert_first(private_linked_list_t *this, void *item)
{
	linked_list_element_t *element;

	element =(linked_list_element_t *) linked_list_element_create(item);

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

	*item = element->value;

	this->count--;

	element->destroy(element);
	
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
	linked_list_element_t *element = (linked_list_element_t *) linked_list_element_create(item);

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

	*item = element->value;

	this->count--;

	element->destroy(element);
	
	return SUCCESS;
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
static iterator_t *create_iterator (private_linked_list_t *linked_list,bool forward)
{
	private_iterator_t *this = allocator_alloc_thing(private_iterator_t);

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

	return &(this->public);
}

/**
 * Implementation of linked_list_t.destroy.
 */
static void linked_list_destroy(private_linked_list_t *this)
{
	void * value;
	/* Remove all list items before destroying list */
	
	while (this->public.remove_first(&(this->public),&value) != NOT_FOUND)
	{
		/* values are not destroyed so memory leaks are possible
		 * if list is not empty when deleting */
	}
	allocator_free(this);
}

/*
 * Described in header
 */
linked_list_t *linked_list_create()
{
	private_linked_list_t *this = allocator_alloc_thing(private_linked_list_t);

	this->public.get_count = (int (*) (linked_list_t *linked_list)) get_count;
	this->public.create_iterator = (iterator_t * (*) (linked_list_t *linked_list,bool forward)) create_iterator;
	this->public.get_first = (status_t (*) (linked_list_t *linked_list, void **item)) get_first;
	this->public.get_last = (status_t (*) (linked_list_t *linked_list, void **item)) get_last;
	this->public.insert_first = (void (*) (linked_list_t *linked_list, void *item)) insert_first;
	this->public.insert_last = (void (*) (linked_list_t *linked_list, void *item)) insert_last;
	this->public.remove_first = (status_t (*) (linked_list_t *linked_list, void **item)) remove_first;
	this->public.remove_last = (status_t (*) (linked_list_t *linked_list, void **item)) remove_last;
	this->public.destroy = (void (*) (linked_list_t *linked_list)) linked_list_destroy;

	this->count = 0;
	this->first = NULL;
	this->last = NULL;

	return (&(this->public));
}
