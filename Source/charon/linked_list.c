/**
 * @file linked_list.c
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

#include <stdlib.h>

#include "allocator.h"
#include "linked_list.h"


typedef struct linked_list_element_s linked_list_element_t;


/**
 * @brief Element of the linked_list.
 *
 * This element holds a pointer to the value of the list item itself.
 */
struct linked_list_element_s{
	/**
	 * value of a list item
	 */
	void *value;

	/**
	 * @brief Destroys a linked_list_element object
	 *
	 * @param linked_list_element_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (linked_list_element_t *this);

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
};

/**
 * @brief implements function destroy of linked_list_item_t
 */
static status_t linked_list_element_destroy(linked_list_element_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	allocator_free(this);
	return SUCCESS;
}

/**
 * @brief Creates an empty linked list object
 *
 * @param[in] value value of item to be set
 *
 * @warning only the pointer to the value is stored
 *
 * @return linked_list_element object
 */

linked_list_element_t *linked_list_element_create(void *value)
{
	linked_list_element_t *this = allocator_alloc_thing(linked_list_element_t);

	if (this == NULL)
	{
		return NULL;
	}

	this->destroy = linked_list_element_destroy;

	this->previous=NULL;
	this->next=NULL;
	this->value = value;

	return (this);
}

/**
 * Private variables and functions of linked list
 *
 */
typedef struct private_linked_list_s private_linked_list_t;

struct private_linked_list_s{
	/**
	 * Public part of linked list
	 */
	linked_list_t public;

	/**
	 * number of items in the list
	 */
	int count;

	/**
	 * First element in list
	 * NULL if no elements in list
	 */
	linked_list_element_t *first;
	/**
	 * Last element in list
	 * NULL if no elements in list
	 */
	linked_list_element_t *last;
};


/**
 * Private variables and functions of linked list iterator
 *
 */
typedef struct private_linked_list_iterator_s private_linked_list_iterator_t;

struct private_linked_list_iterator_s{
	/**
	 * Public part of linked list iterator
	 */
	linked_list_iterator_t public;

	/**
	 * associated linked list
	 */
	private_linked_list_t * list;

	/**
	 * current element of the iterator
	 */
	linked_list_element_t *current;

	/**
	 * direction of iterator
	 */
	bool forward;
};

/**
 * Implements function has_next of linked_list_iteratr
 */
bool iterator_has_next(private_linked_list_iterator_t *this)
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
 * Implements function current of linked_list_iteratr
 */
static status_t iterator_current(private_linked_list_iterator_t *this, void **value)
{
	if (this == NULL)
	{
		return FAILED;
	}
	if (this->current == NULL)
	{
		return FAILED;
	}
	*value = this->current->value;
	return SUCCESS;
}

/**
 * Implements function current of linked_list_iteratr
 */
static status_t iterator_reset(private_linked_list_iterator_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	this->current = NULL;
	return SUCCESS;
}

/**
 * Implements function destroy of linked_list_iteratr
 */
static status_t iterator_destroy(private_linked_list_iterator_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	allocator_free(this);
	return SUCCESS;
}

/**
 * @brief implements function get_count of linked_list_t
 */
static int get_count(private_linked_list_t *this)
{
	return this->count;
}


static status_t create_iterator (private_linked_list_t *linked_list, linked_list_iterator_t **iterator,bool forward)
{
	private_linked_list_iterator_t *this = allocator_alloc_thing(private_linked_list_iterator_t);

	if (this == NULL)
	{
		return FAILED;
	}

	this->public.has_next = (bool (*) (linked_list_iterator_t *this)) iterator_has_next;
	this->public.current = (status_t (*) (linked_list_iterator_t *this, void **value)) iterator_current;
	this->public.reset = (status_t (*) (linked_list_iterator_t *this)) iterator_reset;
	this->public.destroy = (status_t (*) (linked_list_iterator_t *this)) iterator_destroy;


	this->forward = forward;
	this->current = NULL;
	this->list = linked_list;

	*iterator = &(this->public);

	return (SUCCESS);
}


/**
 * @brief implements function insert_first of linked_list_t
 */
static status_t insert_first(private_linked_list_t *this, void *item)
{
	linked_list_element_t *element;

	if (this == NULL)
	{
		return FAILED;
	}

	element =(linked_list_element_t *) linked_list_element_create(item);

	if (element == NULL)
	{
		return FAILED;
	}

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
		if ((this->first == NULL) || (this->last == NULL))
		{
			/* should never happen */
			element->destroy(element);
			return FAILED;
		}
		linked_list_element_t *old_first_element = this->first;
		element->next = old_first_element;
		element->previous = NULL;
		old_first_element->previous = element;
		this->first = element;
	}

	this->count++;

	return SUCCESS;
}

/**
 * @brief implements function remove_first of linked_list_t
 */
static status_t remove_first(private_linked_list_t *this, void **item)
{
	if (this == NULL)
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}

	if (this->first == NULL)
	{
		return FAILED;
	}

	linked_list_element_t *element = this->first;

	if (element->next != NULL)
	{
		element->next->previous = NULL;
	}
	this->first = element->next;

	*item = element->value;

	this->count--;

	return	(element->destroy(element));
}

/**
 * @brief implements function get_first of linked_list_t
 */
static status_t get_first(private_linked_list_t *this, void **item)
{
	if (this == NULL)
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}

	if (this->first == NULL)
	{
		return FAILED;
	}

	*item = this->first->value;

	return SUCCESS;
}

/**
 * @brief implements function insert_last of linked_list_t
 */
static status_t insert_last(private_linked_list_t *this, void *item)
{
	if (this == NULL)
	{
		return FAILED;
	}

	linked_list_element_t *element = (linked_list_element_t *) linked_list_element_create(item);

	if (element == NULL)
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		/* first entry in list */
		this->first = element;
		this->last = element;
		element->previous = NULL;
		element->next = NULL;
	}else
	{
		if ((this->first == NULL) || (this->last == NULL))
		{
			/* should never happen */
			element->destroy(element);
			return FAILED;
		}
		linked_list_element_t *old_last_element = this->last;
		element->previous = old_last_element;
		element->next = NULL;
		old_last_element->next = element;
		this->last = element;
	}

	this->count++;

	return SUCCESS;
}

/**
 * @brief implements function remove_last of linked_list_t
 */
static status_t remove_last(private_linked_list_t *this, void **item)
{
	if (this == NULL)
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}

	if (this->last == NULL)
	{
		return FAILED;
	}

	linked_list_element_t *element = this->last;

	if (element->previous != NULL)
	{
		element->previous->next = NULL;
	}
	this->last = element->previous;

	*item = element->value;

	this->count--;

	return	(element->destroy(element));
}

/**
 * @brief implements function get_last of linked_list_t
 */
static status_t get_last(private_linked_list_t *this, void **item)
{
	if (this == NULL)
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}

	if (this->last == NULL)
	{
		return FAILED;
	}

	*item = this->last->value;

	return SUCCESS;
}

/**
 * @brief implements function insert_before of linked_list_t
 */
static status_t insert_before(private_linked_list_t *this, private_linked_list_iterator_t * iterator, void *item)
{
	if ((this == NULL) || (iterator == NULL))
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}

	if (iterator->current == NULL)
	{
		return (this->public.insert_first(&this->public,item));
	}

	linked_list_element_t *element =(linked_list_element_t *) linked_list_element_create(item);

	if (element == NULL)
	{
		return FAILED;
	}

	if (iterator->current->previous == NULL)
	{
		if (this->first != iterator->current)
		{
			element->destroy(element);
			return FAILED;
		}

		iterator->current->previous = element;
		element->next = iterator->current;
		this->first = element;
	}
	else
	{
		iterator->current->previous->next = element;
		element->previous = iterator->current->previous;
		iterator->current->previous = element;
		element->next = iterator->current;
	}

	this->count++;

	return SUCCESS;
}

/**
 * @brief implements function insert_after of linked_list_t
 */
static status_t insert_after(private_linked_list_t *this, private_linked_list_iterator_t * iterator, void *item)
{
	if ((this == NULL) || (iterator == NULL))
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}

	if (iterator->current == NULL)
	{
		return (this->public.insert_first(&this->public,item));
	}

	linked_list_element_t *element =(linked_list_element_t *) linked_list_element_create(item);

	if (element == NULL)
	{
		return FAILED;
	}

	if (iterator->current->next == NULL)
	{
		if (this->last != iterator->current)
		{
			element->destroy(element);
			return FAILED;
		}

		iterator->current->next = element;
		element->previous = iterator->current;
		this->last = element;
	}
	else
	{
		iterator->current->next->previous = element;
		element->next = iterator->current->next;
		iterator->current->next = element;
		element->previous = iterator->current;
	}

	this->count++;
	return SUCCESS;
}

/**
 * @brief implements function remove of linked_list_t
 */
static status_t linked_list_remove(private_linked_list_t *this, private_linked_list_iterator_t * iterator)
{
	linked_list_element_t *new_current;

	if ((this == NULL) || (iterator == NULL) || (iterator->current == NULL))
	{
		return FAILED;
	}

	if (this->count == 0)
	{
		return FAILED;
	}
	/* find out the new iterator position */
	if (iterator->current->previous != NULL)
	{
		new_current = iterator->current->previous;
	}
	else if (iterator->current->next != NULL)
	{
		new_current = iterator->current->next;
	}
	else
	{
		new_current = NULL;
	}

	/* now delete the entry :-) */
	if (iterator->current->previous == NULL)
	{
		if (iterator->current->next == NULL)
		{
			this->first = NULL;
		 	this->last = NULL;
		}
		else
		{
			iterator->current->next->previous = NULL;
			this->first = iterator->current->next;
		}
	}
	else if (iterator->current->next == NULL)
	{
		iterator->current->previous->next = NULL;
		this->last = iterator->current->previous;
	}
	else
	{
		iterator->current->previous->next = iterator->current->next;
		iterator->current->next->previous = iterator->current->previous;
	}

 	this->count--;
 	iterator->current->destroy(iterator->current);
 	/* set the new iterator position */
 	iterator->current = new_current;
 	return SUCCESS;
}

/**
 * @brief implements function destroy of linked_list_t
 */
static status_t linked_list_destroy(private_linked_list_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}

	/* Remove all list items before destroying list */
	while (this->count > 0)
	{
		void * value;
		/* values are not destroyed so memory leaks are possible
		 * if list is not empty when deleting */
		if (this->public.remove_first(&(this->public),&value) != SUCCESS)
		{
			allocator_free(this);
			return FAILED;
		}
	}
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
linked_list_t *linked_list_create()
{
	private_linked_list_t *this = allocator_alloc_thing(private_linked_list_t);

	this->public.get_count = (int (*) (linked_list_t *linked_list)) get_count;
	this->public.create_iterator = (status_t (*) (linked_list_t *linked_list, linked_list_iterator_t **iterator,bool forward)) create_iterator;
	this->public.get_first = (status_t (*) (linked_list_t *linked_list, void **item)) get_first;
	this->public.get_last = (status_t (*) (linked_list_t *linked_list, void **item)) get_last;
	this->public.insert_first = (status_t (*) (linked_list_t *linked_list, void *item)) insert_first;
	this->public.insert_last = (status_t (*) (linked_list_t *linked_list, void *item)) insert_last;
	this->public.insert_before = (status_t (*) (linked_list_t *linked_list, linked_list_iterator_t * element, void *item)) insert_before;
	this->public.insert_after = (status_t (*) (linked_list_t *linked_list, linked_list_iterator_t * element, void *item)) insert_after;
	this->public.remove = (status_t (*) (linked_list_t *linked_list, linked_list_iterator_t * element)) linked_list_remove;
	this->public.remove_first = (status_t (*) (linked_list_t *linked_list, void **item)) remove_first;
	this->public.remove_last = (status_t (*) (linked_list_t *linked_list, void **item)) remove_last;
	this->public.destroy = (status_t (*) (linked_list_t *linked_list)) linked_list_destroy;

	this->count = 0;
	this->first = NULL;
	this->last = NULL;

	return (&(this->public));
}
