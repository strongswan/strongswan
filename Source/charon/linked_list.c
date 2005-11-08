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
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

#include "linked_list.h"
 

typedef struct private_linked_list_element_s private_linked_list_element_t;


/**
 * Private Data of a linked list element
 * 
 */
struct private_linked_list_element_s{
	/**
	 * public data of element
	 */
	linked_list_element_t public;
	
	/**
	 * @brief Destroys a linked_list_element object
	 * 
	 * @param linked_list_element_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (private_linked_list_element_t *this);
	
	/**
	 * previous list element 
	 * NULL if first element in list
	 */
	private_linked_list_element_t *previous;
	/**
	 * next list element
	 * NULL if last element in list
	 */
	private_linked_list_element_t *next;
};

/**
 * @brief implements function destroy of linked_list_item_t
 */
static status_t linked_list_element_destroy(private_linked_list_element_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}
	pfree(this);
	return SUCCESS;
}

/*
 * Creates an empty linked list (described in header-file)
 */
linked_list_element_t *linked_list_element_create(void *value)
{
	private_linked_list_element_t *this = alloc_thing(private_linked_list_element_t, "private_linked_list_element_t");
	
	if (this == NULL)
	{
		return NULL;
	}
	
	this->destroy = linked_list_element_destroy;
	
	this->previous=NULL;
	this->next=NULL;
	this->public.value = value;
	
	return (&this->public);
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
	private_linked_list_element_t *first;
	/**
	 * Last element in list
	 * NULL if no elements in list
	 */
	private_linked_list_element_t *last;
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
	private_linked_list_element_t *current;

	/**
	 * direction of iterator
	 */
	bool forward;
};

/**
 * Implements function has_next of linked_list_iteratr
 */
static status_t iterator_has_next(private_linked_list_iterator_t *this, bool * has_next)
{
	if (this->list->count == 0)
	{
		*has_next = FALSE;
		return SUCCESS;
	}
	if (this->current == NULL)
	{
		this->current = (this->forward) ? this->list->first : this->list->last;
		*has_next = TRUE;
		return SUCCESS;		
	}
	if (this->forward)
	{
		if (this->current->next == NULL)
		{
			*has_next = FALSE;
			return SUCCESS;
		}
		this->current = this->current->next;
		*has_next = TRUE;
		return SUCCESS;		
	}
	/* backward */	
	if (this->current->previous == NULL)
	{
		*has_next = FALSE;
		return SUCCESS;
	}
	this->current = this->current->previous;
	*has_next = TRUE;
	return SUCCESS;		
}

/**
 * Implements function current of linked_list_iteratr
 */
static status_t iterator_current(private_linked_list_iterator_t *this, linked_list_element_t **element)
{
	*element = &(this->current->public);
	return SUCCESS;
}

/**
 * Implements function current of linked_list_iteratr
 */
static status_t iterator_reset(private_linked_list_iterator_t *this)
{
	this->current = NULL;
	return SUCCESS;
}

/**
 * Implements function destroy of linked_list_iteratr
 */
static status_t iterator_destroy(private_linked_list_iterator_t *this)
{
	pfree(this);
	return SUCCESS;
}

/**
 * @brief implements function get_count of linked_list_t
 */
static status_t get_count(private_linked_list_t *this, int *count)
{
	*count = this->count;
	return SUCCESS;
}


static status_t create_iterator (private_linked_list_t *linked_list, linked_list_iterator_t **iterator,bool forward)
{
	private_linked_list_iterator_t *this = alloc_thing(private_linked_list_iterator_t, "private_linked_list_iterator_t");
	
	if (this == NULL)
	{
		return FAILED;
	}
	
	this->public.has_next = (status_t (*) (linked_list_iterator_t *this, bool * has_next)) iterator_has_next;
	this->public.current = (status_t (*) (linked_list_iterator_t *this, linked_list_element_t **element)) iterator_current;
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
	private_linked_list_element_t *element =(private_linked_list_element_t *) linked_list_element_create(item);
	
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
		private_linked_list_element_t *old_first_element = this->first;
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
	if (this->count == 0)
	{
		return FAILED;
	}
	
	if (this->first == NULL)
	{
		return FAILED;
	}
	
	private_linked_list_element_t *element = this->first;
	
	if (element->next != NULL)
	{
		element->next->previous = NULL;
	}
	this->first = element->next;

	*item = element->public.value;

	this->count--;
	
	return	(element->destroy(element));
}

/**
 * @brief implements function get_first of linked_list_t
 */
static status_t get_first(private_linked_list_t *this, void **item)
{	
	if (this->count == 0)
	{
		return FAILED;
	}
	
	if (this->first == NULL)
	{
		return FAILED;
	}
	
	*item = this->first->public.value;

	return SUCCESS;
}

/**
 * @brief implements function insert_last of linked_list_t
 */
static status_t insert_last(private_linked_list_t *this, void *item)
{
	private_linked_list_element_t *element = (private_linked_list_element_t *) linked_list_element_create(item);
	
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
		private_linked_list_element_t *old_last_element = this->last;
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
	if (this->count == 0)
	{
		return FAILED;
	}
	
	if (this->last == NULL)
	{
		return FAILED;
	}
	
	private_linked_list_element_t *element = this->last;
	
	if (element->previous != NULL)
	{
		element->previous->next = NULL;
	}
	this->last = element->previous;

	*item = element->public.value;

	this->count--;
	
	return	(element->destroy(element));
}

/**
 * @brief implements function get_last of linked_list_t
 */
static status_t get_last(private_linked_list_t *this, void **item)
{
	if (this->count == 0)
	{
		return FAILED;
	}
	
	if (this->last == NULL)
	{
		return FAILED;
	}
	
	*item = this->last->public.value;

	return SUCCESS;
}

/**
 * @brief implements function insert_before of linked_list_t
 */
static status_t insert_before(private_linked_list_t *this, private_linked_list_element_t * next_element, void *item)
{
	if (this->count == 0)
	{
		return FAILED;
	}

	private_linked_list_element_t *element =(private_linked_list_element_t *) linked_list_element_create(item);
	
	if (element == NULL)
	{
		return FAILED;
	}
	
	if (next_element->previous == NULL)
	{
		if (this->first != next_element)
		{
			element->destroy(element);
			return FAILED;
		}
		
		next_element->previous = element;
		element->next = next_element;
		this->first = element;
	}
	else
	{
		next_element->previous->next = element;
		element->previous = next_element->previous;
		next_element->previous = element;
		element->next = next_element;
	}
	
	this->count++;

	return SUCCESS;
}

/**
 * @brief implements function insert_after of linked_list_t
 */
static status_t insert_after(private_linked_list_t *this, private_linked_list_element_t * previous_element, void *item)
{
	if (this->count == 0)
	{
		return FAILED;
	}

	private_linked_list_element_t *element =(private_linked_list_element_t *) linked_list_element_create(item);
	
	if (element == NULL)
	{
		return FAILED;
	}
	
	if (previous_element->next == NULL)
	{
		if (this->last != previous_element)
		{
			element->destroy(element);
			return FAILED;
		}
		
		previous_element->next = element;
		element->previous = previous_element;
		this->last = element;
	}
	else
	{
		previous_element->next->previous = element;
		element->next = previous_element->next;
		previous_element->next = element;
		element->previous = previous_element;
	}
	
	this->count++;
	return SUCCESS;
}

/**
 * @brief implements function remove of linked_list_t
 */
static status_t linked_list_remove(private_linked_list_t *this, private_linked_list_element_t * element)
{
	if (this->count == 0)
	{
		return FAILED;
	}
	
	if (element->previous == NULL)
	{	
		if (element->next == NULL)
		{
			this->first = NULL; 	
		 	this->last = NULL;
		}
		else
		{
			element->next->previous = NULL;
			this->first = element->next;
		}
	}
	else if (element->next == NULL)
	{
		element->previous->next = NULL;
		this->last = element->previous;
	}
	else
	{
		element->previous->next = element->next;
		element->next->previous = element->previous;
	}
	
 	this->count--;
 	element->destroy(element);
 	return SUCCESS;
}

/**
 * @brief implements function destroy of linked_list_t
 */
static status_t linked_list_destroy(private_linked_list_t *this)
{
	/* Remove all list items before destroying list */
	while (this->count > 0)
	{
		void * value;
		/* values are not destroyed so memory leaks are possible
		 * if list is not empty when deleting */
		if (this->public.remove_first(&(this->public),&value) != SUCCESS)
		{
			pfree(this);
			return FAILED;
		}
	}
	pfree(this);
	return SUCCESS;
}
 
/*
 * Described in header
 */
linked_list_t *linked_list_create() 
{
	private_linked_list_t *this = alloc_thing(private_linked_list_t, "private_linked_list_t");
	
	this->public.get_count = (status_t (*) (linked_list_t *linked_list, int *count)) get_count;
	this->public.create_iterator = (status_t (*) (linked_list_t *linked_list, linked_list_iterator_t **iterator,bool forward)) create_iterator;
	this->public.get_first = (status_t (*) (linked_list_t *linked_list, void **item)) get_first;
	this->public.get_last = (status_t (*) (linked_list_t *linked_list, void **item)) get_last;
	this->public.insert_first = (status_t (*) (linked_list_t *linked_list, void *item)) insert_first;
	this->public.insert_last = (status_t (*) (linked_list_t *linked_list, void *item)) insert_last;
	this->public.insert_before = (status_t (*) (linked_list_t *linked_list, linked_list_element_t * element, void *item)) insert_before;
	this->public.insert_after = (status_t (*) (linked_list_t *linked_list, linked_list_element_t * element, void *item)) insert_after;
	this->public.remove = (status_t (*) (linked_list_t *linked_list, linked_list_element_t * element)) linked_list_remove;
	this->public.remove_first = (status_t (*) (linked_list_t *linked_list, void **item)) remove_first;
	this->public.remove_last = (status_t (*) (linked_list_t *linked_list, void **item)) remove_last;
	this->public.destroy = (status_t (*) (linked_list_t *linked_list)) linked_list_destroy;
	
	this->count = 0;
	this->first = NULL;
	this->last = NULL;
	
	return (&(this->public));
}
