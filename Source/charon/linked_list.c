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
 

/**
 * @brief implements function destroy of linked_list_item_t
 */
static status_t destroy_linked_list_element(linked_list_element_t *linked_list_element)
{
	linked_list_element_t * this = 	linked_list_element;
	pfree(this);
	return SUCCESS;
}

linked_list_element_t *linked_list_element_create(void *value)
{
	linked_list_element_t *this = alloc_thing(linked_list_element_t, "linked_list_element_t");
	
	this->destroy = destroy_linked_list_element;
	
	this->previous=NULL;
	this->next=NULL;
	this->value = value;
	
	return this;
}
 
/**
 * @brief implements function insert_first of linked_list_t
 */
static status_t insert_first(linked_list_t *linked_list, void *item)
{
	linked_list_t *this = linked_list;
	
	linked_list_element_t *element = linked_list_element_create(item);
	
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
		linked_list_element_t *old_first_element = this->first;
		element->next = old_first_element;
		old_first_element->previous = element;
		this->first = element;
	}
	
	this->count++;

	return SUCCESS;
}

/**
 * @brief implements function remove_first of linked_list_t
 */
static status_t remove_first(linked_list_t *linked_list, void **item)
{
	linked_list_t *this = linked_list;
	
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
	
	return	element->destroy(element);
}

/**
 * @brief implements function get_first of linked_list_t
 */
static status_t get_first(linked_list_t *linked_list, void **item)
{
	linked_list_t *this = linked_list;
	
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
static status_t insert_last(linked_list_t *linked_list, void *item)
{
	linked_list_t *this = linked_list;
	
	linked_list_element_t *element = linked_list_element_create(item);
	
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
		old_last_element->next = element;
		this->last = element;
	}
	
	this->count++;
	
	return SUCCESS;
}

/**
 * @brief implements function remove_last of linked_list_t
 */
static status_t remove_last(linked_list_t *linked_list, void **item)
{
	linked_list_t *this = linked_list;
	
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
	
	return	element->destroy(element);
}

/**
 * @brief implements function get_last of linked_list_t
 */
static status_t get_last(linked_list_t *linked_list, void **item)
{
	linked_list_t *this = linked_list;
	
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
 * @brief implements function destroy of linked_list_t
 */
static status_t destroy_linked_list(linked_list_t *linked_list)
{
	linked_list_t *this = linked_list;

	/* Delete all list items before deleting list */
	while (this->count > 0)
	{
		void * value;
		if (this->remove_first(this,&value) != SUCCESS)
		{
			pfree(this);
			return FAILED;
		}
	}
	pfree(this);
	return SUCCESS;
}
 

linked_list_t *linked_list_create() 
{
	linked_list_t *this = alloc_thing(linked_list_t, "linked_list_t");
	
	this->get_first = get_first;
	this->get_last = get_last;
	this->insert_first = insert_first;
	this->insert_last = insert_last;
	this->remove_first = remove_first;
	this->remove_last = remove_last;
	this->destroy = destroy_linked_list;
	
	this->count = 0;
	this->first = NULL;
	this->last = NULL;
	
	return this;
}
