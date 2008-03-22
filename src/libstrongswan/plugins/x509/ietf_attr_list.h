/*
 * Copyright (C) 2007 Andreas Steffen
 *
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
 * @defgroup ietf_attr_list ietf_attr_list
 * @{ @ingroup x509_p
 */

#ifndef IETF_ATTR_LIST_H_
#define IETF_ATTR_LIST_H_

#include <library.h>
#include <utils/linked_list.h>


/**
 * @brief Compare two linked lists of ietfAttr_t objects for equality
 *
 * @param list_a	first alphabetically-sorted list
 * @param list_b	second alphabetically-sorted list
 * @return			TRUE if equal	
 */
bool ietfAttr_list_equals(linked_list_t *list_a, linked_list_t *list_b);

/**
 * @brief Lists a linked list of ietfAttr_t objects
 *
 * @param list		alphabetically-sorted linked list of attributes
 * @param out		output file	
 */
void ietfAttr_list_list(linked_list_t *list, FILE *out);

/**
 * @brief Create a linked list of ietfAttr_t objects from a string
 *
 * @param msg		string with comma-separated group names
 * @param list		alphabetically-sorted linked list of attributes
  */
void ietfAttr_list_create_from_string(char *msg, linked_list_t *list);

/**
 * @brief Create a linked list of ietfAttr_t objects from an ASN.1-coded chunk
 *
 * @param chunk		chunk containing ASN.1-coded attributes
 * @param list		alphabetically-sorted linked list of attributes
 * @param level0	parsing level
 */
void ietfAttr_list_create_from_chunk(chunk_t chunk, linked_list_t *list, int level0);

/**
 * @brief Encode a linked list of ietfAttr_t objects into an ASN.1-coded chunk
 *
 * @param list		alphabetically-sorted linked list of attributes
 * @return			chunk containing ASN.1-coded attributes
 */
chunk_t ietfAttr_list_encode(linked_list_t *list);

/**
 * @brief Destroys a linked list of ietfAttr_t objects
 *
 * @param list		list to be destroyed
 */
void ietfAttr_list_destroy(linked_list_t *list);

#endif /* IETF_ATTR_LIST_H_ @}*/

