/**
 * @file kernel_interface.h
 *
 * @brief Interface of kernel_interface_t.
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

#ifndef KERNEL_INTERFACE_H_
#define KERNEL_INTERFACE_H_



typedef struct kernel_interface_t kernel_interface_t;

/**
 * @brief 
 * 
 * @ingroup threads
 */
struct kernel_interface_t {

	/**
	 * @brief Destroys a kernel_interface object.
	 *
	 * Stopps the prime thread and destroys the pool.
	 *
	 * @param kernel_interface_t 	calling object
	 */
	void (*destroy) (kernel_interface_t *kernel_interface);
};

/**
 * @brief 
 * 
 * @ingroup threads
 */
kernel_interface_t *kernel_interface_create();

#endif /*KERNEL_INTERFACE_H_*/
