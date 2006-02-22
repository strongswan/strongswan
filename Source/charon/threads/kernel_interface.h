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

#include <linux/xfrm.h>

#include <network/host.h>
#include <encoding/payloads/proposal_substructure.h>

typedef struct kernel_interface_t kernel_interface_t;

/**
 * @brief Interface to the kernel.
 * 
 * @b Constructors:
 *  - kernel_interface_create()
 * 
 * @ingroup threads
 */
struct kernel_interface_t {

	/**
	 * @brief Get a SPI from the kernel
	 * 
	 * @todo Fix spi range
	 */
	status_t (*get_spi) (kernel_interface_t *this, 
				host_t *src, host_t *dest, 
				protocol_id_t protocol, 
				u_int32_t reqid,
				u_int32_t *spi);
	
	/**
	 * @brief Create an SA.
	 * 
	 * @todo Fix reqid and replay_window params
	 * 
	 * @todo Cleanup method params
	 */
	status_t (*add_sa)(kernel_interface_t *this,
				host_t *src, host_t *dst,
				u_int32_t spi,
				protocol_id_t protocol,
				u_int32_t reqid,
				encryption_algorithm_t enc_alg,
				chunk_t encryption_key,
				integrity_algorithm_t int_alg,
				chunk_t integrity_key,
				bool replace);
	
	status_t (*add_policy) (kernel_interface_t *this, 
				host_t *me, host_t *other, 
				host_t *src, host_t *dst,
				u_int8_t src_hostbits, u_int8_t dst_hostbits,
				int direction, int upper_proto, 
				bool ah, bool esp,
				u_int32_t reqid);
	
	/**
	 * @brief Destroys a kernel_interface object.
	 *
	 * @param kernel_interface_t 	calling object
	 */
	void (*destroy) (kernel_interface_t *kernel_interface);
};

/**
 * @brief Creates an object of type kernel_interface_t.
 * 
 * @ingroup threads
 */
kernel_interface_t *kernel_interface_create();

#endif /*KERNEL_INTERFACE_H_*/
