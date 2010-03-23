/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

/**
 * @defgroup dhcp_transaction dhcp_transaction
 * @{ @ingroup dhcp
 */

#ifndef DHCP_TRANSACTION_H_
#define DHCP_TRANSACTION_H_

#include <utils/host.h>
#include <utils/identification.h>

typedef struct dhcp_transaction_t dhcp_transaction_t;

/**
 * DHCP transaction class.
 */
struct dhcp_transaction_t {

	/**
	 * Get the DCHP transaction ID.
	 *
	 * @return			DHCP transaction identifier
	 */
	u_int32_t (*get_id)(dhcp_transaction_t *this);

	/**
	 * Get the peer identity this transaction is used for.
	 *
	 * @return			peer Identity
	 */
	identification_t* (*get_identity)(dhcp_transaction_t *this);

	/**
	 * Set the DHCP address received using this transaction.
	 *
	 * @param host		received DHCP address
	 */
	void (*set_address)(dhcp_transaction_t *this, host_t *address);

	/**
	 * Get the DHCP address received using this transaction.
	 *
	 * @return			received DHCP address
	 */
	host_t* (*get_address)(dhcp_transaction_t *this);

	/**
	 * Destroy a dhcp_transaction_t.
	 */
	void (*destroy)(dhcp_transaction_t *this);
};

/**
 * Create a dhcp_transaction instance.
 *
 * @param id		DHCP transaction identifier
 * @param identity	peer identity this transaction is used for
 * @return			transaction instance
 */
dhcp_transaction_t *dhcp_transaction_create(u_int32_t id,
											identification_t *identity);

#endif /** DHCP_TRANSACTION_H_ @}*/
