/**
 * @file dead_peer_detection.h
 * 
 * @brief Interface of transaction dead_peer_detection.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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


#ifndef DEAD_PEER_DETECTION_H_
#define DEAD_PEER_DETECTION_H_

#include <sa/ike_sa.h>
#include <sa/transactions/transaction.h>


typedef struct dead_peer_detection_t dead_peer_detection_t;

/**
 * @brief A transaction used to detect dead peers.
 *
 * In IKEv2, dead peer detection is done using empty
 * informational messages. These must be acknowledged.
 *
 * @ingroup transactions
 */
struct dead_peer_detection_t {
	
	/**
	 * The transaction_t interface.
	 */
	transaction_t transaction;
};

/**
 * @brief Create a new transaction which detects dead peers.
 *
 * @param ike_sa		assigned IKE_SA
 * @return				created dead_peer_detection transaction
 *
 * @ingroup transactions
 */
dead_peer_detection_t *dead_peer_detection_create(ike_sa_t *ike_sa);

#endif /* DEAD_PEER_DETECTION_H_ */
