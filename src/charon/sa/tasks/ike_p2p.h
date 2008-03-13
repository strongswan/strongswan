/*
 * Copyright (C) 2007 Tobias Brunner
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
 * @defgroup ike_p2p ike_p2p
 * @{ @ingroup tasks
 */

#ifndef IKE_P2P_H_
#define IKE_P2P_H_

typedef struct ike_p2p_t ike_p2p_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>

/**
 * Task of type IKE_P2P, detects and handles P2P-NAT-T extensions.
 *
 * This tasks handles the P2P_MEDIATION notify exchange to setup a mediation
 * connection, allows to initiate mediated connections using P2P_CONNECT
 * exchanges and to request reflexive addresses from the mediation server using
 * P2P_ENDPOINT notifies.
 * 
 * @note This task has to be activated before the IKE_AUTH task, because that
 * task generates the IKE_SA_INIT message so that no more payloads can be added
 * to it afterwards.
 */
struct ike_p2p_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
	
	/**
	 * Initiates a connection with another peer (i.e. sends a P2P_CONNECT
	 * to the mediation server)
	 *
	 * @param peer_id			ID of the other peer (gets cloned)
	 */
	void (*connect)(ike_p2p_t *this, identification_t *peer_id);
	
	/**
	 * Responds to a P2P_CONNECT from another peer (i.e. sends a P2P_CONNECT
	 * to the mediation server)
	 * 
	 * @param peer_id			ID of the other peer (gets cloned)
	 * @param session_id		the session ID as provided by the initiator (gets cloned)
	 */
	void (*respond)(ike_p2p_t *this, identification_t *peer_id, chunk_t session_id);
	
	/**
	 * Sends a P2P_CALLBACK to a peer that previously requested another peer.
	 * 
	 * @param peer_id			ID of the other peer (gets cloned)
	 */
	void (*callback)(ike_p2p_t *this, identification_t *peer_id);
	
	/**
	 * Relays data to another peer (i.e. sends a P2P_CONNECT to the peer)
	 * 
	 * Data gets cloned.
	 * 
	 * @param requester			ID of the requesting peer
	 * @param session_id		content of the P2P_SESSIONID notify
	 * @param session_key		content of the P2P_SESSIONKEY notify
	 * @param endpoints			endpoints
	 * @param response			TRUE if this is a response
	 */
	void (*relay)(ike_p2p_t *this, identification_t *requester, chunk_t session_id,
			chunk_t session_key, linked_list_t *endpoints, bool response);

};

/**
 * Create a new ike_p2p task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE if taks is initiated by us
 * @return			  	ike_p2p task to handle by the task_manager
 */
ike_p2p_t *ike_p2p_create(ike_sa_t *ike_sa, bool initiator);

#endif /*IKE_P2P_H_ @} */
