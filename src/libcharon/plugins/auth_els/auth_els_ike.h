/* Copyright (C) 2019-2020 Marvell */

/**
 * @defgroup auth_els_ike auth_els_ike
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_IKE_H_
#define AUTH_ELS_IKE_H_

#include <collections/hashtable.h>
#include <sa/ike_sa.h>
#include <daemon.h>

typedef struct auth_els_ike_t auth_els_ike_t;
/**
 * Listener to synchronize IKE_SAs.
 */
struct auth_els_ike_t {

	/**
	 * Implements bus listener interface.
	 */
	listener_t listener;

	/**
	 * Destroy a auth_els_ike_t.
	 */
	void (*destroy)(auth_els_ike_t *this);

};

/**
 * Create a auth_els_ike instance.
 *
 * @param cache			message cache
 * @param cache			List of rport sockets
 * @return				IKE listener
 */
auth_els_ike_t *auth_els_ike_create(auth_els_plugin_t *plugin_ref);

#endif /** AUTH_ELS_IKE_ @}*/
