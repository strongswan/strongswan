/*
 * Copyright (C) 2013 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 *
 * @defgroup imv_session_t imv_session
 * @{ @ingroup libimcv_imv
 */

#ifndef  IMV_SESSION_H_
#define  IMV_SESSION_H_

#include "imv_workitem.h"

#include <tncifimv.h>

#include <library.h>

typedef struct imv_session_t imv_session_t;

/**
 * IMV session interface
 */
struct imv_session_t {

	/**
	 * Get unique session ID
	 *
	 * @return				Session ID
	 */
	int (*get_session_id)(imv_session_t *this);

	/**
	 * Get TNCCS Connection ID
	 *
	 * @return				TNCCS Connection ID
	 */
	TNC_ConnectionID (*get_connection_id)(imv_session_t *this);

	/**
	 * Set policy_started status
	 *
	 * @param start			TRUE if policy started, FALSE if policy stopped
	 */
	void (*set_policy_started)(imv_session_t *this, bool start);

	/**
	 * Get policy_started status
	 *
	 * @return				TRUE if policy started, FALSE if policy stopped
	 */
	bool (*get_policy_started)(imv_session_t *this);

	/**
	 * Insert workitem into list
	 *
	 * @param workitem		Workitem to be inserted
	 */
	void (*insert_workitem)(imv_session_t *this, imv_workitem_t *workitem);

	/**
	 * Remove workitem from list
	 *
	 * @param enumerator	Enumerator pointing to workitem to be removed
	 */
	void (*remove_workitem)(imv_session_t *this, enumerator_t *enumerator);

	/**
	 * Create workitem enumerator
	 *
	 */
	 enumerator_t* (*create_workitem_enumerator)(imv_session_t *this);

	/**
	 * Get number of workitem allocated to a given IMV
	 *
	 * @param imv_id		IMV ID
	 * @return				Number of workitems assigned to given IMV
	 */
	 int (*get_workitem_count)(imv_session_t *this, TNC_IMVID imv_id);

	/**
	 * Get reference to session
	 */
	imv_session_t* (*get_ref)(imv_session_t*);

	/**
	 * Destroys an imv_session_t object
	 */
	void (*destroy)(imv_session_t *this);
};

/**
 * Create an imv_session_t instance
 *
 * @param session_id		Unique Session ID
 * @param id				Associated Connection ID
 */
imv_session_t* imv_session_create(int session_id, TNC_ConnectionID id);

#endif /**  IMV_SESSION_H_ @}*/
