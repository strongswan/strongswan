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
 * @defgroup imv_database_t imv_database
 * @{ @ingroup libimcv_imv
 */

#ifndef IMV_DATABASE_H_
#define IMV_DATABASE_H_

#include <tncif.h>

#include <library.h>

typedef struct imv_database_t imv_database_t;

/**
 * IMV database interface 
 */
struct imv_database_t {

	/**
	 * Register or get a unique session ID using the TNCCS connection ID
	 *
	 * @param id			TNCCS Connection ID
	 * @param ar_id_type	Access Requestor identity type
	 * @param ar_id_value	Access Requestor identity value
	 * @return				Session ID or 0 if not available
	 */
	 int (*get_session_id)(imv_database_t *this, TNC_ConnectionID id,
						   u_int32_t ar_id_type, chunk_t ar_id_value);

	/**
	 * Add product information string to a session
	 *
	 * @param session_id	Session ID
	 * @param product		Product information string
	 * @return				Product ID or 0 if not available
	 */
	 int (*add_product)(imv_database_t *this, int session_id, char *product);

	/**
	 * Add device identification to a session
	 *
	 * @param session_id	Session ID
	 * @param device		Device identification
	 * @return				Device ID or 0 if not available
	 */
	 int (*add_device)(imv_database_t *this, int session_id, chunk_t device);

	/**
	 * Announce session start/stop to policy script
	 *
	 * @param session_id	Session ID
	 * @param start			TRUE if session start, FALSE if session stop
	 * @return				TRUE if command successful, FALSE otherwise
	 */
	 bool (*policy_script)(imv_database_t *this, int session_id, bool start);

	/**
	 * Create enumerator for workitems assigned to a session ID
	 *
	 * @param session_id	Session ID
	 * @return				Enumerator of workitems assigned to session ID
	 */
	 enumerator_t* (*create_workitem_enumerator)(imv_database_t *this,
					int session_id);

	/**
	 * Get database handle
	 *
	 * @return				Database handle
	 */
	 database_t* (*get_database)(imv_database_t *this);

	/**
	 * Destroys an imv_database_t object
	 */
	void (*destroy)(imv_database_t *this);
};

/**
 * Create an imv_database_t instance
 *
 * @param uri			database uri
 */
imv_database_t* imv_database_create(char *uri);

#endif /** IMV_DATABASE_H_ @}*/
