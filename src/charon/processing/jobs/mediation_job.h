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
 * @defgroup mediation_job mediation_job
 * @{ @ingroup jobs
 */

#ifndef MEDIATION_JOB_H_
#define MEDIATION_JOB_H_

typedef struct mediation_job_t mediation_job_t;

#include <library.h>
#include <processing/jobs/job.h>
#include <utils/identification.h>
#include <utils/linked_list.h>

/**
 * Class representing a MEDIATION Job.
 * 
 * This job handles the mediation on the mediation server.
 */
struct mediation_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * Creates a job of type MEDIATION.
 * 
 * Parameters get cloned.
 * 
 * @param peer_id		ID of the requested peer
 * @param requester		ID of the requesting peer
 * @param session_id	content of P2P_SESSIONID (could be NULL)
 * @param session_key	content of P2P_SESSIONKEY
 * @param endpoints		list of submitted endpoints
 * @param response		TRUE if this is a response
 * @return				job object
 */
mediation_job_t *mediation_job_create(identification_t *peer_id,
		identification_t *requester, chunk_t session_id, chunk_t session_key,
		linked_list_t *endpoints, bool response);


/**
 * Creates a special job of type MEDIATION that is used to send a callback
 * notification to a peer.
 * 
 * Parameters get cloned.
 * 
 * @param requester		ID of the waiting peer
 * @param peer_id		ID of the requested peer
 * @return				job object
 */
mediation_job_t *mediation_callback_job_create(identification_t *requester,
		identification_t *peer_id);

#endif /*MEDIATION_JOB_H_ @} */
