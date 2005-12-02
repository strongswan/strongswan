/**
 * @file retransmit_request_job.c
 * 
 * @brief Interface of retransmit_request_job_t.
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

#ifndef _RESEND_MESSAGE_JOB_H_
#define _RESEND_MESSAGE_JOB_H_

#include <types.h>
#include <queues/jobs/job.h>
#include <sa/ike_sa_id.h>


typedef struct retransmit_request_job_t retransmit_request_job_t;

/**
 * Object representing an RETRANSMIT_REQUEST Job.
 * 
 * @ingroup jobs
 */
struct retransmit_request_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
	
	/**
	 * @brief Returns the message_id of the request to be resent
	 *
	 * @param this 	calling retransmit_request_job_t object
	 * @return 		message id of the request to resend
	 */
	u_int32_t (*get_message_id) (retransmit_request_job_t *this);
	
	/**
	 * @brief Returns the ike_sa_id_t object of the IKE_SA 
	 * 		  which the request belongs to
	 * 
	 * @warning returned ike_sa_id_t object is getting destroyed in 
	 * retransmit_request_job_t.destroy.
	 *
	 * @param this 	calling retransmit_request_job_t object
	 * @return 		ike_sa_id_t object to identify IKE_SA (gets NOT cloned)
	 */
	ike_sa_id_t *(*get_ike_sa_id) (retransmit_request_job_t *this);

	/**
	 * @brief Destroys an retransmit_request_job_t object.
	 *
	 * @param this 	retransmit_request_job_t object to destroy
	 */
	void (*destroy) (retransmit_request_job_t *this);
};

/**
 * @brief Creates a job of type RETRANSMIT_REQUEST.
 * 
 * @param message_id		message_id of the request to resend
 * @param ike_sa_id			identification of the ike_sa as ike_sa_id_t object (gets cloned)
 * @return					retransmit_request_job_t object
 * 
 * @ingroup jobs
 */
retransmit_request_job_t *retransmit_request_job_create(u_int32_t message_id,ike_sa_id_t *ike_sa_id);

#endif //_RESEND_MESSAGE_JOB_H_
