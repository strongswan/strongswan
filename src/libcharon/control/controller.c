/*
 * Copyright (C) 2007-2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "controller.h"

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <daemon.h>
#include <library.h>


typedef struct private_controller_t private_controller_t;
typedef struct interface_listener_t interface_listener_t;

/**
 * Private data of an stroke_t object.
 */
struct private_controller_t {

	/**
	 * Public part of stroke_t object.
	 */
	controller_t public;
};

/**
 * helper struct to map listener callbacks to interface callbacks
 */
struct interface_listener_t {

	/**
	 * public bus listener interface
	 */
	listener_t public;

	/**
	 * status of the operation, return to method callers
	 */
	status_t status;

	/**
	 *  interface callback (listener gets redirected to here)
	 */
	controller_cb_t callback;

	/**
	 * user parameter to pass to callback
	 */
	void *param;

	/**
	 * child configuration, used for initiate
	 */
	child_cfg_t *child_cfg;

	/**
	 * peer configuration, used for initiate
	 */
	peer_cfg_t *peer_cfg;

	/**
	 * IKE_SA to handle
	 */
	ike_sa_t *ike_sa;

	/**
	 * CHILD_SA to handle
	 */
	child_sa_t *child_sa;

	/**
	 * unique ID, used for various methods
	 */
	u_int32_t id;
};


typedef struct interface_job_t interface_job_t;

/**
 * job for asynchronous listen operations
 */
struct interface_job_t {

	/**
	 * job interface
	 */
	job_t public;

	/**
	 * associated listener
	 */
	interface_listener_t listener;
};

METHOD(listener_t, listener_log, bool,
	interface_listener_t *this, debug_t group, level_t level, int thread,
	ike_sa_t *ike_sa, char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, group, level, ike_sa, format, args))
		{
			return FALSE;
		}
	}
	return TRUE;
}

METHOD(job_t, get_priority_medium, job_priority_t,
	job_t *this)
{
	return JOB_PRIO_MEDIUM;
}

METHOD(listener_t, ike_state_change, bool,
	interface_listener_t *this, ike_sa_t *ike_sa, ike_sa_state_t state)
{
	if (this->ike_sa == ike_sa)
	{
		switch (state)
		{
#ifdef ME
			case IKE_ESTABLISHED:
			{	/* mediation connections are complete without CHILD_SA */
				peer_cfg_t *peer_cfg = ike_sa->get_peer_cfg(ike_sa);

				if (peer_cfg->is_mediation(peer_cfg))
				{
					this->status = SUCCESS;
					return FALSE;
				}
				break;
			}
#endif /* ME */
			case IKE_DESTROYING:
				if (ike_sa->get_state(ike_sa) == IKE_DELETING)
				{	/* proper termination */
					this->status = SUCCESS;
				}
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
	interface_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	child_sa_state_t state)
{
	if (this->ike_sa == ike_sa)
	{
		switch (state)
		{
			case CHILD_INSTALLED:
				this->status = SUCCESS;
				return FALSE;
			case CHILD_DESTROYING:
				switch (child_sa->get_state(child_sa))
				{
					case CHILD_DELETING:
						/* proper delete */
						this->status = SUCCESS;
						break;
					default:
						break;
				}
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}

METHOD(job_t, recheckin, void,
	interface_job_t *job)
{
	if (job->listener.ike_sa)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager,
										job->listener.ike_sa);
	}
}

METHOD(controller_t, create_ike_sa_enumerator, enumerator_t*,
	private_controller_t *this, bool wait)
{
	return charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager,
													 wait);
}

METHOD(job_t, initiate_execute, void,
	interface_job_t *job)
{
	ike_sa_t *ike_sa;
	interface_listener_t *listener = &job->listener;
	peer_cfg_t *peer_cfg = listener->peer_cfg;

	ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
														peer_cfg);
	listener->ike_sa = ike_sa;

	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}
	peer_cfg->destroy(peer_cfg);

	if (ike_sa->initiate(ike_sa, listener->child_cfg, 0, NULL, NULL) == SUCCESS)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		listener->status = SUCCESS;
	}
	else
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													ike_sa);
		listener->status = FAILED;
	}
}

METHOD(controller_t, initiate, status_t,
	private_controller_t *this, peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
	controller_cb_t callback, void *param, u_int timeout)
{
	interface_job_t job = {
		.listener = {
			.public = {
				.log = _listener_log,
				.ike_state_change = _ike_state_change,
				.child_state_change = _child_state_change,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.child_cfg = child_cfg,
			.peer_cfg = peer_cfg,
		},
		.public = {
			.execute = _initiate_execute,
			.get_priority = _get_priority_medium,
			.destroy = _recheckin,
		},
	};
	if (callback == NULL)
	{
		initiate_execute(&job);
	}
	else
	{
		if (charon->bus->listen(charon->bus, &job.listener.public, &job.public,
								timeout))
		{
			job.listener.status = OUT_OF_RES;
		}
	}
	return job.listener.status;
}

METHOD(job_t, terminate_ike_execute, void,
	interface_job_t *job)
{
	interface_listener_t *listener = &job->listener;
	ike_sa_t *ike_sa = listener->ike_sa;

	charon->bus->set_sa(charon->bus, ike_sa);

	if (ike_sa->delete(ike_sa) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		/* delete failed */
		listener->status = FAILED;
	}
	else
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													ike_sa);
		listener->status = SUCCESS;
	}
}

METHOD(controller_t, terminate_ike, status_t,
	controller_t *this, u_int32_t unique_id,
	controller_cb_t callback, void *param, u_int timeout)
{
	ike_sa_t *ike_sa;
	interface_job_t job = {
		.listener = {
			.public = {
				.log = _listener_log,
				.ike_state_change = _ike_state_change,
				.child_state_change = _child_state_change,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.id = unique_id,
		},
		.public = {
			.execute = _terminate_ike_execute,
			.get_priority = _get_priority_medium,
			.destroy = _recheckin,
		},
	};

	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													unique_id, FALSE);
	if (ike_sa == NULL)
	{
		DBG1(DBG_IKE, "unable to terminate IKE_SA: ID %d not found", unique_id);
		return NOT_FOUND;
	}
	job.listener.ike_sa = ike_sa;

	if (callback == NULL)
	{
		terminate_ike_execute(&job);
	}
	else
	{
		if (charon->bus->listen(charon->bus, &job.listener.public, &job.public,
								timeout))
		{
			job.listener.status = OUT_OF_RES;
		}
		/* checkin of the ike_sa happened in the thread that executed the job */
		charon->bus->set_sa(charon->bus, NULL);
	}
	return job.listener.status;
}

METHOD(job_t, terminate_child_execute, void,
	interface_job_t *job)
{
	interface_listener_t *listener = &job->listener;
	ike_sa_t *ike_sa = listener->ike_sa;
	child_sa_t *child_sa = listener->child_sa;

	charon->bus->set_sa(charon->bus, ike_sa);
	if (ike_sa->delete_child_sa(ike_sa, child_sa->get_protocol(child_sa),
								child_sa->get_spi(child_sa, TRUE)) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		listener->status = SUCCESS;
	}
	else
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													ike_sa);
		listener->status = FAILED;
	}
}

METHOD(controller_t, terminate_child, status_t,
	controller_t *this, u_int32_t reqid,
	controller_cb_t callback, void *param, u_int timeout)
{
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	enumerator_t *enumerator;
	interface_job_t job = {
		.listener = {
			.public = {
				.log = _listener_log,
				.ike_state_change = _ike_state_change,
				.child_state_change = _child_state_change,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.id = reqid,
		},
		.public = {
			.execute = _terminate_child_execute,
			.get_priority = _get_priority_medium,
			.destroy = _recheckin,
		},
	};

	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													reqid, TRUE);
	if (ike_sa == NULL)
	{
		DBG1(DBG_IKE, "unable to terminate, CHILD_SA with ID %d not found",
			 reqid);
		return NOT_FOUND;
	}
	job.listener.ike_sa = ike_sa;

	enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
	while (enumerator->enumerate(enumerator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) != CHILD_ROUTED &&
			child_sa->get_reqid(child_sa) == reqid)
		{
			break;
		}
		child_sa = NULL;
	}
	enumerator->destroy(enumerator);

	if (child_sa == NULL)
	{
		DBG1(DBG_IKE, "unable to terminate, established "
			 "CHILD_SA with ID %d not found", reqid);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return NOT_FOUND;
	}
	job.listener.child_sa = child_sa;

	if (callback == NULL)
	{
		terminate_child_execute(&job);
	}
	else
	{
		if (charon->bus->listen(charon->bus, &job.listener.public, &job.public,
								timeout))
		{
			job.listener.status = OUT_OF_RES;
		}
		/* checkin of the ike_sa happened in the thread that executed the job */
		charon->bus->set_sa(charon->bus, NULL);
	}
	return job.listener.status;
}

/**
 * See header
 */
bool controller_cb_empty(void *param, debug_t group, level_t level,
						 ike_sa_t *ike_sa, char *format, va_list args)
{
	return TRUE;
}

METHOD(controller_t, destroy, void,
	private_controller_t *this)
{
	free(this);
}

/*
 * Described in header-file
 */
controller_t *controller_create(void)
{
	private_controller_t *this;

	INIT(this,
		.public = {
			.create_ike_sa_enumerator = _create_ike_sa_enumerator,
			.initiate = _initiate,
			.terminate_ike = _terminate_ike,
			.terminate_child = _terminate_child,
			.destroy = _destroy,
		},
	);

	return &this->public;
}

