/*
 * Copyright (C) 2007 Martin Willi
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

/**
 * listener log function
 */
static bool listener_log(interface_listener_t *this, debug_t group,
						 level_t level, int thread, ike_sa_t *ike_sa,
						 char* format, va_list args)
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

/**
 * Implementation of listener_t.ike_state_change
 */
static bool listener_ike_state(interface_listener_t *this, ike_sa_t *ike_sa,
							   ike_sa_state_t state)
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

/**
 * Implementation of listener_t.child_state_change
 */
static bool listener_child_state(interface_listener_t *this, ike_sa_t *ike_sa,
								 child_sa_t *child_sa, child_sa_state_t state)
{
	if (this->ike_sa == ike_sa)
	{
		switch (state)
		{
			case CHILD_ROUTED:
			case CHILD_INSTALLED:
				this->status = SUCCESS;
				return FALSE;
			case CHILD_DESTROYING:
				switch (child_sa->get_state(child_sa))
				{
					case CHILD_ROUTED:
						/* has been unrouted */
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

/**
 * cleanup job if job is never executed
 */
static void recheckin(interface_job_t *job)
{
	if (job->listener.ike_sa)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager,
										job->listener.ike_sa);
	}
}

/**
 * Implementation of controller_t.create_ike_sa_iterator.
 */
static enumerator_t* create_ike_sa_enumerator(controller_t *this)
{
	return charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager);
}

/**
 * execute function for initiate
 */
static status_t initiate_execute(interface_job_t *job)
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
	
	if (ike_sa->initiate(ike_sa, listener->child_cfg) == SUCCESS)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return SUCCESS;
	}
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	return FAILED;
}

/**
 * Implementation of controller_t.initiate.
 */
static status_t initiate(private_controller_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 controller_cb_t callback, void *param)
{
	interface_job_t job = {
		.listener = {
			.public = {
				.log = (void*)listener_log,
				.ike_state_change = (void*)listener_ike_state,
				.child_state_change = (void*)listener_child_state,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.child_cfg = child_cfg,
			.peer_cfg = peer_cfg,
		},
		.public = {
			.execute = (void*)initiate_execute,
			.destroy = (void*)recheckin,
		},
	};
	if (callback == NULL)
	{
		return initiate_execute(&job);
	}
	charon->bus->listen(charon->bus, &job.listener.public, (job_t*)&job);
	return job.listener.status;
}

/**
 * execute function for terminate_ike
 */
static status_t terminate_ike_execute(interface_job_t *job)
{
	interface_listener_t *listener = &job->listener;
	ike_sa_t *ike_sa = listener->ike_sa;
	
	charon->bus->set_sa(charon->bus, ike_sa);
	
	if (ike_sa->delete(ike_sa) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		/* delete failed */
		return FAILED;
	}
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	return SUCCESS;
}

/**
 * Implementation of controller_t.terminate_ike.
 */
static status_t terminate_ike(controller_t *this, u_int32_t unique_id, 
							  controller_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	interface_job_t job = {
		.listener = {
			.public = {
				.log = (void*)listener_log,
				.ike_state_change = (void*)listener_ike_state,
				.child_state_change = (void*)listener_child_state,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.id = unique_id,
		},
		.public = {
			.execute = (void*)terminate_ike_execute,
			.destroy = (void*)recheckin,
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
		return terminate_ike_execute(&job);
	}
	charon->bus->listen(charon->bus, &job.listener.public, (job_t*)&job);
	return job.listener.status;
}

/**
 * execute function for terminate_child
 */
static status_t terminate_child_execute(interface_job_t *job)
{
	interface_listener_t *listener = &job->listener;
	ike_sa_t *ike_sa = listener->ike_sa;
	child_sa_t *child_sa = listener->child_sa;
	
	charon->bus->set_sa(charon->bus, ike_sa);
	if (ike_sa->delete_child_sa(ike_sa, child_sa->get_protocol(child_sa),
								child_sa->get_spi(child_sa, TRUE)) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return SUCCESS;
	}
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	return FAILED;
}

/**
 * Implementation of controller_t.terminate_child.
 */
static status_t terminate_child(controller_t *this, u_int32_t reqid, 
								controller_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	iterator_t *iterator;
	interface_job_t job = {
		.listener = {
			.public = {
				.log = (void*)listener_log,
				.ike_state_change = (void*)listener_ike_state,
				.child_state_change = (void*)listener_child_state,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.id = reqid,
		},
		.public = {
			.execute = (void*)terminate_child_execute,
			.destroy = (void*)recheckin,
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
	
	iterator = ike_sa->create_child_sa_iterator(ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) != CHILD_ROUTED &&
			child_sa->get_reqid(child_sa) == reqid)
		{
			break;
		}
		child_sa = NULL;
	}
	iterator->destroy(iterator);
	
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
		return terminate_child_execute(&job);
	}
	charon->bus->listen(charon->bus, &job.listener.public, (job_t*)&job);
	return job.listener.status;
}

/**
 * execute function for route
 */
static status_t route_execute(interface_job_t *job)
{
	interface_listener_t *listener = &job->listener;
	ike_sa_t *ike_sa = listener->ike_sa;
	
	charon->bus->set_sa(charon->bus, ike_sa);
	if (ike_sa->route(ike_sa, listener->child_cfg) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return SUCCESS;
	}
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	return FAILED;
}

/**
 * Implementation of controller_t.route.
 */
static status_t route(controller_t *this,
					  peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
					  controller_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	interface_job_t job = {
		.listener = {
			.public = {
				.log = (void*)listener_log,
				.ike_state_change = (void*)listener_ike_state,
				.child_state_change = (void*)listener_child_state,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.peer_cfg = peer_cfg,
			.child_cfg = child_cfg,
		},
		.public = {
			.execute = (void*)route_execute,
			.destroy = (void*)recheckin,
		},
	};
	
	ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
														peer_cfg);
	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}
	job.listener.ike_sa = ike_sa;
	if (callback == NULL)
	{
		return route_execute(&job);
	}
	charon->bus->listen(charon->bus, &job.listener.public, (job_t*)&job);
	return job.listener.status;
}

/**
 * execute function for unroute
 */
static status_t unroute_execute(interface_job_t *job)
{
	interface_listener_t *listener = &job->listener;
	ike_sa_t *ike_sa = listener->ike_sa;
	
	if (ike_sa->unroute(ike_sa, listener->id) != DESTROY_ME)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return SUCCESS;
	}
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	return SUCCESS;
}

/**
 * Implementation of controller_t.unroute.
 */
static status_t unroute(controller_t *this, u_int32_t reqid, 
						controller_cb_t callback, void *param)
{
	ike_sa_t *ike_sa;
	interface_job_t job = {
		.listener = {
			.public = {
				.log = (void*)listener_log,
				.ike_state_change = (void*)listener_ike_state,
				.child_state_change = (void*)listener_child_state,
			},
			.callback = callback,
			.param = param,
			.status = FAILED,
			.id = reqid,
		},
		.public = {
			.execute = (void*)unroute_execute,
			.destroy = (void*)recheckin,
		},
	};
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													reqid, TRUE);
	if (ike_sa == NULL)
	{
		DBG1(DBG_IKE, "unable to unroute, CHILD_SA with ID %d not found", reqid);
		return NOT_FOUND;
	}
	job.listener.ike_sa = ike_sa;

	if (callback == NULL)
	{
		return unroute_execute(&job);
	}
	charon->bus->listen(charon->bus, &job.listener.public, (job_t*)&job);	
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

/**
 * Implementation of stroke_t.destroy.
 */
static void destroy(private_controller_t *this)
{
	free(this);
}

/*
 * Described in header-file
 */
controller_t *controller_create(void)
{
	private_controller_t *this = malloc_thing(private_controller_t);
	
	this->public.create_ike_sa_enumerator = (enumerator_t*(*)(controller_t*))create_ike_sa_enumerator;
	this->public.initiate = (status_t(*)(controller_t*,peer_cfg_t*,child_cfg_t*,controller_cb_t,void*))initiate;
	this->public.terminate_ike = (status_t(*)(controller_t*,u_int32_t,controller_cb_t, void*))terminate_ike;
	this->public.terminate_child = (status_t(*)(controller_t*,u_int32_t,controller_cb_t, void *param))terminate_child;
	this->public.route = (status_t(*)(controller_t*,peer_cfg_t*, child_cfg_t*,controller_cb_t,void*))route;
	this->public.unroute = (status_t(*)(controller_t*,u_int32_t,controller_cb_t,void*))unroute;
	this->public.destroy = (void (*)(controller_t*))destroy;
	
	return &this->public;
}

