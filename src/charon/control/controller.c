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
 *
 * $Id$
 */

#include "controller.h"

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <daemon.h>
#include <library.h>


typedef struct private_controller_t private_controller_t;
typedef struct interface_bus_listener_t interface_bus_listener_t;

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
 * helper struct to map bus listener callbacks to interface callbacks
 */
struct interface_bus_listener_t {

	/**
	 * public bus listener interface
	 */
	bus_listener_t public;
	
	/**
	 * status of the operation, return to method callers
	 */
	status_t status;
	
	/**
	 * IKE SA to filter log output
	 */
	ike_sa_t *ike_sa;
	
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
	interface_bus_listener_t listener;
};

/**
 * Implements the famous nop operation
 */
static void nop(job_t *job)
{
	/* NOP */
}

/**
 * Implementation of controller_t.create_ike_sa_iterator.
 */
static iterator_t* create_ike_sa_iterator(controller_t *this)
{
	return charon->ike_sa_manager->create_iterator(charon->ike_sa_manager);
}

/**
 * listener function for initiate
 */
static bool initiate_listener(interface_bus_listener_t *this, signal_t signal,
							  level_t level, int thread, ike_sa_t *ike_sa,
							  char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			return FALSE;
		}
		switch (signal)
		{
			case CHILD_UP_SUCCESS:
				this->status = SUCCESS;
				return FALSE;
			case IKE_UP_FAILED:
			case CHILD_UP_FAILED:
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * execute function for initiate
 */
static status_t initiate_execute(interface_job_t *job)
{
	ike_sa_t *ike_sa;
	interface_bus_listener_t *listener = &job->listener;
	peer_cfg_t *peer_cfg = listener->peer_cfg;
	
	ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
														peer_cfg);
	listener->ike_sa = ike_sa;
	
	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}
	peer_cfg->destroy(peer_cfg);
	
	if (ike_sa->initiate(ike_sa, listener->child_cfg) != SUCCESS)
	{
		return charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
	}
	return charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Implementation of controller_t.initiate.
 */
static status_t initiate(private_controller_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 controller_cb_t callback, void *param)
{
	interface_job_t job;

	job.listener.public.signal = (void*)initiate_listener;
	job.listener.ike_sa = NULL;
	job.listener.callback = callback;
	job.listener.param = param;
	job.listener.status = FAILED;
	job.listener.child_cfg = child_cfg;
	job.listener.peer_cfg = peer_cfg;
	job.public.execute = (void*)initiate_execute;
	job.public.destroy = nop;

	if (callback == NULL)
	{
		return initiate_execute(&job);
	}
	charon->bus->listen(charon->bus, (bus_listener_t*)&job.listener, (job_t*)&job);
	return job.listener.status;
}

/**
 * listener function for terminate_ike
 */
static bool terminate_ike_listener(interface_bus_listener_t *this, signal_t signal,
								   level_t level, int thread, ike_sa_t *ike_sa,
								   char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			return FALSE;
		}
		switch (signal)
		{
			case IKE_DOWN_SUCCESS:
				this->status = SUCCESS;
				return FALSE;
			case IKE_DOWN_FAILED:
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * execute function for terminate_ike
 */
static status_t terminate_ike_execute(interface_job_t *job)
{
	ike_sa_t *ike_sa;
	interface_bus_listener_t *listener = &job->listener;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													listener->id, FALSE);
	if (ike_sa == NULL)
	{
		SIG(IKE_DOWN_FAILED, "unable to terminate, IKE_SA with "
			"ID %d not found", listener->id);
		return NOT_FOUND;
	}	
	listener->ike_sa = ike_sa;						
	
	if (ike_sa->delete(ike_sa) == DESTROY_ME)
	{
		return charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
	}
	return charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Implementation of controller_t.terminate_ike.
 */
static status_t terminate_ike(controller_t *this, u_int32_t unique_id, 
							  controller_cb_t callback, void *param)
{
	interface_job_t job;
	
	job.listener.public.signal = (void*)terminate_ike_listener;
	job.listener.ike_sa = NULL;
	job.listener.callback = callback;
	job.listener.param = param;
	job.listener.status = FAILED;
	job.listener.id = unique_id;
	job.public.execute = (void*)terminate_ike_execute;
	job.public.destroy = nop;

	if (callback == NULL)
	{
		return terminate_ike_execute(&job);
	}
	charon->bus->listen(charon->bus, (bus_listener_t*)&job.listener, (job_t*)&job);
	return job.listener.status;
}
/**
 * listener function for terminate_child
 */
static bool terminate_child_listener(interface_bus_listener_t *this, signal_t signal,
									 level_t level, int thread, ike_sa_t *ike_sa,
									 char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			return FALSE;
		}
		switch (signal)
		{
			case CHILD_DOWN_SUCCESS:
			case IKE_DOWN_SUCCESS:
				this->status = SUCCESS;
				return FALSE;
			case IKE_DOWN_FAILED:
			case CHILD_DOWN_FAILED:
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * execute function for terminate_child
 */
static status_t terminate_child_execute(interface_job_t *job)
{
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	iterator_t *iterator;
	interface_bus_listener_t *listener = &job->listener;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													listener->id, TRUE);							
	if (ike_sa == NULL)
	{
		SIG(CHILD_DOWN_FAILED, "unable to terminate, CHILD_SA with "
			"ID %d not found", listener->id);
		return NOT_FOUND;
	}
	listener->ike_sa = ike_sa;
	
	iterator = ike_sa->create_child_sa_iterator(ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) != CHILD_ROUTED &&
			child_sa->get_reqid(child_sa) == listener->id)
		{
			break;
		}
		child_sa = NULL;
	}
	iterator->destroy(iterator);
	
	if (child_sa == NULL)
	{
		SIG(CHILD_DOWN_FAILED, "unable to terminate, established CHILD_SA with "
			"ID %d not found", listener->id);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		return NOT_FOUND;
	}
	
	if (ike_sa->delete_child_sa(ike_sa, child_sa->get_protocol(child_sa),
								child_sa->get_spi(child_sa, TRUE)) == DESTROY_ME)
	{
		return charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
	}
	return charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Implementation of controller_t.terminate_child.
 */
static status_t terminate_child(controller_t *this, u_int32_t reqid, 
								controller_cb_t callback, void *param)
{
	interface_job_t job;
	
	job.listener.public.signal = (void*)terminate_child_listener;
	job.listener.ike_sa = NULL;
	job.listener.callback = callback;
	job.listener.param = param;
	job.listener.status = FAILED;
	job.listener.id = reqid;
	job.public.execute = (void*)terminate_child_execute;
	job.public.destroy = nop;

	if (callback == NULL)
	{
		return terminate_child_execute(&job);
	}
	charon->bus->listen(charon->bus, (bus_listener_t*)&job.listener, (job_t*)&job);	
	return job.listener.status;
}

/**
 * listener function for route
 */
static bool route_listener(interface_bus_listener_t *this, signal_t signal,
						   level_t level, int thread, ike_sa_t *ike_sa,
						   char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			return FALSE;
		}
		switch (signal)
		{
			case CHILD_ROUTE_SUCCESS:
				this->status = SUCCESS;
				return FALSE;
			case CHILD_ROUTE_FAILED:
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * execute function for route
 */
static status_t route_execute(interface_job_t *job)
{
	ike_sa_t *ike_sa;
	interface_bus_listener_t *listener = &job->listener;
	peer_cfg_t *peer_cfg = listener->peer_cfg;
	ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
														peer_cfg);
	listener->ike_sa = ike_sa;
	
	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, peer_cfg);
	}
	if (ike_sa->route(ike_sa, listener->child_cfg) == DESTROY_ME)
	{
		return charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
	}
	return charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Implementation of controller_t.route.
 */
static status_t route(controller_t *this,
					  peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
					  controller_cb_t callback, void *param)
{
	interface_job_t job;
	
	job.listener.public.signal = (void*)route_listener;
	job.listener.ike_sa = NULL;
	job.listener.callback = callback;
	job.listener.param = param;
	job.listener.status = FAILED;
	job.listener.peer_cfg = peer_cfg;
	job.listener.child_cfg = child_cfg;
	job.public.execute = (void*)route_execute;
	job.public.destroy = nop;

	if (callback == NULL)
	{
		return route_execute(&job);
	}
	charon->bus->listen(charon->bus, (bus_listener_t*)&job.listener, (job_t*)&job);
	return job.listener.status;
}

/**
 * listener function for unroute
 */
static bool unroute_listener(interface_bus_listener_t *this, signal_t signal,
						     level_t level, int thread, ike_sa_t *ike_sa,
						     char* format, va_list args)
{
	if (this->ike_sa == ike_sa)
	{
		if (!this->callback(this->param, signal, level, ike_sa, format, args))
		{
			return FALSE;
		}
		switch (signal)
		{
			case CHILD_UNROUTE_SUCCESS:
				this->status = SUCCESS;
				return FALSE;
			case CHILD_UNROUTE_FAILED:
				return FALSE;
			default:
				break;
		}
	}
	return TRUE;
}
/**
 * execute function for unroute
 */
static status_t unroute_execute(interface_job_t *job)
{
	ike_sa_t *ike_sa;
	interface_bus_listener_t *listener = &job->listener;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
													listener->id, TRUE);
	if (ike_sa == NULL)
	{
		SIG(CHILD_DOWN_FAILED, "unable to unroute, CHILD_SA with "
			"ID %d not found", listener->id);
		return NOT_FOUND;
	}
	listener->ike_sa = ike_sa;
	if (ike_sa->unroute(ike_sa, listener->id) == DESTROY_ME)
	{
		return charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
	}
	return charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Implementation of controller_t.unroute.
 */
static status_t unroute(controller_t *this, u_int32_t reqid, 
						controller_cb_t callback, void *param)
{
	interface_job_t job;
	
	job.listener.public.signal = (void*)unroute_listener;
	job.listener.ike_sa = NULL;
	job.listener.callback = callback;
	job.listener.param = param;
	job.listener.status = FAILED;
	job.listener.id = reqid;
	job.public.execute = (void*)unroute_execute;
	job.public.destroy = nop;

	if (callback == NULL)
	{
		return unroute_execute(&job);
	}
	charon->bus->listen(charon->bus, (bus_listener_t*)&job.listener, (job_t*)&job);	
	return job.listener.status;
}

/**
 * See header
 */
bool controller_cb_empty(void *param, signal_t signal, level_t level,
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
	
	this->public.create_ike_sa_iterator = (iterator_t*(*)(controller_t*))create_ike_sa_iterator;
	this->public.initiate = (status_t(*)(controller_t*,peer_cfg_t*,child_cfg_t*,bool(*)(void*,signal_t,level_t,ike_sa_t*,char*,va_list),void*))initiate;
	this->public.terminate_ike = (status_t(*)(controller_t*,u_int32_t,controller_cb_t, void*))terminate_ike;
	this->public.terminate_child = (status_t(*)(controller_t*,u_int32_t,controller_cb_t, void *param))terminate_child;
	this->public.route = (status_t(*)(controller_t*,peer_cfg_t*, child_cfg_t*,controller_cb_t,void*))route;
	this->public.unroute = (status_t(*)(controller_t*,u_int32_t,controller_cb_t,void*))unroute;
	this->public.destroy = (void (*)(controller_t*))destroy;
	
	return &this->public;
}

