/**
 * @file dbus_interface.c
 * 
 * @brief Implementation of dbus_interface_t.
 * 
 */

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

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <NetworkManager/NetworkManager.h>
#include <NetworkManager/NetworkManagerVPN.h>
#include <stdlib.h>

#include "dbus_interface.h"

#include <library.h>
#include <daemon.h>


#define NM_DBUS_SERVICE_STRONG "org.freedesktop.NetworkManager.strongswan"
#define NM_DBUS_INTERFACE_STRONG "org.freedesktop.NetworkManager.strongswan"
#define NM_DBUS_PATH_STRONG "/org/freedesktop/NetworkManager/strongswan"

typedef struct private_dbus_interface_t private_dbus_interface_t;

/**
 * Private data of an dbus_interface_t object.
 */
struct private_dbus_interface_t {

	/**
	 * Public part of dbus_t object.
	 */
	dbus_interface_t public;
	
	/**
	 * DBUS connection
	 */
	DBusConnection* conn;
	
	/**
	 * error value used here and there
	 */
	DBusError err;
	
	/**
	 * state of the daemon
	 */
	NMVPNState state;
	
	/**
	 * dispatcher thread for DBUS messages
	 */
	pthread_t thread;
};

/**
 * set daemon state and send StateChange signal to the bus
 */
static void set_state(private_dbus_interface_t *this, NMVPNState state)
{
	DBusMessage* msg;

	msg = dbus_message_new_signal(NM_DBUS_PATH_STRONG, NM_DBUS_INTERFACE_STRONG, NM_DBUS_VPN_SIGNAL_STATE_CHANGE);

	if (!dbus_message_append_args(msg, DBUS_TYPE_UINT32, &this->state,
							  DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID) ||
		!dbus_connection_send(this->conn, msg, NULL))
	{
		DBG1(DBG_CFG, "unable to send DBUS StateChange signal");
	}
	dbus_connection_flush(this->conn);
	dbus_message_unref(msg);
	this->state = state;
}


/**
 * get the child_cfg with the same name as the peer cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	iterator_t *iterator;
	
	iterator = peer_cfg->create_child_cfg_iterator(peer_cfg);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * get a peer configuration by its name, or a name of its children
 */
static peer_cfg_t *get_peer_cfg_by_name(char *name)
{
	iterator_t *i1, *i2;
	peer_cfg_t *current, *found = NULL;
	child_cfg_t *child;

	i1 = charon->backends->create_iterator(charon->backends);
	while (i1->iterate(i1, (void**)&current))
	{
	        /* compare peer_cfgs name first */
	        if (streq(current->get_name(current), name))
	        {
	                found = current;
	                found->get_ref(found);
	                break;
	        }
	        /* compare all child_cfg names otherwise */
	        i2 = current->create_child_cfg_iterator(current);
	        while (i2->iterate(i2, (void**)&child))
	        {
	                if (streq(child->get_name(child), name))
	                {
	                        found = current;
	                        found->get_ref(found);
	                        break;
	                }
	        }
	        i2->destroy(i2);
	        if (found)
	        {
	                break;
	        }
	}
	i1->destroy(i1);
	return found;
}

/**
 * logging dummy
 */
static bool dbus_log(void *param, signal_t signal, level_t level,
					 ike_sa_t *ike_sa, char *format, va_list args)
{
	return TRUE;
}


/**
 * process NetworkManagers startConnection method call
 */
static bool start_connection(private_dbus_interface_t *this, DBusMessage* msg)
{
	DBusMessage *reply, *signal;
	char *name, *user, **data, **passwords, **routes;
	int data_count, passwords_count, routes_count;
	u_int32_t me, other, p2p, netmask, mss;
	char *dev, *domain, *banner;
	const dbus_int32_t array[] = {};
	const dbus_int32_t *varray = array;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	status_t status = FAILED;

	if (!dbus_message_get_args(msg, &this->err,
  			 DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &user,
			 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &passwords, &passwords_count,
			 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data, &data_count,
			 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &routes, &routes_count,
			 DBUS_TYPE_INVALID))
	{
		return FALSE;
	}
	set_state(this, NM_VPN_STATE_STARTING);
	
	peer_cfg = get_peer_cfg_by_name(name);
	if (peer_cfg)
	{
		child_cfg = get_child_from_peer(peer_cfg, name);
		if (child_cfg)
		{
			status = charon->interfaces->initiate(charon->interfaces, peer_cfg,
												  child_cfg, dbus_log, NULL);
		}
	}	
	
	if (status == SUCCESS)
	{
		signal = dbus_message_new_signal(NM_DBUS_PATH_STRONG,
										 NM_DBUS_INTERFACE_STRONG,
										 NM_DBUS_VPN_SIGNAL_IP4_CONFIG);
		me = other = p2p = mss = netmask = 0;
		dev = domain = banner = "";
		if (dbus_message_append_args(signal,
						DBUS_TYPE_UINT32, &other,
						DBUS_TYPE_STRING, &dev,
						DBUS_TYPE_UINT32, &me,
						DBUS_TYPE_UINT32, &p2p,
						DBUS_TYPE_UINT32, &netmask,
						DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &varray, 0,
						DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &varray, 0,
						DBUS_TYPE_UINT32, &mss,
						DBUS_TYPE_STRING, &domain,
						DBUS_TYPE_STRING, &banner, DBUS_TYPE_INVALID))
		{
			dbus_connection_send(this->conn, signal, NULL);
		}						 
		dbus_message_unref(signal);
		set_state(this, NM_VPN_STATE_STARTED);
	}
	else
	{
		set_state(this, NM_VPN_STATE_STOPPED);
	}
	
	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(this->conn, reply, NULL);
	dbus_connection_flush(this->conn);
	dbus_message_unref(reply);
	return TRUE;
}

/**
 * process NetworkManagers stopConnection method call
 */
static bool stop_connection(private_dbus_interface_t *this, DBusMessage* msg)
{
	set_state(this, NM_VPN_STATE_STOPPING);
	set_state(this, NM_VPN_STATE_STOPPED);
	return FALSE;
}

/**
 * process NetworkManagers getState method call
 */
static bool get_state(private_dbus_interface_t *this, DBusMessage* msg)
{
	DBusMessage* reply;
	reply = dbus_message_new_method_return(msg);
	if (!reply || !dbus_message_append_args(reply,
											DBUS_TYPE_UINT32, &this->state,
											DBUS_TYPE_INVALID))
	{
		return FALSE;
	}
	dbus_connection_send(this->conn, reply, NULL);
	return TRUE;
}

/**
 * Handle incoming messages
 */
static DBusHandlerResult message_handler(DBusConnection *con, DBusMessage *msg,
										 private_dbus_interface_t *this)
{
	bool handled;

	if (dbus_message_is_method_call(msg, NM_DBUS_INTERFACE_STRONG,
									"startConnection"))
	{
		handled = start_connection(this, msg);
	}
	else if (dbus_message_is_method_call(msg, NM_DBUS_INTERFACE_STRONG,
										 "stopConnection"))
	{
		handled = stop_connection(this, msg);
	}
	else if (dbus_message_is_method_call(msg, NM_DBUS_INTERFACE_STRONG,
										 "getState"))
	{
		handled = get_state(this, msg);
	}
	else
	{
		DBG1(DBG_CFG, "ignoring DBUS message %s.%s",
			 dbus_message_get_interface(msg), dbus_message_get_member(msg));
		handled = FALSE;
	}
	
	if (handled)
	{
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/**
 * Handle received signals

static DBusHandlerResult signal_handler(DBusConnection *con, DBusMessage *msg,
										private_dbus_interface_t *this)
{
	bool handled;

	if (dbus_message_is_signal(msg, NM_DBUS_INTERFACE, "VPNConnectionStateChange"))
	{
		NMVPNState state;
		char *name;
		
		if (dbus_message_get_args(msg, &this->err, DBUS_TYPE_STRING, &name, 
								  DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID))
		{
			DBG1(DBG_CFG, "got state %d for %s", state, name);
		}
		handled = TRUE;
	}
	else
	{
		DBG1(DBG_CFG, "ignoring DBUS signal %s.%s",
			 dbus_message_get_interface(msg), dbus_message_get_member(msg));
		handled = FALSE;
	}
	if (handled)
	{
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
} */

/**
 * dispatcher function processed by a seperate thread
 */
static void dispatch(private_dbus_interface_t *this)
{
	/* drop threads capabilities */
	charon->drop_capabilities(charon, TRUE, FALSE, FALSE);

	while (dbus_connection_read_write_dispatch(this->conn, -1))
	{
		/* nothing */
	}
}

/**
 * Implementation of interface_t.destroy.
 */
static void destroy(private_dbus_interface_t *this)
{
	pthread_cancel(this->thread);
	pthread_join(this->thread, NULL);
	dbus_error_free(&this->err); 
	free(this);
}

/*
 * Described in header file
 */
interface_t *interface_create()
{
	int ret;
	DBusObjectPathVTable v = {NULL, (void*)&message_handler, NULL, NULL, NULL, NULL};
	private_dbus_interface_t *this = malloc_thing(private_dbus_interface_t);
  
	this->public.interface.destroy = (void (*)(interface_t*))destroy;
	
	dbus_error_init(&this->err); 
	this->conn = dbus_bus_get(DBUS_BUS_SYSTEM, &this->err);
	if (dbus_error_is_set(&this->err))
	{ 
		DBG1(DBG_CFG, "unable to open DBUS connection: %s", this->err.message); 
		charon->kill(charon, "DBUS initialization failed");
	}
	
	ret = dbus_bus_request_name(this->conn, NM_DBUS_SERVICE_STRONG,
							    DBUS_NAME_FLAG_REPLACE_EXISTING , &this->err);
	if (dbus_error_is_set(&this->err))
	{
		DBG1(DBG_CFG, "unable to set DBUS name: %s", this->err.message);
		charon->kill(charon, "unable to set DBUS name");
	}
	if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
	{
		charon->kill(charon, "DBUS name already owned");
	}
	if (!dbus_connection_register_object_path(this->conn, NM_DBUS_PATH_STRONG, &v, this))
    {
		charon->kill(charon, "unable to register DBUS message handler");
    }
	/*
	if (!dbus_connection_add_filter(this->conn, (void*)signal_handler, this, NULL))
	{
		charon->kill(charon, "unable to register DBUS signal handler");
	}
	
	dbus_bus_add_match(this->conn, "type='signal', "
					   "interface='" NM_DBUS_INTERFACE_VPN "',"
					   "path='" NM_DBUS_PATH_VPN "'", &this->err);
	if (dbus_error_is_set (&this->err))
	{
		charon->kill(charon, "unable to add DBUS signal match");
	}*/

	this->state = NM_VPN_STATE_INIT;
	set_state(this, NM_VPN_STATE_STOPPED);

	if (pthread_create(&this->thread, NULL, (void*(*)(void*))dispatch, this) != 0)
	{
		charon->kill(charon, "unable to create stroke thread");
	}

	return &this->public.interface;
}
