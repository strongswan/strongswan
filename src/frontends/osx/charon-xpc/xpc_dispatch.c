/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "xpc_dispatch.h"

#include <xpc/xpc.h>

#include <daemon.h>
#include <processing/jobs/callback_job.h>

typedef struct private_xpc_dispatch_t private_xpc_dispatch_t;

/**
 * Private data of an xpc_dispatch_t object.
 */
struct private_xpc_dispatch_t {

	/**
	 * Public xpc_dispatch_t interface.
	 */
	xpc_dispatch_t public;

	/**
	 * XPC service we offer
	 */
	xpc_connection_t service;

    /**
     * GCD queue for XPC events
     */
    dispatch_queue_t queue;
};

/**
 * Return version of this helper
 */
static xpc_object_t get_version(private_xpc_dispatch_t *this,
								xpc_object_t request, xpc_connection_t client)
{
	xpc_object_t reply;

	reply = xpc_dictionary_create_reply(request);
	xpc_dictionary_set_string(reply, "version", PACKAGE_VERSION);

	return reply;
}

/**
 * XPC command dispatch table
 */
static struct {
	char *name;
	xpc_object_t (*handler)(private_xpc_dispatch_t *this,
							xpc_object_t request, xpc_connection_t client);
} commands[] = {
	{ "get_version", get_version },
};

/**
 * Handle a received XPC request message
 */
static void handle(private_xpc_dispatch_t *this, xpc_object_t request)
{
	xpc_connection_t client;
	xpc_object_t reply;
	const char *command;
	int i;

	client = xpc_dictionary_get_remote_connection(request);
	command = xpc_dictionary_get_string(request, "command");
	if (command)
	{
		for (i = 0; i < countof(commands); i++)
		{
			if (streq(commands[i].name, command))
			{
				reply = commands[i].handler(this, request, client);
				if (reply)
				{
					xpc_connection_send_message(client, reply);
					xpc_release(reply);
				}
				break;
			}
		}
	}
}

/**
 * Set up GCD handler for XPC events
 */
static void set_handler(private_xpc_dispatch_t *this)
{
	xpc_connection_set_event_handler(this->service, ^(xpc_object_t conn) {

		xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {

			if (xpc_get_type(event) == XPC_TYPE_ERROR)
			{
				if (event == XPC_ERROR_CONNECTION_INVALID ||
					event == XPC_ERROR_TERMINATION_IMMINENT)
				{
					xpc_connection_cancel(conn);
				}
			}
			else
			{
				handle(this, event);
			}
		});

		xpc_connection_resume(conn);
	});

	xpc_connection_resume(this->service);
}

METHOD(xpc_dispatch_t, destroy, void,
	private_xpc_dispatch_t *this)
{
	if (this->service)
	{
		xpc_connection_suspend(this->service);
		xpc_connection_cancel(this->service);
	}
	free(this);
}

/**
 * See header
 */
xpc_dispatch_t *xpc_dispatch_create()
{
	private_xpc_dispatch_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.queue = dispatch_queue_create("org.strongswan.charon-xpc.q",
									DISPATCH_QUEUE_CONCURRENT),
	);

	this->service = xpc_connection_create_mach_service(
									"org.strongswan.charon-xpc", this->queue,
									XPC_CONNECTION_MACH_SERVICE_LISTENER);
	if (!this->service)
	{
		destroy(this);
		return NULL;
	}

	set_handler(this);

	return &this->public;
}
