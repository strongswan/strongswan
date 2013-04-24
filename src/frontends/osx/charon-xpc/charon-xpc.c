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

#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <stdio.h>
#include <xpc/xpc.h>

#include <library.h>
#include <hydra.h>
#include <daemon.h>

/**
 * Loglevel configuration
 */
static level_t levels[DBG_MAX];

/**
 * hook in library for debugging messages
 */
extern void (*dbg) (debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= 1)
	{
		va_start(args, fmt);
		fprintf(stderr, "00[%N] ", debug_names, group);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Return version of this helper
 */
xpc_object_t get_version(xpc_object_t request, xpc_connection_t client)
{
    xpc_object_t reply;

    reply = xpc_dictionary_create_reply(request);
    xpc_dictionary_set_string(reply, "version", PACKAGE_VERSION);

    return reply;
}

/**
 * XPC command dispatch table
 */
struct {
    char *name;
    xpc_object_t (*handler)(xpc_object_t request, xpc_connection_t client);
} commands[] = {
    { "get_version", get_version },
};

/**
 * Handle a received XPC request message
 */
static void handle(xpc_object_t request)
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
                reply = commands[i].handler(request, client);
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
 * Dispatch XPC commands
 */
static int dispatch()
{
    xpc_connection_t service;

    service = xpc_connection_create_mach_service("org.strongswan.charon-xpc",
                                    NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service)
    {
        return EXIT_FAILURE;
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t conn) {

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
                handle(event);
            }
        });
        xpc_connection_resume(conn);
    });

    xpc_connection_resume(service);

    dispatch_main();

    xpc_release(service);
}

/**
 * Main function, starts the daemon.
 */
int main(int argc, char *argv[])
{
	struct utsname utsname;
	int group;

	dbg = dbg_stderr;
	atexit(library_deinit);
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity)
	{
		if (!lib->integrity->check_file(lib->integrity, "charon-xpc", argv[0]))
		{
			exit(SS_RC_DAEMON_INTEGRITY);
		}
	}
	atexit(libhydra_deinit);
	if (!libhydra_init("charon-xpc"))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	atexit(libcharon_deinit);
	if (!libcharon_init("charon-xpc"))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	for (group = 0; group < DBG_MAX; group++)
	{
		levels[group] = LEVEL_CTRL;
	}
	charon->load_loggers(charon, levels, TRUE);

	lib->settings->set_default_str(lib->settings, "charon-cmd.port", "0");
	lib->settings->set_default_str(lib->settings, "charon-cmd.port_nat_t", "0");
	if (!charon->initialize(charon,
            lib->settings->get_str(lib->settings, "charon-xpc.load",
                "random nonce pem pkcs1 openssl kernel-pfkey kernel-pfroute "
                "socket-default eap-identity eap-mschapv2")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	if (uname(&utsname) != 0)
	{
		memset(&utsname, 0, sizeof(utsname));
	}
	DBG1(DBG_DMN, "Starting charon-xpc IKE daemon (strongSwan %s, %s %s, %s)",
		 VERSION, utsname.sysname, utsname.release, utsname.machine);

	charon->start(charon);
	return dispatch();
}
