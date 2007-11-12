/**
 * @file main.c
 *
 * @brief Implementation of dispatcher_t.
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

#include <dispatcher.h>
#include <stdio.h>

#include "manager.h"
#include "database.h"
#include "controller/auth_controller.h"
#include "controller/status_controller.h"
#include "controller/gateway_controller.h"
#include "controller/control_controller.h"
#include "controller/config_controller.h"

#define DBFILE IPSECDIR "/manager.db"
#define SESSION_TIMEOUT 180
#define THREADS 10

int main (int arc, char *argv[])
{
	dispatcher_t *dispatcher;
	database_t *database;
	char *socket = NULL;
	
#ifdef FCGI_SOCKET
	socket = FCGI_SOCKET;
#endif /* FCGI_SOCKET */
	
	database = database_create(DBFILE);
	if (database == NULL)
	{
		fprintf(stderr, "opening database '%s' failed.\n", DBFILE);
		return 1;
	}
	
	dispatcher = dispatcher_create(socket, SESSION_TIMEOUT,
						(context_constructor_t)manager_create, database);
	dispatcher->add_controller(dispatcher, status_controller_create, NULL);
	dispatcher->add_controller(dispatcher, gateway_controller_create, NULL);
	dispatcher->add_controller(dispatcher, auth_controller_create, NULL);
	dispatcher->add_controller(dispatcher, control_controller_create, NULL);
	dispatcher->add_controller(dispatcher, config_controller_create, NULL);
	
	dispatcher->run(dispatcher, THREADS, NULL, NULL, NULL, NULL);
	
	dispatcher->waitsignal(dispatcher);
	
	dispatcher->destroy(dispatcher);
	database->destroy(database);

    return 0;
}

