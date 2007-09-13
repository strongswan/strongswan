/**
 * @file manager.c
 *
 * @brief Implementation of manager_t.
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

#include "manager.h"

#include "gateway.h"

#include <utils/linked_list.h>

typedef struct private_manager_t private_manager_t;

/**
 * private data of manager
 */
struct private_manager_t {

	/**
	 * public functions
	 */
	manager_t public;
	
	/**
	 * underlying database
	 */
	database_t *db;
	
	/**
	 * user id, if we are logged in
	 */
	int user;
	
	/**
	 * selected gateway
	 */
	gateway_t *gateway;
};	
	
/**
 * Implementation of manager_t.create_gateway_enumerator.
 */
static enumerator_t* create_gateway_enumerator(private_manager_t *this)
{
	return this->db->create_gateway_enumerator(this->db, this->user);
}

/**
 * Implementation of manager_t.select_gateway.
 */
static gateway_t* select_gateway(private_manager_t *this, int select_id)
{
	if (select_id != 0)
	{
		enumerator_t *enumerator;
		int id, port;
		char *name, *address;
		host_t *host;
		
		if (this->gateway) this->gateway->destroy(this->gateway);
		this->gateway = NULL;
		
		enumerator = this->db->create_gateway_enumerator(this->db, this->user);
		while (enumerator->enumerate(enumerator, &id, &name, &port, &address))
		{
			if (select_id == id)
			{
				if (port != 0)
				{
					host = host_create_from_string(address, port);
					if (host)
					{
						this->gateway = gateway_create(name, host);
					}
				}
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return this->gateway;
}

/**
 * Implementation of manager_t.logged_in.
 */
static bool logged_in(private_manager_t *this)
{
	return this->user != 0;
}

/**
 * Implementation of manager_t.login.
 */
static bool login(private_manager_t *this, char *username, char *password)
{
	if (!this->user)
	{
		this->user = this->db->login(this->db, username, password);
	}
	return this->user != 0;
}

/**
 * Implementation of manager_t.logout.
 */
static void logout(private_manager_t *this)
{
	if (this->gateway)
	{
		this->gateway->destroy(this->gateway);
		this->gateway = NULL;
	}
	this->user = 0;
}

/**
 * Implementation of manager_t.destroy
 */
static void destroy(private_manager_t *this)
{
	if (this->gateway) this->gateway->destroy(this->gateway);
	free(this);
}

/*
 * see header file
 */
manager_t *manager_create(database_t *database)
{
	private_manager_t *this = malloc_thing(private_manager_t);
	
	this->public.login = (bool(*)(manager_t*, char *username, char *password))login;
	this->public.logged_in = (bool(*)(manager_t*))logged_in;
	this->public.logout = (void(*)(manager_t*))logout;
	this->public.create_gateway_enumerator = (enumerator_t*(*)(manager_t*))create_gateway_enumerator;
	this->public.select_gateway = (gateway_t*(*)(manager_t*, int id))select_gateway;
	this->public.context.destroy = (void(*)(context_t*))destroy;
	
	this->user = 0;
	this->db = database;
	this->gateway = NULL;
	
	return &this->public;
}

