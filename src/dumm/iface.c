/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2002 Jeff Dike
 *
 * Based on the "tunctl" utlity from Jeff Dike.
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
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

#include <debug.h>

#include "iface.h"

typedef struct private_iface_t private_iface_t;

struct private_iface_t {
	/** public interface */
	iface_t public;
	/** device name in guest (eth0) */
	char *guest;
	/** device name at host (tap0) */
	char *host;
	/** tap device handle to manage taps */
	int tap;
	/** mconsole for guest */
	mconsole_t *mconsole;
};

/**
 * Implementation of iface_t.get_guest.
 */
static char* get_guest(private_iface_t *this)
{
	return this->guest;
}

/**
 * Implementation of iface_t.get_host.
 */
static char* get_host(private_iface_t *this)
{
	return this->host;
}

/**
 * destroy the tap device
 */
static bool destroy_tap(private_iface_t *this)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, this->host, sizeof(ifr.ifr_name) - 1);
	
	if (ioctl(this->tap, TUNSETIFF, &ifr) < 0 ||
		ioctl(this->tap, TUNSETPERSIST, 0) < 0)
	{
		DBG1("removing %s failed: %m", this->host);
		return FALSE;
	}
	return TRUE;
}

/**
 * create the tap device
 */
static char* create_tap(private_iface_t *this)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	
	if (ioctl(this->tap, TUNSETIFF, &ifr) < 0 ||
		ioctl(this->tap, TUNSETPERSIST, 1) < 0)
    {
		DBG1("creating new tap device failed: %m");
		return NULL;
    } 
	return strdup(ifr.ifr_name);
}

/**
 * Implementation of iface_t.destroy.
 */
static void destroy(private_iface_t *this)
{
	this->mconsole->del_iface(this->mconsole, this->guest);
	destroy_tap(this);
	close(this->tap);
	free(this->guest);
	free(this->host);
	free(this);
}

/**
 * create the iface instance
 */
iface_t *iface_create(char *guest, mconsole_t *mconsole)
{
	private_iface_t *this = malloc_thing(private_iface_t);
	
	this->public.get_host = (char*(*)(iface_t*))get_host;
	this->public.get_guest = (char*(*)(iface_t*))get_guest;
	this->public.destroy = (void*)destroy;

	this->mconsole = mconsole;
	this->tap = open(TAP_DEVICE, O_RDWR);
	if (this->tap < 0)
	{
		DBG1("unable to open tap device %s: %m", TAP_DEVICE);
		free(this);
		return NULL;
	}
	this->guest = strdup(guest);
	this->host = create_tap(this);
	if (this->host == NULL)
	{
		destroy_tap(this);
		close(this->tap);
		free(this->guest);
		free(this);
		return NULL;
	}
	if (!this->mconsole->add_iface(this->mconsole, this->guest, this->host))
	{
		DBG1("creating interface '%s' in guest failed", this->guest);
		destroy_tap(this);
		close(this->tap);
		free(this->guest);
		free(this->host);
		free(this);
		return NULL;
	}
	return &this->public;
}

