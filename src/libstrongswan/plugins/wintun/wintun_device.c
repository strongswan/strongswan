/*
 * Copyright (C) 2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#ifdef WIN32
#include <wintun.h>
#endif

#include "wintun_device.h"

#include <utils/debug.h>

#ifndef WIN32

wintun_device_t *wintun_device_create(const char *name_tmpl)
{
	DBG1(DBG_LIB, "Wintun devices not supported");
	return NULL;
}

bool wintun_library_init()
{
	DBG1(DBG_LIB, "Wintun library not supported");
 	return TRUE;
}

void wintun_library_deinit()
{
}

#else /* WIN32 */

/**
  * Functions offered by the Wintun dynamic library
  */
static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static HMODULE Wintun;

#define IFNAMSIZ         16
#define TUN_DEFAULT_MTU  1500

typedef struct private_wintun_device_t private_wintun_device_t;

struct private_wintun_device_t {

	/**
	 * Public interface
	 */
	wintun_device_t public;

	/**
	 * The Wintun device's file descriptor
	 */
	int tunfd;

	/**
	 * Name of the Wintun device
	 */
	char if_name[IFNAMSIZ];

	/**
	 * The current MTU
	 */
	int mtu;

	/**
	 * Associated address
	 */
	host_t *address;

	/**
	 * Netmask for address
	 */
	uint8_t netmask;

	/*
	 * Wintun adapter handle
	 */
    WINTUN_ADAPTER_HANDLE Adapter;

};

METHOD(tun_device_t, set_address, bool,
	private_wintun_device_t *this, host_t *addr, uint8_t netmask)
{
	this->address = addr->clone(addr);
	this->netmask = netmask;

	return TRUE;
}

METHOD(tun_device_t, get_address, host_t*,
	private_wintun_device_t *this, uint8_t *netmask)
{
	if (netmask && this->address)
	{
		*netmask = this->netmask;
	}
	return this->address;
}

METHOD(tun_device_t, up, bool,
	private_wintun_device_t *this)
{
	return TRUE;
}

METHOD(tun_device_t, set_mtu, bool,
	private_wintun_device_t *this, int mtu)
{
	this->mtu = mtu;

	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_wintun_device_t *this)
{
	return this->mtu;
}

METHOD(tun_device_t, get_name, char*,
	private_wintun_device_t *this)
{
	return this->if_name;
}

METHOD(tun_device_t, get_fd, int,
	private_wintun_device_t *this)
{
	return this->tunfd;
}

METHOD(tun_device_t, write_packet, bool,
	private_wintun_device_t *this, chunk_t packet)
{
	return TRUE;
}

METHOD(tun_device_t, read_packet, bool,
	private_wintun_device_t *this, chunk_t *packet)
{
	return TRUE;
}

METHOD(tun_device_t, destroy, void,
	private_wintun_device_t *this)
{
	WintunCloseAdapter(this->Adapter);
	free(this);
}

/**
 * Initialize the Windows TUN device
 */
static bool init_wintun(private_wintun_device_t *this, const char *name_tmpl)
{
	DWORD Version;
	GUID Guid;

	Guid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
	this->Adapter = WintunCreateAdapter(L"strongSwan", L"Wintun", &Guid);
	if (!Adapter)
	{
		DBG1(DBG_LIB,"could not create Wintun adapter");
		return FALSE;
	}
	this->ifname = "strongSwan";
	Version = WintunGetRunningDriverVersion();
	DBG1(DBG_LIB, "Wintun adapter v%u.%u loaded",
		(Version >> 16) & 0xff, (Version >> 0) & 0xff);
    return TRUE;
}

/*
 * Described in header
 */
wintun_device_t *wintun_device_create(const char *name_tmpl)
{
	private_wintun_device_t *this;

	INIT(this,
		.public = {
			.tun = {
				.read_packet = _read_packet,
				.write_packet = _write_packet,
				.get_mtu = _get_mtu,
				.set_mtu = _set_mtu,
				.get_name = _get_name,
				.get_fd = _get_fd,
				.set_address = _set_address,
				.get_address = _get_address,
				.up = _up,
				.destroy = _destroy,
			},
		},
	);

	if (!init_wintun(this, name_tmpl))
	{
		free(this);
		return NULL;
	}
	DBG1(DBG_LIB, "created Wintun device: %s", this->if_name);

	return &this->public;
}

/*
 * Described in header
 */
bool wintun_library_init()
{
	Wintun = LoadLibraryExW(L"wintun.dll", NULL,
				LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
				LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!Wintun)
	{
		DBG1(DBG_LIB, "failed to load Wintun library");
		return FALSE;
	}

#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
	if (X(WintunCreateAdapter)           || X(WintunCloseAdapter)         ||
		X(WintunOpenAdapter)             || X(WintunGetAdapterLUID)       ||
		X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver)         ||
		X(WintunSetLogger)               || X(WintunStartSession)         ||
		X(WintunEndSession)              || X(WintunGetReadWaitEvent)     ||
		X(WintunReceivePacket)           || X(WintunReleaseReceivePacket) ||
		X(WintunAllocateSendPacket)      || X(WintunSendPacket))
#undef X
	{
		FreeLibrary(Wintun);
		DBG1(DBG_LIB, "failed to initialize Wintun library");
		return FALSE;
	}
	DBG1(DBG_LIB, "Wintun library loaded and initialized");
 	return TRUE;
}

/*
 * Described in header
 */
void wintun_library_deinit()
{
	FreeLibrary(Wintun);
}

#endif /* WIN32 */
