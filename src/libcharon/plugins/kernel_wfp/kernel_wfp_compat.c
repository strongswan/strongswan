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

#include <library.h>

const GUID FWPM_CONDITION_IP_REMOTE_ADDRESS = {
	0xb235ae9a, 0x1d64, 0x49b8, { 0xa4,0x4c,0x5f,0xf3,0xd9,0x09,0x50,0x45 }
};
const GUID FWPM_CONDITION_IP_LOCAL_ADDRESS = {
	0xd9ee00de, 0xc1ef, 0x4617, { 0xbf,0xe3,0xff,0xd8,0xf5,0xa0,0x89,0x57 }
};
const GUID FWPM_CONDITION_IP_LOCAL_PORT = {
	0x0c1ba1af, 0x5765, 0x453f, { 0xaf,0x22,0xa8,0xf7,0x91,0xac,0x77,0x5b }
};
const GUID FWPM_CONDITION_IP_REMOTE_PORT = {
	0xc35a604d, 0xd22b, 0x4e1a, { 0x91,0xb4,0x68,0xf6,0x74,0xee,0x67,0x4b }
};
const GUID FWPM_CONDITION_IP_PROTOCOL = {
	0x3971ef2b, 0x623e, 0x4f9a, { 0x8c,0xb1,0x6e,0x79,0xb8,0x06,0xb9,0xa7 }
};
const GUID FWPM_LAYER_INBOUND_TRANSPORT_V4 = {
	0x5926dfc8, 0xe3cf, 0x4426, { 0xa2,0x83,0xdc,0x39,0x3f,0x5d,0x0f,0x9d }
};
const GUID FWPM_LAYER_OUTBOUND_TRANSPORT_V4 = {
	0x09e61aea, 0xd214, 0x46e2, { 0x9b,0x21,0xb2,0x6b,0x0b,0x2f,0x28,0xc8 }
};
const GUID FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4 = {
	0x5132900d, 0x5e84, 0x4b5f, { 0x80,0xe4,0x01,0x74,0x1e,0x81,0xff,0x10 }
};
const GUID FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4 = {
	0x4b46bf0a, 0x4523, 0x4e57, { 0xaa,0x38,0xa8,0x79,0x87,0xc9,0x10,0xd9 }
};

/**
 * Load a function symbol from a loaded dll
 */
static inline void *load_function(char *dll, char *name)
{
	HANDLE handle;
	void *sym = NULL;

	handle = GetModuleHandle(dll);
	if (!handle)
	{
		return NULL;
	}
	sym = GetProcAddress(handle, name);
	return sym;
}

/**
 * Macro that defines a stub for a function that calls the same DLL function
 *
 * @param dll		DLL to find function in
 * @param ret		return type of function
 * @param name		function name
 * @param size		size of all arguments on stack
 * @param ...		arguments of function
 */
#define STUB(dll, ret, name, size, ...) \
ret WINAPI name(__VA_ARGS__) \
{ \
	static void (*fun)() = NULL; \
	if (!fun) \
	{ \
		fun = load_function(#dll, #name); \
	} \
	if (fun) \
	{ \
		__builtin_return(__builtin_apply(fun, __builtin_apply_args(), size)); \
	} \
	return ERROR_NOT_SUPPORTED; \
}

STUB(fwpuclnt, DWORD, IPsecSaContextCreate1, 40,
	HANDLE engineHandle, const void *outboundTraffic,
	const void *virtualIfTunnelInfo, UINT64 *inboundFilterId, UINT64 *id)

STUB(fwpuclnt, DWORD, IPsecSaContextSetSpi0, 32,
	HANDLE engineHandle, UINT64 id, const void *getSpi, UINT32 inboundSpi)

STUB(fwpuclnt, DWORD, IPsecSaContextGetById1, 24,
	HANDLE engineHandle, UINT64 id, void **saContext)

STUB(fwpuclnt, DWORD, IPsecSaContextUpdate0, 24,
	HANDLE engineHandle, UINT32 flags, const void *newValues)
