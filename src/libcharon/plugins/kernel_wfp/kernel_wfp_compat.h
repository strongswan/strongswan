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

/**
 * @defgroup kernel_wfp_compat kernel_wfp_compat
 * @{ @ingroup kernel_wfp
 */

#ifndef KERNEL_WFP_COMPAT_H_
#define KERNEL_WFP_COMPAT_H_

#include <winsock2.h>
#include <windows.h>
#include <ipsectypes.h>

/* MinGW defines CIPHERs incorrectly starting at 0 */
#define IPSEC_CIPHER_TYPE_DES					1
#define IPSEC_CIPHER_TYPE_3DES					2
#define IPSEC_CIPHER_TYPE_AES_128				3
#define IPSEC_CIPHER_TYPE_AES_192				4
#define IPSEC_CIPHER_TYPE_AES_256				5
#define IPSEC_CIPHER_TYPE_MAX					6

#include <fwpmtypes.h>
#include <fwpmu.h>
#undef interface

/* MinGW defines TRANSFORMs incorrectly starting at 0 */
#define IPSEC_TRANSFORM_AH						1
#define IPSEC_TRANSFORM_ESP_AUTH				2
#define IPSEC_TRANSFORM_ESP_CIPHER				3
#define IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER		4
#define IPSEC_TRANSFORM_ESP_AUTH_FW				5
#define IPSEC_TRANSFORM_TYPE_MAX				6

/* missing in MinGW */
enum {
	FWPM_TUNNEL_FLAG_POINT_TO_POINT = 						(1<<0),
	FWPM_TUNNEL_FLAG_ENABLE_VIRTUAL_IF_TUNNELING =			(1<<1),
};

DWORD WINAPI FwpmIPsecTunnelAdd0(HANDLE, UINT32,
	const FWPM_PROVIDER_CONTEXT0*, const FWPM_PROVIDER_CONTEXT0*, UINT32,
	const FWPM_FILTER_CONDITION0*, PSECURITY_DESCRIPTOR);

#endif /** KERNEL_WFP_COMPAT_H_ @}*/
