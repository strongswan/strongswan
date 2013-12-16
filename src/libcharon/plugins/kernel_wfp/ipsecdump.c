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

/* Windows 7, for some fwpmu.h functionality */
#define _WIN32_WINNT 0x0601

#include "kernel_wfp_compat.h"

#include <library.h>

ENUM(auth_type_names, IPSEC_AUTH_MD5, IPSEC_AUTH_AES_256,
	"MD5",
	"SHA1",
	"SHA256",
	"AES128",
	"AES192",
	"AES256",
);

ENUM(auth_config_names, 0, 5,
	"HMAC96",
	"HMAC96",
	"HMAC128",
	"GMAC",
	"GMAC",
	"GMAC",
);

ENUM(cipher_type_names, IPSEC_CIPHER_TYPE_DES, IPSEC_CIPHER_TYPE_AES_256,
	"DES",
	"3DES",
	"AES128",
	"AES192",
	"AES256",
);

ENUM(cipher_config_names, 1, 8,
	"CBC",
	"CBC",
	"CBC",
	"CBC",
	"CBC",
	"GCM",
	"GCM",
	"GCM",
);

ENUM(match_type_names, FWP_MATCH_EQUAL, FWP_MATCH_NOT_EQUAL,
	"equals",
	"greater",
	"less than",
	"greater or equal than",
	"less or equal than",
	"in range",
	"has all flags set",
	"has any flags set",
	"has none flags set",
	"equals case insensitive",
	"not equal",
);

ENUM(traffic_type_names, IPSEC_TRAFFIC_TYPE_TRANSPORT, IPSEC_TRAFFIC_TYPE_TUNNEL,
	"Transport",
	"Tunnel",
);

/**
 * Print a GUID to a static buffer
 */
static char *guid2string(GUID *guid)
{
	static char buf[64];

	snprintf(buf, sizeof(buf),
		"%08x,%04x,%04x%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x",
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);

	return buf;
}

const GUID FWPM_CONDITION_IP_SOURCE_ADDRESS = {
	0xae96897e, 0x2e94, 0x4bc9, { 0xb3,0x13,0xb2,0x7e,0xe8,0x0e,0x57,0x4d }
};
const GUID FWPM_CONDITION_IP_DESTINATION_ADDRESS = {
	0x2d79133b, 0xb390, 0x45c6, { 0x86,0x99,0xac,0xac,0xea,0xaf,0xed,0x33 }
};

/**
 * Convert filter condition key GUID to some known strings
 */
static char* cond2name(GUID *guid, bool *address)
{
	struct {
		GUID guid;
		char *name;
		bool address;
	} map[] = {
		{ FWPM_CONDITION_IP_LOCAL_ADDRESS, "local address", TRUE},
		{ FWPM_CONDITION_IP_REMOTE_ADDRESS, "remote address", TRUE},
		{ FWPM_CONDITION_IP_SOURCE_ADDRESS, "source address", TRUE},
		{ FWPM_CONDITION_IP_DESTINATION_ADDRESS, "destination address", TRUE},
		{ FWPM_CONDITION_IP_LOCAL_PORT, "local port", FALSE},
		{ FWPM_CONDITION_IP_REMOTE_PORT, "remote port", FALSE},
		{ FWPM_CONDITION_IP_PROTOCOL, "protocol", FALSE},
		{ FWPM_CONDITION_ICMP_CODE, "icmp code", FALSE},
		{ FWPM_CONDITION_ICMP_TYPE, "icmp type", FALSE},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (memeq(&map[i].guid, guid, sizeof(GUID)))
		{
			*address = map[i].address;
			return map[i].name;
		}
	}
	*address = FALSE;
	return guid2string(guid);
}

/**
 * Print a host from raw data and IP version
 */
static void print_host(FWP_IP_VERSION version, void *data)
{
	host_t *host = NULL;
	UINT32 ints[4];

	switch (version)
	{
		case FWP_IP_VERSION_V4:
			ints[0] = untoh32(data);
			host = host_create_from_chunk(AF_INET, chunk_from_thing(ints[0]), 0);
			break;
		case FWP_IP_VERSION_V6:
			ints[3] = untoh32(data);
			ints[2] = untoh32(data + 4);
			ints[1] = untoh32(data + 8);
			ints[0] = untoh32(data + 12);
			host = host_create_from_chunk(AF_INET6, chunk_from_thing(ints), 0);
			break;
		default:
			break;
	}
	if (host)
	{
		printf("%H", host);
		host->destroy(host);
	}
}

/**
 * Print IPSEC_SA_AUTH_INFORMATION0
 */
static void print_auth(IPSEC_SA_AUTH_INFORMATION0 *a)
{
	printf("%N-%N",
		auth_type_names, a->authTransform.authTransformId.authType,
		auth_config_names, a->authTransform.authTransformId.authConfig);
}

/**
 * Print IPSEC_SA_CIPHER_INFORMATION0
 */
static void print_cipher(IPSEC_SA_CIPHER_INFORMATION0 *c)
{
	printf("%N-%N",
		cipher_type_names, c->cipherTransform.cipherTransformId.cipherType,
		cipher_config_names, c->cipherTransform.cipherTransformId.cipherConfig);
}

/**
 * Print IPsec SA transform
 */
static void list_sa(HANDLE engine, IPSEC_SA0 *sa)
{
	printf("    SPI 0x%08x\n", sa->spi);
	switch (sa->saTransformType)
	{
		case IPSEC_TRANSFORM_AH:
			printf("      AH: ");
			print_auth(sa->ahInformation);
			break;
		case IPSEC_TRANSFORM_ESP_AUTH:
			printf("      ESP: ");
			print_auth(sa->espAuthInformation);
			break;
		case IPSEC_TRANSFORM_ESP_CIPHER:
			printf("      ESP: ");
			print_cipher(sa->espCipherInformation);
			break;
		case IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER:
			printf("      ESP: ");
			print_auth(&sa->espAuthAndCipherInformation->saAuthInformation);
			printf(", ");
			print_cipher(&sa->espAuthAndCipherInformation->saCipherInformation);
			break;
		default:
			printf("      (Transform %d)", sa->saTransformType);
			break;
	}
	printf("\n");
}

/**
 * List a filter condition value, optionally as IP address
 */
static void print_value(FWP_CONDITION_VALUE0 *value, bool address)
{
	chunk_t chunk;

	switch (value->type)
	{
		case FWP_EMPTY:
			printf("empty");
			break;
		case FWP_UINT8:
			printf("%u", value->uint8);
			break;
		case FWP_UINT16:
			printf("%u", value->uint16);
			break;
		case FWP_UINT32:
			if (address)
			{
				print_host(FWP_IP_VERSION_V4, &value->uint32);
			}
			else
			{
				printf("%u", value->uint32);
			}
			break;
		case FWP_UINT64:
			printf("%llu", value->uint64);
			break;
		case FWP_INT8:
			printf("%d", value->int8);
			break;
		case FWP_INT16:
			printf("%d", value->int16);
			break;
		case FWP_INT32:
			printf("%d", value->int32);
			break;
		case FWP_INT64:
			printf("%lld", value->int64);
			break;
		case FWP_FLOAT:
			printf("%f", value->float32);
			break;
		case FWP_DOUBLE:
			printf("%lf", value->double64);
			break;
		case FWP_BYTE_ARRAY16_TYPE:
			if (address)
			{
				print_host(FWP_IP_VERSION_V6, value->byteArray16);
			}
			else
			{
				chunk = chunk_create((u_char*)value->byteArray16, 16);
				printf("%#B", &chunk);
			}
			break;
		case FWP_BYTE_BLOB_TYPE:
			chunk = chunk_create(value->byteBlob->data, value->byteBlob->size);
			printf("%#B", &chunk);
			break;
		case FWP_V4_ADDR_MASK:
			print_host(FWP_IP_VERSION_V4, &value->v4AddrMask->addr);
			printf("/");
			print_host(FWP_IP_VERSION_V4, &value->v4AddrMask->mask);
			break;
		case FWP_V6_ADDR_MASK:
			print_host(FWP_IP_VERSION_V6, &value->v6AddrMask->addr);
			printf("/%u", &value->v6AddrMask->prefixLength);
			break;
		case FWP_RANGE_TYPE:
			print_value((FWP_CONDITION_VALUE0*)&value->rangeValue->valueLow,
						address);
			printf(" - ");
			print_value((FWP_CONDITION_VALUE0*)&value->rangeValue->valueHigh,
						address);
			break;
		default:
			printf("(unsupported)");
			break;
	}
}

/**
 * List a filter condition
 */
static void list_cond(HANDLE engine, FWPM_FILTER_CONDITION0 *cond)
{
	bool address;

	printf("      '%s' %N '", cond2name(&cond->fieldKey, &address),
		match_type_names, cond->matchType);
	print_value(&cond->conditionValue, address);
	printf("'\n");
}

/**
 * Print IPsec SA details
 */
static void list_details(HANDLE engine, IPSEC_SA_DETAILS1 *details)
{
	int i;

	printf("  %sbound SA: ",
		details->saDirection == FWP_DIRECTION_INBOUND ? "In" : "Out");
	print_host(details->traffic.ipVersion, &details->traffic.localV4Address);
	printf(" %s ", details->saDirection == FWP_DIRECTION_INBOUND ? "<-" : "->");
	print_host(details->traffic.ipVersion, &details->traffic.remoteV4Address);
	printf("\n    %N, flags: 0x%06x, lifetime: %us\n",
		  traffic_type_names, details->traffic.trafficType,
		  details->saBundle.flags, details->saBundle.lifetime.lifetimeSeconds);
	if (details->udpEncapsulation)
	{
		printf("    UDP encap ports %u - %u\n",
			details->udpEncapsulation->localUdpEncapPort,
			details->udpEncapsulation->remoteUdpEncapPort);
	}
	for (i = 0; i < details->saBundle.numSAs; i++)
	{
		list_sa(engine, &details->saBundle.saList[i]);
	}
	printf("    Filter ID %llu\n", details->transportFilter->filterId);
	for (i = 0; i < details->transportFilter->numFilterConditions; i++)
	{
		list_cond(engine, &details->transportFilter->filterCondition[i]);
	}
}

/**
 * List installed SA contexts
 */
static bool list_contexts(HANDLE engine)
{
	HANDLE handle;
	UINT32 returned;
	DWORD res;
	IPSEC_SA_CONTEXT1 **entries;

	res = IPsecSaContextCreateEnumHandle0(engine, NULL, &handle);
	if (res != ERROR_SUCCESS)
	{
		fprintf(stderr, "IPsecSaContextCreateEnumHandle0(): 0x%08x\n", res);
		return FALSE;
	}

	while (TRUE)
	{
		res = IPsecSaContextEnum1(engine, handle, 1, &entries, &returned);
		if (res != ERROR_SUCCESS)
		{
			fprintf(stderr, "IPsecSaContextEnum1(): 0x%08x\n", res);
			IPsecSaContextDestroyEnumHandle0(engine, handle);
			return FALSE;
		}
		if (returned == 0)
		{
			break;
		}

		printf("SA context %llu:\n", entries[0]->saContextId);
		list_details(engine, entries[0]->inboundSa);
		list_details(engine, entries[0]->outboundSa);

		FwpmFreeMemory0((void**)&entries);
	}
	IPsecSaContextDestroyEnumHandle0(engine, handle);
	return TRUE;
}

/**
 * ipsecdump main()
 */
int main(int argc, char *argv[])
{
	FWPM_SESSION0 session = {
		.displayData = {
			.name = L"ipsecdump",
			.description = L"strongSwan SAD/SPD dumper",
		},
	};
	HANDLE engine;
	DWORD res;
	int code;

	library_init(NULL, "ipsecdump");
	atexit(library_deinit);

	res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (res != ERROR_SUCCESS)
	{
		fprintf(stderr, "FwpmEngineOpen(): 0x%08x\n", res);
		return 2;
	}
	code = list_contexts(engine) ? 0 : 1;
	FwpmEngineClose0(engine);
	return code;
}
