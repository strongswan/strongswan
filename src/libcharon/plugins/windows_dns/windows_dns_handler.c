/*
 * Copyright (C) 2018 Sophos Group plc
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

#ifdef NOCRYPT
#undef NOCRYPT
#endif
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <naptypes.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <wbemidl.h>
#include <errno.h>

#include "windows_dns_handler.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utils/debug.h>
#include <utils/process.h>
#include <collections/array.h>
#include <threading/mutex.h>

CLSID MY_CLSID_WbemLocator = { 0x4590F811, 0x1D3A, 0x11D0, { 0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 } };
IID MY_IID_IWbemLocator =    { 0xDC12A687, 0x737F, 0x11CF, { 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24 } };

typedef struct private_windows_dns_handler_t private_windows_dns_handler_t;


/**
 * Server entry
 */
typedef struct {
	/** address */
	host_t *ip;
	/** reference count */
	int count;
} server_t;

/**
 * Suffix entry
 */
typedef struct {
	/** suffix */
	char suffix[256];
	/** reference count */
	int count;
} suffix_t;

/**
 * Clean up an server_t
 */
CALLBACK(server_destroy, void, server_t *this)
{
	this->ip->destroy(this->ip);
	free(this);
}

/**
* Find an address entry given its IP address
*/
static void find_server( linked_list_t *servers, host_t *ip, server_t **found )
{
	enumerator_t *enumerator;
	server_t *server = NULL;
	*found = NULL;

	enumerator = servers->create_enumerator( servers );
	while ( enumerator->enumerate( enumerator, &server ) )
	{
		if ( ip->ip_equals( ip, server->ip ) )
		{
			*found = server;
			break;
		}
	}
	enumerator->destroy( enumerator );
}

/**
 * Private data of an windows_dns_handler_t object.
 */
struct private_windows_dns_handler_t {

	/**
	 * Public windows_dns_handler_t interface.
	 */
	windows_dns_handler_t public;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;

	/**
	 * List of known DNS servers, as server_t
	 */
	linked_list_t *servers;

	/**
	 * Suffix currently assigned to the adapter
	 */
	suffix_t suffix;
};

static const char *ErrToStr( int err )
{
	static char unk[128];
	switch ( err )
	{
		case 0: return "success";
		case 1: return "success - reboot required";
		case 84: return "failure - IP not enabled on adapter";
		case 91: return "failure - access denied";
		case 92: return "failure - out of memory";
		case 93: return "failure - already exists";
		case 97: return "failure - interface not configurable";
		default:
			sprintf_s( unk, _countof( unk ), "unexpected error: %d", err );
			return unk;
	}
}

static SAFEARRAY *CreateDnsServersArray( wchar_t *dns1, wchar_t *dns2, wchar_t *dns3, wchar_t *dns4 )
{
	SAFEARRAYBOUND bound;
	BSTR HUGEP *addresses = NULL;
	SAFEARRAY *result = NULL;
	ULONG idx = 0;
	HRESULT hr;

	bound.cElements = 0;
	if ( dns1 && *dns1 ) bound.cElements++;
	if ( dns2 && *dns2 ) bound.cElements++;
	if ( dns3 && *dns3 ) bound.cElements++;
	if ( dns4 && *dns4 ) bound.cElements++;
	bound.lLbound = 0;
	result = SafeArrayCreate( VT_BSTR, 1, &bound );
	if ( result == NULL )
		return NULL;

	if ( bound.cElements > 0 )
	{
		hr = SafeArrayAccessData( result, (void HUGEP **)&addresses );
		if ( FAILED( hr ) )
		{
			SafeArrayDestroy( result );
			return NULL;
		}

		if ( dns1 && *dns1 )
			addresses[idx++] = SysAllocString( dns1 );
		if ( dns2 && *dns2 )
			addresses[idx++] = SysAllocString( dns2 );
		if ( dns3 && *dns3 )
			addresses[idx++] = SysAllocString( dns3 );
		if ( dns4 && *dns4 )
			addresses[idx++] = SysAllocString( dns4 );

		SafeArrayUnaccessData( result );

		while ( idx > 0 )
		{
			if ( addresses[--idx] == NULL )
			{
				SafeArrayDestroy( result );
				result = NULL;
				break;
			}
		}
	}

	return result;
}

static int GetTapAdapterInfo( IWbemServices *pSvc, int *iface_idx, wchar_t *dns1, size_t dns1_sz, wchar_t *dns2, size_t dns2_sz, wchar_t *dns3, size_t dns3_sz, wchar_t *dns4, size_t dns4_sz )
{
	HRESULT hres;
	IEnumWbemClassObject *pEnumerator = NULL;
	IWbemClassObject *pClassObj = NULL;
	BSTR language = NULL, query = NULL;
	ULONG uReturn = 0;
	int res = ENOENT;

	// Sanity checks
	if ( pSvc == NULL || iface_idx == NULL || dns1 == NULL || dns1_sz == 0 || dns2 == NULL || dns2_sz == 0 || dns3 == NULL || dns3_sz == 0 || dns4 == NULL || dns4_sz == 0 )
		return EINVAL;

	// Reset the return parameters
	*iface_idx = 0;
	*dns1 = 0;
	*dns2 = 0;
	*dns3 = 0;
	*dns4 = 0;

	do
	{
		// Allocate our strings
		language = SysAllocString( L"WQL" );
		query = SysAllocString( L"SELECT * FROM Win32_NetworkAdapterConfiguration where Description LIKE 'Sophos TAP Adapter'" );

		// Get the current DNS servers list for our adapter
		hres = pSvc->lpVtbl->ExecQuery( pSvc, language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );
		if ( FAILED( hres ) || !pEnumerator )
		{
			DBG1( DBG_IKE, "Failed to execute query for TAP adapter. Error code = 0x%08X", hres );
			break;
		}

		// We assume only 1 matching result
		hres = pEnumerator->lpVtbl->Next( pEnumerator, WBEM_INFINITE, 1, &pClassObj, &uReturn );
		if ( 0 == uReturn )
		{
			DBG1( DBG_IKE, "TAP adapter not found. Error code = 0x%08X", hres );
			break;
		}

		VARIANT vtProp;
		// Get the existing array
		hres = pClassObj->lpVtbl->Get( pClassObj, L"DNSServerSearchOrder", 0, &vtProp, 0, 0 );
		if ( !FAILED( hres ) )
		{
			if ( (vtProp.vt != VT_NULL) && (vtProp.vt != VT_EMPTY) )
			{
				if ( (vtProp.vt & VT_ARRAY) )
				{
					long lLower, lUpper;
					BSTR Element = NULL;
					SAFEARRAY *pSafeArray = vtProp.parray;
					SafeArrayGetLBound( pSafeArray, 1, &lLower );
					SafeArrayGetUBound( pSafeArray, 1, &lUpper );

					for ( long i = lLower; i <= lUpper; i++ )
					{
						hres = SafeArrayGetElement( pSafeArray, &i, &Element );
						if ( FAILED( hres ) )
						{
							DBG1( DBG_IKE, "Failed to get DNS server from safe array. Error code = 0x%08X", hres );
							break;
						}

						if ( *dns1 == 0 )
							wcsncpy_s( dns1, dns1_sz, Element, _TRUNCATE );
						else if ( *dns2 == 0 )
							wcsncpy_s( dns2, dns2_sz, Element, _TRUNCATE );
						else if ( *dns3 == 0 )
							wcsncpy_s( dns3, dns3_sz, Element, _TRUNCATE );
						else if ( *dns4 == 0 )
							wcsncpy_s( dns4, dns4_sz, Element, _TRUNCATE );
					}
				}
				VariantClear( &vtProp );
			}
		}

		hres = pClassObj->lpVtbl->Get( pClassObj, L"Index", 0, &vtProp, 0, 0 );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Failed to get interface index. Error code = 0x%08X", hres );
			break;
		}
		if ( vtProp.vt != VT_I4 )
		{
			DBG1( DBG_IKE, "Interface index variant type is not VT_I4. Error code = 0x%08X", hres );
			break;
		}
		*iface_idx = vtProp.lVal;
		VariantClear( &vtProp );

		res = 0;
	} while ( 0 );

	if ( pClassObj ) pClassObj->lpVtbl->Release( pClassObj );
	if ( pEnumerator ) pEnumerator->lpVtbl->Release( pEnumerator );
	if ( language ) SysFreeString( language );
	if ( query ) SysFreeString( query );

	return res;
}

static IWbemServices *ConnectToAdapterService()
{
	HRESULT hres = 0;
	IWbemLocator *pLoc = NULL;
	IWbemServices *pSvc = NULL;
	BSTR wmi_ns = NULL;

	do
	{
		// Allocate the strings we need
		wmi_ns = SysAllocString( L"ROOT\\CIMV2" );
		if ( wmi_ns == NULL )
		{
			DBG1( DBG_IKE, "Failed to allocate strings" );
			break;
		}

		/*
		 NOTE: We are intentionally not calling CoInitializeSecurity() here. We
		 will let COM do it.
		 */
		/*
		hres = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Failed to initialize security. Error code = 0x%08X", hres );
			break;
		}
		*/

		// Connect to WMI
		hres = CoCreateInstance( &MY_CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &MY_IID_IWbemLocator, (LPVOID *)&pLoc );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Failed to create IWbemLocator object. Error code = 0x%08X", hres );
			break;
		}

		// Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc to make IWbemServices calls.
		hres = pLoc->lpVtbl->ConnectServer( pLoc, wmi_ns, NULL, NULL, NULL, 0, 0, 0, &pSvc );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Could not connect. Error code = 0x%08X", hres );
			break;
		}

		// Set security levels on the proxy
		hres = CoSetProxyBlanket( (IUnknown *)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Could not set proxy blanket. Error code = 0x%08X", hres );
			break;
		}

	} while ( 0 );

	// Cleanup
	if ( pLoc ) pLoc->lpVtbl->Release( pLoc );
	if ( wmi_ns ) SysFreeString( wmi_ns );

	return pSvc;
}

static int DoExec( IWbemServices *pSvc, int iface_idx, wchar_t *method, wchar_t *param1, VARIANT *vParam1, wchar_t *param2, VARIANT *vParam2 )
{
	HRESULT hres = 0;
	IWbemClassObject *pNetAdaptCfg = NULL;
	IWbemClassObject *pNetAdaptCfgInst = NULL;
	IWbemClassObject *pExecParams = NULL;
	IWbemClassObject *pExecResult = NULL;
	VARIANT vRetVal;
	BSTR method_bstr = NULL, netadaptcfg = NULL, netadaptcfgIdx = NULL;
	int res = 1;
	wchar_t fmt_buf[64] = { 0 };

	do
	{
		VariantInit( &vRetVal );

		// Allocate the strings we need
		netadaptcfg = SysAllocString( L"Win32_NetWorkAdapterConfiguration" );
		method_bstr = SysAllocString( method );
		if ( method_bstr == NULL || netadaptcfg == NULL )
		{
			DBG1( DBG_IKE, "Failed to allocate strings" );
			break;
		}

		// Get the object to do our put
		hres = pSvc->lpVtbl->GetObject( pSvc, netadaptcfg, 0, NULL, &pNetAdaptCfg, NULL );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Faild to get Win32_NetWorkAdapterConfiguration. Error code = 0x%08X", hres );
			break;
		}

		hres = pNetAdaptCfg->lpVtbl->GetMethod( pNetAdaptCfg, method_bstr, 0, &pExecParams, NULL );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "GetMethod() failed. Error code = 0x%08X", hres );
			break;
		}

		hres = pExecParams->lpVtbl->SpawnInstance( pExecParams, 0, &pNetAdaptCfgInst );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "SpawnInstance() failed. Error code = 0x%08X", hres );
			break;
		}

		hres = pNetAdaptCfgInst->lpVtbl->Put( pNetAdaptCfgInst, param1, 0, vParam1, 0 );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Put() failed. Error code = 0x%08X", hres );
			break;
		}

		if ( param2 != NULL && vParam2 != NULL )
		{
			hres = pNetAdaptCfgInst->lpVtbl->Put( pNetAdaptCfgInst, param2, 0, vParam2, 0 );
			if ( FAILED( hres ) )
			{
				DBG1( DBG_IKE, "Put()[2] failed. Error code = 0x%08X", hres );
				break;
			}
		}

		swprintf_s( fmt_buf, _countof( fmt_buf ), L"Win32_NetWorkAdapterConfiguration.Index='%d'", iface_idx );
		netadaptcfgIdx = SysAllocString( fmt_buf );
		if ( netadaptcfgIdx == NULL )
		{
			DBG1( DBG_IKE, "Failed to allocate string" );
			break;
		}

		hres = pSvc->lpVtbl->ExecMethod( pSvc, netadaptcfgIdx, method_bstr, 0, NULL, pNetAdaptCfgInst, &pExecResult, NULL );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "ExecMethod() failed. Error code = 0x%08X", hres );
			break;
		}

		hres = pExecResult->lpVtbl->Get( pExecResult, L"ReturnValue", 0, &vRetVal, NULL, 0 );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Failed to get result from ExecResult. Error code = 0x%08X", hres );
			break;
		}

		// We executed the method_bstr, set the return result
		res = vRetVal.intVal;
	} while ( 0 );

	// Cleanup
	VariantClear( &vRetVal );
	if ( pExecResult )pExecResult->lpVtbl->Release( pExecResult );
	if ( pNetAdaptCfgInst ) pNetAdaptCfgInst->lpVtbl->Release( pNetAdaptCfgInst );
	if ( pExecParams ) pExecParams->lpVtbl->Release( pExecParams );
	if ( pNetAdaptCfg )pNetAdaptCfg->lpVtbl->Release( pNetAdaptCfg );
	if ( method_bstr ) SysFreeString( method_bstr );
	if ( netadaptcfg ) SysFreeString( netadaptcfg );
	if ( netadaptcfgIdx ) SysFreeString( netadaptcfgIdx );

	return res;
}

static int SetDNSServerSearchOrder( IWbemServices *pSvc, int iface_idx, SAFEARRAY *dnsServers )
{
	VARIANT vDnsServers;
	int res = 1;

	// Make the array variant
	VariantInit( &vDnsServers );
	vDnsServers.vt = VT_ARRAY | VT_BSTR;
	vDnsServers.parray = dnsServers;

	// OK, execute it
	res = DoExec( pSvc, iface_idx, L"SetDNSServerSearchOrder", L"DNSServerSearchOrder", &vDnsServers, NULL, NULL );

	// Cleanup
	VariantClear( &vDnsServers );

	return res;
}

static int SetDynamicDNSRegistration( IWbemServices *pSvc, int iface_idx, BOOL FullDNSRegistrationEnabled, BOOL DomainDNSRegistrationEnabled )
{
	VARIANT vFullDNSRegistrationEnabled, vDomainDNSRegistrationEnabled;
	int res = 1;

	// Make the bool variant for param 1
	VariantInit( &vFullDNSRegistrationEnabled );
	vFullDNSRegistrationEnabled.vt = VT_BOOL;
	vFullDNSRegistrationEnabled.boolVal = FullDNSRegistrationEnabled ? VARIANT_TRUE : VARIANT_FALSE;

	// Make the bool variant for param 2
	VariantInit( &vDomainDNSRegistrationEnabled );
	vDomainDNSRegistrationEnabled.vt = VT_BOOL;
	vDomainDNSRegistrationEnabled.boolVal = DomainDNSRegistrationEnabled ? VARIANT_TRUE : VARIANT_FALSE;

	// OK, execute it
	res = DoExec( pSvc, iface_idx, L"SetDynamicDNSRegistration", L"FullDNSRegistrationEnabled", &vFullDNSRegistrationEnabled, L"DomainDNSRegistrationEnabled", &vDomainDNSRegistrationEnabled );

	// Cleanup
	VariantClear( &vFullDNSRegistrationEnabled );
	VariantClear( &vDomainDNSRegistrationEnabled );

	return res;
}

/**
 * Adds the given DNS server to the TAP adapter
 */
static bool add_dns_server(private_windows_dns_handler_t *this, host_t *ip)
{
	chunk_t dns_server_chunk;
	wchar_t dns_server[64];
	HRESULT hres = 0;
	IWbemServices *pSvc = NULL;
	wchar_t dns1[16] = { 0 }, dns2[16] = { 0 }, dns3[16] = { 0 }, dns4[16] = { 0 };
	SAFEARRAY *dns_servers_arr = NULL;
	int res = -1;
	int iface_idx = 0;

	do
	{
		/* Convert to wide character string */
		dns_server_chunk = ip->get_address( ip );
		if ( InetNtopW( ip->get_family( ip ), dns_server_chunk.ptr, dns_server, _countof( dns_server ) ) == NULL )
		{
			DBG1( DBG_IKE, "Failed to convert chunk to IP address string" );
			break;
		}

		// Initialize COM
		hres = CoInitializeEx( 0, COINIT_MULTITHREADED );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Failed to initialize COM library. Error code = 0x%08X", hres );
			break;
		}

		// Connect to the adapter service
		pSvc = ConnectToAdapterService();
		if ( pSvc == NULL )
			break;

		// Get the information we need for the adapter
		res = GetTapAdapterInfo( pSvc, &iface_idx, dns1, _countof(dns1), dns2, _countof( dns2 ), dns3, _countof( dns3 ), dns4, _countof( dns4 ) );
		if ( res != 0 )
		{
			DBG1( DBG_IKE, "Failed to get TAP adapter information. Error code = %d", res );
			break;
		}

		/* If the address is already there, nothing more to do */
		if ( wcscmp( dns_server, dns1 ) == 0 ||
			 wcscmp( dns_server, dns2 ) == 0 ||
			 wcscmp( dns_server, dns3 ) == 0 ||
			 wcscmp( dns_server, dns4 ) == 0 )
		{
			DBG1( DBG_IKE, "DNS server IP address %H is already in the DNS server list", ip );
			res = 0;
			break;
		}

		/*
		 The DNS server isn't there, so we need to add it. We need to make a
		 safe array for the DNS servers. Note that if there are already the
		 maximum number of DNS servers, we will make the one we are adding the
		 first.
		 */
		if ( dns1[0] == 0 )
			wcsncpy_s( dns1, _countof( dns1 ), dns_server, _TRUNCATE );
		else if ( dns2[0] == 0 )
			wcsncpy_s( dns2, _countof( dns2 ), dns_server, _TRUNCATE );
		else if ( dns3[0] == 0 )
			wcsncpy_s( dns3, _countof( dns3 ), dns_server, _TRUNCATE );
		else if ( dns4[0] == 0 )
			wcsncpy_s( dns4, _countof( dns4 ), dns_server, _TRUNCATE );
		else
			wcsncpy_s( dns1, _countof( dns1 ), dns_server, _TRUNCATE );
		dns_servers_arr = CreateDnsServersArray( dns1, dns2, dns3, dns4 );
		if ( dns_servers_arr == NULL )
		{
			DBG1( DBG_IKE, "Failed to create DNS servers array" );
			break;
		}

		// Disable dynamic DNS registration
		res = SetDynamicDNSRegistration( pSvc, iface_idx, FALSE, FALSE );
		if ( res != 0 )
			DBG1( DBG_IKE, "Set dynamic DNS registration to adapter failed: %s", ErrToStr( res ) );

		// Set the DNS servers list into the adapter (takes ownership of dns_servers_arr)
		res = SetDNSServerSearchOrder( pSvc, iface_idx, dns_servers_arr );
		if ( res != 0 )
			DBG1( DBG_IKE, "Add DNS server %H to adapter failed: %s", ip, ErrToStr( res ) );

	} while ( 0 );

	// Cleanup
	if ( pSvc ) pSvc->lpVtbl->Release( pSvc );
	if ( hres != 0 ) CoUninitialize();

	return res == 0;
}

/**
 * Removes the given DNS server from the TAP adapter
 */
static bool remove_dns_server(private_windows_dns_handler_t *this, host_t *ip)
{
	chunk_t dns_server_chunk;
	wchar_t dns_server[64];
	HRESULT hres = 0;
	IWbemServices *pSvc = NULL;
	wchar_t dns1[16] = { 0 }, dns2[16] = { 0 }, dns3[16] = { 0 }, dns4[16] = { 0 };
	SAFEARRAY *dns_servers_arr = NULL;
	int res = -1;
	int iface_idx = 0;

	do
	{
		/* Convert to wide character string */
		dns_server_chunk = ip->get_address( ip );
		if ( InetNtopW( ip->get_family( ip ), dns_server_chunk.ptr, dns_server, _countof( dns_server ) ) == NULL )
		{
			DBG1( DBG_IKE, "Failed to convert chunk to IP address string" );
			break;
		}

		// Initialize COM
		hres = CoInitializeEx( 0, COINIT_MULTITHREADED );
		if ( FAILED( hres ) )
		{
			DBG1( DBG_IKE, "Failed to initialize COM library. Error code = 0x%08X", hres );
			break;
		}

		// Connect to the adapter service
		pSvc = ConnectToAdapterService();
		if ( pSvc == NULL )
			break;

		// Get the information we need for the adapter
		res = GetTapAdapterInfo( pSvc, &iface_idx, dns1, _countof( dns1 ), dns2, _countof( dns2 ), dns3, _countof( dns3 ), dns4, _countof( dns4 ) );
		if ( res != 0 )
		{
			DBG1( DBG_IKE, "Failed to get TAP adapter information. Error code = %d", res );
			break;
		}

		/* If the address is already there, nothing more to do */
		if ( wcscmp( dns_server, dns1 ) != 0 &&
			 wcscmp( dns_server, dns2 ) != 0 &&
			 wcscmp( dns_server, dns3 ) != 0 &&
			 wcscmp( dns_server, dns4 ) != 0 )
		{
			DBG1( DBG_IKE, "Dns server IP address %H is already not in the DNS server list", ip );
			res = 0;
			break;
		}

		/*
		 The DNS server is there, so we need to remove it. We need to make a
		 safe array for the DNS servers. Note that if there are already the
		 maximum number of DNS servers, we will make the one we are adding the
		 first.
		 */
		if ( wcscmp( dns_server, dns1 ) == 0 )
			dns1[0] = 0;
		if ( wcscmp( dns_server, dns2 ) == 0 )
			dns2[0] = 0;
		if ( wcscmp( dns_server, dns3 ) == 0 )
			dns3[0] = 0;
		if ( wcscmp( dns_server, dns4 ) == 0 )
			dns4[0] = 0;
		dns_servers_arr = CreateDnsServersArray( dns1, dns2, dns3, dns4 );
		if ( dns_servers_arr == NULL )
		{
			DBG1( DBG_IKE, "Failed to create DNS servers array" );
			break;
		}

		// Set the DNS servers list into the adapter (takes ownership of dns_servers_arr)
		res = SetDNSServerSearchOrder( pSvc, iface_idx, dns_servers_arr );
		if ( res != 0 )
			DBG1( DBG_IKE, "Remove DNS server %H from adapter: %s", ip, ErrToStr( res ) );

	} while ( 0 );

	// Cleanup
	if ( pSvc ) pSvc->lpVtbl->Release( pSvc );
	if ( hres != 0 ) CoUninitialize();

	return res == 0;
}

static bool set_dns_suffix( wchar_t *suffix )
{
	HRESULT hres = 0;
	IWbemServices *pSvc = NULL;
	VARIANT vSuffix;
	int res = -1;
	BSTR suffix_bstr;
	wchar_t dns1[16] = { 0 }, dns2[16] = { 0 }, dns3[16] = { 0 }, dns4[16] = { 0 };
	int ifaceIdx = 0;

	// Initialize COM
	hres = CoInitializeEx( 0, COINIT_MULTITHREADED );
	if ( FAILED( hres ) )
	{
		DBG1( DBG_IKE, "Failed to initialize COM library. Error code = 0x%08X", hres );
		return FALSE;
	}

	do
	{
		// Allocate the strings we need
		suffix_bstr = SysAllocString( suffix );
		if ( suffix_bstr == NULL )
		{
			DBG1( DBG_IKE, "Failed to allocate strings" );
			break;
		}

		// Make the variant
		VariantInit( &vSuffix );
		vSuffix.vt = VT_BSTR;
		vSuffix.bstrVal = suffix_bstr;

		// Connect to the adapter service
		pSvc = ConnectToAdapterService();
		if ( pSvc == NULL )
			break;

		// Get the information we need for the adapter
		res = GetTapAdapterInfo( pSvc, &ifaceIdx, dns1, _countof( dns1 ), dns2, _countof( dns2 ), dns3, _countof( dns3 ), dns4, _countof( dns4 ) );
		if ( res != 0 )
		{
			DBG1( DBG_IKE, "Failed to get TAP adapter information. Error code = %d", res );
			break;
		}

		// OK, execute it
		res = DoExec( pSvc, ifaceIdx, L"SetDNSDomain", L"DNSDomain", &vSuffix, NULL, NULL );
	} while ( 0 );

	// Cleanup
	if ( pSvc ) pSvc->lpVtbl->Release( pSvc );
	CoUninitialize();
	VariantClear( &vSuffix );

	return res == 0;
}

METHOD( attribute_handler_t, handle, bool,
		private_windows_dns_handler_t *this, ike_sa_t *ike_sa,
		configuration_attribute_type_t type, chunk_t data )
{
	bool handled = FALSE;

	if ( type == INTERNAL_IP4_DNS ||
		 type == INTERNAL_IP6_DNS )
	{
		server_t *server = NULL;
		host_t *ip = host_create_from_chunk( type == INTERNAL_IP4_DNS ? AF_INET : AF_INET6, data, 0 );
		if ( !ip || ip->is_anyaddr( ip ) )
		{
			DESTROY_IF( ip );
			return FALSE;
		}

		DBG1( DBG_IKE, "Adding DNS server %H to the TAP adapter", ip );

		this->mutex->lock( this->mutex );

		// Check if we've already added this server
		find_server(this->servers, ip, &server);
		if ( server )
		{
			// Yep. Just increment the reference count
			server->count++;
			DBG1( DBG_IKE, "%H already in servers list, count = %d", ip, server->count );
			handled = TRUE;
		}
		else
		{
			// Nope. Do the add
			DBG1( DBG_IKE, "%H not in servers list, doing add", ip );
			handled = add_dns_server( this, ip );

			if ( handled )
			{
				INIT( server,
					  .ip = ip->clone( ip ),
					  .count = 1
				);
				this->servers->insert_last( this->servers, server );
			}
			else
			{
				DBG1( DBG_IKE, "adding DNS server failed" );
			}
		}

		this->mutex->unlock( this->mutex );

		ip->destroy( ip );

	}
	else if ( type == UNITY_DEF_DOMAIN )
	{
		char suffix[256] = { 0 };

		// Maximum domain name length is 253
		if ( data.len > 253 )
		{
			DBG1( DBG_IKE, "Given domain name length of %d is too big", data.len );
			return FALSE;
		}

		memcpy( suffix, data.ptr, data.len );
		DBG1( DBG_IKE, "Setting DNS suffix %s into the TAP adapter", suffix );

		this->mutex->lock( this->mutex );

		// Do we already have a suffix?
		if ( this->suffix.count > 0 )
		{
			// Is it the same as the one being added?
			if ( strcmp( suffix, this->suffix.suffix ) == 0 )
			{
				// Same, just update the reference count
				this->suffix.count++;
				DBG1( DBG_IKE, "Domain suffix %s already added, count = %d", suffix, this->suffix.count );
				handled = TRUE;
			}
			else
			{
				// Different. Reset the reference count so it gets added
				this->suffix.count = 0;
				DBG1( DBG_IKE, "Domain suffix %s is different than existing suffix %s - resetting", suffix, this->suffix.suffix );
			}
		}

		// Check again since the count could have been reset above
		if ( this->suffix.count == 0 )
		{
			// WMI needs a wide character version of the suffix
			wchar_t suffixW[256];
			swprintf_s( suffixW, _countof( suffixW ), L"%S", suffix );

			DBG1( DBG_IKE, "Domain suffix %s not in virtual adapter - adding", suffix );
			handled = set_dns_suffix( suffixW );
			if ( handled )
			{
				// Save the suffix and set the count
				strncpy_s( this->suffix.suffix, _countof(this->suffix.suffix), suffix, _TRUNCATE );
				this->suffix.count = 1;
				DBG1( DBG_IKE, "Domain suffix %s added to virtual adapter", suffix );
			}
			else
			{
				DBG1( DBG_IKE, "setting DNS domain failed" );
			}
		}

		this->mutex->unlock( this->mutex );
	}

	return handled;
}

METHOD(attribute_handler_t, release, void,
	private_windows_dns_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	if ( type == INTERNAL_IP4_DNS ||
		 type == INTERNAL_IP6_DNS )
	{
		server_t *server = NULL;
		host_t *ip = host_create_from_chunk( type == INTERNAL_IP4_DNS ? AF_INET : AF_INET6, data, 0 );
		if ( !ip || ip->is_anyaddr( ip ) )
		{
			DESTROY_IF( ip );
			return;
		}

		DBG1( DBG_IKE, "Removing DNS server %H from the TAP adapter", ip );

		this->mutex->lock( this->mutex );

		// Find the server
		find_server( this->servers, ip, &server );
		if ( server )
		{
			server->count--;
			if ( server->count == 0 )
			{
				DBG1( DBG_IKE, "%H count is 0, doing remove", ip );
				this->servers->remove( this->servers, server, NULL );
				server_destroy( server );
				if ( !remove_dns_server( this, ip ) )
				{
					DBG1( DBG_IKE, "removing DNS server failed" );
				}
			}
			else
			{
				DBG1( DBG_IKE, "%H still in servers list, count = %d", ip, server->count );
			}
		}
		else
		{
			DBG1( DBG_IKE, "DNS server %H not in servers list - nothing more to do", ip );
		}

		this->mutex->unlock( this->mutex );

		ip->destroy( ip );
	}
	else if ( type == UNITY_DEF_DOMAIN )
	{
		char suffix[256] = { 0 };

		// Maximum domain name length is 253
		if ( data.len > 253 )
		{
			DBG1( DBG_IKE, "Given domain name length of %d is too big", data.len );
			return;
		}

		memcpy( suffix, data.ptr, data.len );
		DBG1( DBG_IKE, "Removing DNS suffix %s from the TAP adapter", suffix );

		this->mutex->lock( this->mutex );

		if ( this->suffix.count == 0 )
		{
			DBG1( DBG_IKE, "No suffixes assigned to the TAP adapter - nothing to do" );
		}
		else
		{
			if ( strcmp( this->suffix.suffix, suffix ) != 0 )
			{
				DBG1( DBG_IKE, "Suffix %s is not assigned to the TAP adapter - nothing to do", suffix );
			}
			else
			{
				--this->suffix.count;
				if ( this->suffix.count == 0 )
				{
					DBG1( DBG_IKE, "Suffix count is 0 - doing remove" );

					if ( !set_dns_suffix( L"" ) )
					{
						DBG1( DBG_IKE, "removing DNS suffix failed" );
					}
				}
				else
				{
					DBG1( DBG_IKE, "Suffix count is %d - nothing more to do", this->suffix.count );
				}
			}
		}

		this->mutex->unlock( this->mutex );
	}
}

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** request IPv4 DNS? */
	bool v4;
	/** request IPv6 DNS? */
	bool v6;
} attribute_enumerator_t;

METHOD(enumerator_t, attribute_enumerate, bool,
	attribute_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);
	if (this->v4)
	{
		*type = INTERNAL_IP4_DNS;
		*data = chunk_empty;
		this->v4 = FALSE;
		return TRUE;
	}
	if (this->v6)
	{
		*type = INTERNAL_IP6_DNS;
		*data = chunk_empty;
		this->v6 = FALSE;
		return TRUE;
	}
	return FALSE;
}

/**
 * Check if a list has a host of given family
 */
static bool has_host_family(linked_list_t *list, int family)
{
	enumerator_t *enumerator;
	host_t *host;
	bool found = FALSE;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (host->get_family(host) == family)
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return found;
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	private_windows_dns_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	attribute_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _attribute_enumerate,
			.destroy = (void*)free,
		},
		.v4 = has_host_family(vips, AF_INET),
		.v6 = has_host_family(vips, AF_INET6),
	);
	return &enumerator->public;
}

METHOD(windows_dns_handler_t, destroy, void,
	private_windows_dns_handler_t *this)
{
	this->mutex->destroy(this->mutex);
	this->servers->destroy_function(this->servers, (void*)server_destroy);
	free(this);
}

/**
 * See header
 */
windows_dns_handler_t *windows_dns_handler_create()
{
	private_windows_dns_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.servers = linked_list_create(),
		.suffix = {
			  .count = 0,
		  },
	);

	return &this->public;
}
