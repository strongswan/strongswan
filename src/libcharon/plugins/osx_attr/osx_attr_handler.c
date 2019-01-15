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

#include "osx_attr_handler.h"

#include <networking/host.h>
#include <utils/debug.h>
#include <threading/mutex.h>

#include <SystemConfiguration/SCDynamicStore.h>

typedef struct private_osx_attr_handler_t private_osx_attr_handler_t;


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
 * Clean up a server_t
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

	DBG1(DBG_CFG, "find_server: looking for %H in servers %p", ip, servers);
	enumerator = servers->create_enumerator( servers );
	DBG1(DBG_CFG, "find_server: beginning iteration");
	while ( enumerator->enumerate( enumerator, &server ) )
	{
		DBG1(DBG_CFG, "find_server: checking %H, %H", ip, server->ip);
		if ( ip->ip_equals( ip, server->ip ) )
		{
			DBG1(DBG_CFG, "find_server: %H matches", ip);
			*found = server;
			break;
		}
	}
	DBG1(DBG_CFG, "find_server: destroying enumerator");
	enumerator->destroy( enumerator );
}

/**
 * Suffix entry
 */
typedef struct {
	/** suffix */
	char *suffix;
	/** reference count */
	int count;
} suffix_t;

/**
 * Clean up a suffix_t
 */
CALLBACK(suffix_destroy, void, suffix_t *this)
{
	if (this->suffix) free(this->suffix);
	free(this);
}

/**
 * Find an address entry given its IP address
 */
static void find_suffix( linked_list_t *suffixes, const char *suffix, suffix_t **found )
{
	enumerator_t *enumerator;
	suffix_t *entry = NULL;
	*found = NULL;

	enumerator = suffixes->create_enumerator( suffixes );
	while ( enumerator->enumerate( enumerator, &entry ) )
	{
		if ( strcmp( suffix, entry->suffix ) == 0 )
		{
			*found = entry;
			break;
		}
	}
	enumerator->destroy( enumerator );
}

/**
 * Private data of an osx_attr_handler_t object.
 */
struct private_osx_attr_handler_t {

	/**
	 * Public interface
	 */
	osx_attr_handler_t public;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;

	/**
	 * List of known DNS servers, as server_t
	 */
	linked_list_t *servers;

	/**
	 * List of known DNS suffixes, as suffix_t
	 */
	linked_list_t *suffixes;
};

/**
 * Create a path to the DNS configuration of the Primary IPv4 Service
 */
static CFStringRef create_dns_path(SCDynamicStoreRef store)
{
	CFStringRef service, path = NULL;
	CFDictionaryRef dict;

	/* get primary service */
	dict = SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/IPv4"));
	if (dict)
	{
		service = CFDictionaryGetValue(dict, CFSTR("PrimaryService"));
		if (service)
		{
			path = CFStringCreateWithFormat(NULL, NULL,
								CFSTR("State:/Network/Service/%@/DNS"), service);
		}
		else
		{
			DBG1(DBG_CFG, "SystemConfiguration PrimaryService not known");
		}
		CFRelease(dict);
	}
	else
	{
		DBG1(DBG_CFG, "getting global IPv4 SystemConfiguration failed");
	}
	return path;
}

/**
 * Create a mutable dictionary from path, a new one if not found
 */
static CFMutableDictionaryRef get_dictionary(SCDynamicStoreRef store,
											 CFStringRef path)
{
	CFDictionaryRef dict;
	CFMutableDictionaryRef mut = NULL;

	dict = SCDynamicStoreCopyValue(store, path);
	if (dict)
	{
		if (CFGetTypeID(dict) == CFDictionaryGetTypeID())
		{
			mut = CFDictionaryCreateMutableCopy(NULL, 0, dict);
		}
		CFRelease(dict);
	}
	if (!mut)
	{
		mut = CFDictionaryCreateMutable(NULL, 0,
										&kCFTypeDictionaryKeyCallBacks,
										&kCFTypeDictionaryValueCallBacks);
	}
	return mut;
}

/**
 * Create a mutable array from dictionary path, a new one if not found
 */
static CFMutableArrayRef get_array_from_dict(CFDictionaryRef dict,
											 CFStringRef name)
{
	CFArrayRef arr;

	arr = CFDictionaryGetValue(dict, name);
	if (arr && CFGetTypeID(arr) == CFArrayGetTypeID())
	{
		return CFArrayCreateMutableCopy(NULL, 0, arr);
	}
	return CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
}

static bool manage_dns_arr_setting(const char *setting, const char *value, bool add)
{
	SCDynamicStoreRef store = NULL;
	CFStringRef path = NULL, cf_value = NULL, cf_setting = NULL;;
	CFMutableDictionaryRef dict = NULL;
	CFMutableArrayRef arr = NULL;
	CFIndex i = 0;
	bool success = FALSE;

	do
	{
		cf_setting = CFStringCreateWithCString(NULL, setting, kCFStringEncodingUTF8);
		if (cf_setting == NULL)
		{
			DBG1(DBG_CFG, "Failed to create CF string from setting '%s'", setting);
			break;
		}

		cf_value = CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
		if (cf_value == NULL)
		{
			DBG1(DBG_CFG, "Failed to create CF string from value '%s'", value);
			break;
		}

		store = SCDynamicStoreCreate(NULL, CFSTR("osx-attr"), NULL, NULL);
		if (store == NULL)
		{
			DBG1(DBG_CFG, "Failed to create dynamic store for osx-attr");
			break;
		}

		path = create_dns_path(store);
		if (path == NULL)
		{
			/* error already logged */
			break;
		}

		dict = get_dictionary(store, path);
		if (dict == NULL)
		{
			DBG1(DBG_CFG, "Failed to get dictionary");
			break;
		}

		arr = get_array_from_dict(dict, cf_setting);
		if (arr == NULL)
		{
			DBG1(DBG_CFG, "Failed to get %s array from dictionary", setting);
			break;
		}

		i = CFArrayGetFirstIndexOfValue(arr, CFRangeMake(0, CFArrayGetCount(arr)), cf_value);

		if ( add )
		{
			if ( i >= 0 )
			{
				DBG1(DBG_CFG, "%s %s already exists - nothing to add", setting, value);
				success = TRUE;
				break;
			}

			DBG1(DBG_CFG, "adding %s %s", setting, value);
			CFArrayInsertValueAtIndex(arr, 0, cf_value);
		}
		else
		{
			if ( i == -1 )
			{
				DBG1(DBG_CFG, "%s %s does not exist - nothing to remove", setting, value);
				success = TRUE;
				break;
			}

			DBG1(DBG_CFG, "removing %s %s", setting, value);
			CFArrayRemoveValueAtIndex(arr, i);
		}

		CFDictionarySetValue(dict, cf_setting, arr);
		success = SCDynamicStoreSetValue(store, path, dict);

	} while ( 0 );

	if (cf_setting) CFRelease(cf_setting);
	if (cf_value) CFRelease(cf_value);
	if (arr) CFRelease(arr);
	if (dict) CFRelease(dict);
	if (path) CFRelease(path);
	if (store) CFRelease(store);

	if (!success)
	{
		if ( add )
			DBG1(DBG_CFG, "adding %s %s to SystemConfiguration failed", setting, value);
		else
			DBG1(DBG_CFG, "removing %s %s from SystemConfiguration failed", setting, value);
	}
	return success;
}

static bool manage_dns_server(private_osx_attr_handler_t *this, host_t *ip, bool add)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%H", ip);
	return manage_dns_arr_setting("ServerAddresses", buf, add);
}

static bool manage_dns_suffix( char *suffix, bool add )
{
	return manage_dns_arr_setting("SearchDomains", suffix, add);
}

METHOD(attribute_handler_t, handle, bool,
	private_osx_attr_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	bool handled = FALSE;

	if ( type == INTERNAL_IP6_DNS )
	{
		/* We don't handle this yet - TBD */
		DBG1(DBG_CFG, "IPv6 DNS not yet stupported");
		return FALSE;
	}

	if ( type == INTERNAL_IP4_DNS ||
		 type == INTERNAL_IP6_DNS )
	{
		server_t *entry = NULL;
		host_t *ip = host_create_from_chunk( type == INTERNAL_IP4_DNS ? AF_INET : AF_INET6, data, 0 );
		if ( !ip || ip->is_anyaddr( ip ) )
		{
			DESTROY_IF( ip );
			return FALSE;
		}

		DBG1(DBG_CFG, "Adding DNS server %H", ip);

		this->mutex->lock( this->mutex );

		// Check if we've already added this server
		find_server(this->servers, ip, &entry);
		if ( entry )
		{
			DBG1(DBG_CFG, "Found entry %p, count = %d", entry, entry->count);
			// Yep. Just increment the reference count
			entry->count++;
			DBG1(DBG_CFG, "%H already in servers list, count = %d", ip, entry->count);
			handled = TRUE;
		}
		else
		{
			// Nope. Do the add
			DBG1(DBG_CFG, "%H not in servers list, doing add", ip);
			handled = manage_dns_server( this, ip, true );

			if ( handled )
			{
				INIT( entry,
					 .ip = ip->clone( ip ),
					 .count = 1
					 );
				this->servers->insert_last( this->servers, entry );
			}
			else
			{
				DBG1(DBG_CFG, "adding DNS server failed");
			}
		}

		this->mutex->unlock( this->mutex );

		ip->destroy( ip );

	}
	else if ( type == UNITY_DEF_DOMAIN )
	{
		suffix_t *entry = NULL;
		char suffix[256] = { 0 };

		// Maximum domain name length is 253
		if ( data.len > 253 )
		{
			DBG1(DBG_CFG, "Given domain name length of %d is too big", data.len);
			return FALSE;
		}

		memcpy( suffix, data.ptr, data.len );
		DBG1(DBG_CFG, "Adding DNS suffix %s", suffix);

		this->mutex->lock( this->mutex );

		// Check if we've already added this suffix
		find_suffix(this->suffixes, suffix, &entry);
		if ( entry )
		{
			// Yep. Just increment the reference count
			entry->count++;
			DBG1(DBG_CFG, "%s already in suffixes list, count = %d", suffix, entry->count);
			handled = TRUE;
		}
		else
		{
			// Nope. Do the add
			DBG1(DBG_CFG, "%s not in suffixes list, doing add", suffix);
			handled = manage_dns_suffix( suffix, true );

			if ( handled )
			{
				INIT( entry,
					 .suffix = strdup(suffix),
					 .count = 1
					 );
				this->suffixes->insert_last( this->suffixes, entry );
			}
			else
			{
				DBG1(DBG_CFG, "adding DNS suffix failed");
			}
		}

		this->mutex->unlock( this->mutex );
	}

	return handled;
}

METHOD(attribute_handler_t, release, void,
	private_osx_attr_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	bool handled = FALSE;

	if ( type == INTERNAL_IP6_DNS )
	{
		/* We don't handle this yet - TBD */
		DBG1(DBG_CFG, "IPv6 DNS not yet stupported");
		return;
	}

	if ( type == INTERNAL_IP4_DNS ||
		 type == INTERNAL_IP6_DNS )
	{
		server_t *entry = NULL;
		host_t *ip = host_create_from_chunk( type == INTERNAL_IP4_DNS ? AF_INET : AF_INET6, data, 0 );
		if ( !ip || ip->is_anyaddr( ip ) )
		{
			DESTROY_IF( ip );
			return;
		}

		DBG1(DBG_CFG, "Removing DNS server %H", ip);

		DBG1(DBG_CFG, "Locking mutex %p", this->mutex);
		this->mutex->lock( this->mutex );

		// Find the server
		DBG1(DBG_CFG, "Finding %H in servers %p", ip, this->servers);
		find_server( this->servers, ip, &entry );
		if ( entry )
		{
			DBG1(DBG_CFG, "Found entry %p, count = %d", entry, entry->count);
			entry->count--;
			if ( entry->count == 0 )
			{
				DBG1(DBG_CFG, "%H count is 0, doing remove", ip);
				this->servers->remove( this->servers, entry, NULL );
				server_destroy( entry );
				handled = manage_dns_server( this, ip, false );
				if ( !handled )
				{
					DBG1(DBG_CFG, "removing DNS server failed");
				}
			}
			else
			{
				DBG1(DBG_CFG, "%H still in servers list, count = %d", ip, entry->count);
				handled = TRUE;
			}
		}
		else
		{
			DBG1(DBG_CFG, "DNS server %H not in servers list - nothing more to do", ip);
			handled = TRUE;
		}

		this->mutex->unlock( this->mutex );

		ip->destroy( ip );
	}
	else if ( type == UNITY_DEF_DOMAIN )
	{
		suffix_t *entry = NULL;
		char suffix[256] = { 0 };

		// Maximum domain name length is 253
		if ( data.len > 253 )
		{
			DBG1(DBG_CFG, "Given domain name length of %d is too big", data.len);
			return;
		}

		memcpy( suffix, data.ptr, data.len );
		DBG1(DBG_CFG, "Removing DNS suffix %s", suffix);

		this->mutex->lock( this->mutex );

		// Find the suffix
		find_suffix( this->suffixes, suffix, &entry );
		if ( entry )
		{
			entry->count--;
			if ( entry->count == 0 )
			{
				DBG1(DBG_CFG, "%s count is 0, doing remove", suffix);
				this->suffixes->remove( this->suffixes, entry, NULL );
				suffix_destroy( entry );
				handled = manage_dns_suffix( suffix, false );
				if ( !handled )
				{
					DBG1(DBG_CFG, "removing DNS suffix failed");
				}
			}
			else
			{
				DBG1(DBG_CFG, "%s still in suffixes list, count = %d", suffix, entry->count);
				handled = TRUE;
			}
		}
		else
		{
			DBG1(DBG_CFG, "DNS suffix %s not in suffixes list - nothing more to do", suffix);
			handled = TRUE;
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

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t *,
	private_osx_attr_handler_t *this, ike_sa_t *ike_sa,
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

METHOD(osx_attr_handler_t, destroy, void,
	private_osx_attr_handler_t *this)
{
	this->mutex->destroy(this->mutex);
	this->servers->destroy_function(this->servers, (void*)server_destroy);
	this->suffixes->destroy_function(this->suffixes, (void*)suffix_destroy);
	free(this);
}

/**
 * See header
 */
osx_attr_handler_t *osx_attr_handler_create()
{
	private_osx_attr_handler_t *this;

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
		.suffixes = linked_list_create(),
	);

	return &this->public;
}
