/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 * Copyright (C) 2019 Sophos Inc
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

/*
 * Theory of Operation
 * The dictionary associated with the State:/Network/Global/DNS dynamic store
 * key contains what the current DNS configuration. This key is not modifiable.
 * In order to use the DNS servers and suffix specified for the tunnel, we want
 * to create a State:/Network/Service/<service-id>/DNS key which contains the
 * tunnel DNS settings. However, that is not enough because the system will not
 * use this key as it is not the primary DNS key. Further, there is no direct
 * way to make it the primary DNS key. To do that, we also need to create a
 * State:/Network/Service/<service-id>/IPv4 key and add an OverridePrimary key
 * to it. This will make the IPv4 key primary for IPv4, and also the
 * corresponding DNS key primary for DNS. In order to not break network
 * connectivity on the system, the IPv4 key we create will be an exact copy of
 * the IPv4 key of the active interface at the time the tunnel is established
 * (the only exception being the addition of the OverridePrimary key). Likewise,
 * in order to allow failover to the existing DNS servers in case the tunnel
 * DNS server(s) are unavailable, the DNS key we create will be a copy of the
 * DNS key of the active interface with the tunnel DNS servers added.
 *
 * Because we don't want these keys to exist beyond the scope of the tunnel,
 * they will be regenerated every time a DNS server or suffix is added or
 * removed. In the event that the DNS key generation results in no subkeys (i.e.
 * there are no DNS servers or suffix), the keys will be removed.
 */

#include "osx_attr_handler.h"

#include <networking/host.h>
#include <utils/debug.h>
#include <threading/mutex.h>

#include <SystemConfiguration/SystemConfiguration.h>
#include <SystemConfiguration/SCDynamicStore.h>

#define SERVICE_ID  "strongswan"
static CFStringRef service_id = CFSTR(SERVICE_ID);

#define RELEASE_IF(ref) if (ref) { CFRelease(ref); ref = NULL; }

typedef struct private_osx_attr_handler_t private_osx_attr_handler_t;


/**
 * Server entry
 */
typedef struct {
	/** address */
	host_t *ip;
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
 * Suffix entry
 */
typedef struct {
	/** suffix */
	char *suffix;
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
 * Return a string description of the specified CFErrorRef. Note that this
 * string is kept in a static buffer and therefore is not thread safe.
 */
static const char *last_err_str()
{
	static char buf[512];
	CFStringRef str_ref = NULL;
	CFErrorRef err_ref = NULL;

	do
	{
		memset(buf, 0, sizeof(buf));

		err_ref = SCCopyLastError();
		if ( !err_ref )
		{
			break;
		}

		str_ref = CFErrorCopyDescription( err_ref );
		if ( !str_ref )
		{
			break;
		}

		CFStringGetCString( str_ref, buf, sizeof(buf), kCFStringEncodingUTF8 );

	} while ( 0 );

	RELEASE_IF( str_ref );
	RELEASE_IF( err_ref );

	return buf;
}

/**
 * Return the path to the primary service. Any non-NULL returned CFStringRef
 * must be freed by calling CFRelease.
 */
static CFStringRef get_primary_service(SCDynamicStoreRef store)
{
	CFStringRef service = NULL;
	CFDictionaryRef dict;

	/* Open the global IPv4 key */
	dict = SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/IPv4"));
	if (dict)
	{
		/* The PrimaryService subkey is what we are interested in */
		CFStringRef value = CFDictionaryGetValue(dict, CFSTR("PrimaryService"));
		if (!value)
		{
			DBG1(DBG_KNL, "Global IPv4 SystemConfiguration PrimaryService not known");
		}
		service = CFStringCreateCopy( NULL, value );
		if (!service)
		{
			DBG1(DBG_KNL, "Failed to copy PrimaryService value");
		}
		CFRelease(dict);
	}
	else
	{
		DBG1(DBG_KNL, "getting global IPv4 SystemConfiguration failed");
	}

	return service;
}

/**
 * Build the path to the IPv4 key for the specified service. The returned
 * CFStringRef must be freed by calling CFRelease.
 */
static CFStringRef create_ipv4_key(CFStringRef service)
{
	CFStringRef key = NULL;
	if (service)
	{
		key = CFStringCreateWithFormat(NULL, NULL, CFSTR("State:/Network/Service/%@/IPv4"), service);
		if (!key)
		{
			DBG1(DBG_KNL, "Failed to create IPv4 key");
		}
	}
	return key;
}

/**
 * Build the path to the IPv6 key for the specified service. The returned
 * CFStringRef must be freed by calling CFRelease.
 */
static CFStringRef create_ipv6_key(CFStringRef service)
{
	CFStringRef key = NULL;
	if (service)
	{
		key = CFStringCreateWithFormat(NULL, NULL, CFSTR("State:/Network/Service/%@/IPv6"), service);
		if (!key)
		{
			DBG1(DBG_KNL, "Failed to create IPv6 key");
		}
	}
	return key;
}

/**
 * Build the path to the DNS key for the specified service. The returned
 * CFStringRef must be freed by calling CFRelease.
 */
static CFStringRef create_dns_key(CFStringRef service)
{
	CFStringRef key = NULL;
	if (service)
	{
		key = CFStringCreateWithFormat(NULL, NULL, CFSTR("State:/Network/Service/%@/DNS"), service);
		if (!key)
		{
			DBG1(DBG_KNL, "Failed to create DNS key");
		}
	}
	return key;
}

/**
 * Open a mutable dictionary from path. If it doesn't yet exist, optionally
 * create a new one. The returned CFMutableDictionaryRef must be freed by
 * calling CFRelease.
 */
static CFMutableDictionaryRef open_mutable_dict(SCDynamicStoreRef store,
												CFStringRef path,
												bool create)
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
	if (!mut && create)
	{
		mut = CFDictionaryCreateMutable(NULL, 0,
										&kCFTypeDictionaryKeyCallBacks,
										&kCFTypeDictionaryValueCallBacks);
	}
	return mut;
}

static bool key_exists( SCDynamicStoreRef store, CFStringRef key )
{
	CFPropertyListRef pl;

	if (!store || !key)
	{
		return FALSE;
	}

	pl = SCDynamicStoreCopyValue(store, key);
	if (pl)
	{
		CFRelease(pl);
		return TRUE;
	}
	return FALSE;
}

static CFMutableDictionaryRef build_dns_dict(private_osx_attr_handler_t *this)
{
	/* Build a DNS dictionary from the current known DNS addresses and suffixes.
	 * If no addresses or suffixes are currently known, then return NULL. */
	CFMutableDictionaryRef dict = NULL;
	int servers_count = this->servers->get_count(this->servers);
	int suffixes_count = this->suffixes->get_count(this->suffixes);
	if ( servers_count == 0 && suffixes_count == 0 )
	{
		/* Expected result when nothing to build */
		return NULL;
	}

	do
	{
		/* Create the mutable dictionary */
		dict = CFDictionaryCreateMutable(NULL, 0,
										 &kCFTypeDictionaryKeyCallBacks,
										 &kCFTypeDictionaryValueCallBacks);
		if (!dict)
		{
			DBG1(DBG_KNL, "failed to create mutable dictionary for DNS: %s", last_err_str());
			break;
		}

		/* Add in the DNS servers */
		if (servers_count > 0)
		{
			server_t *server = NULL;
			char buf[64];
			enumerator_t *enumerator;
			CFStringRef dns_server_ref = NULL;
			CFMutableArrayRef array_ref = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
			if (!array_ref)
			{
				DBG1(DBG_KNL, "failed to create array for DNS servers");
				break;
			}

			enumerator = this->servers->create_enumerator( this->servers );
			while ( enumerator->enumerate( enumerator, &server ) )
			{
				snprintf(buf, sizeof(buf), "%H", server->ip);

				dns_server_ref = CFStringCreateWithCString(NULL, buf, kCFStringEncodingUTF8);
				if (!dns_server_ref)
				{
					DBG1(DBG_KNL, "Failed to create CF string from DNS server '%s'", buf);
					break;
				}
				CFArrayAppendValue(array_ref, dns_server_ref);
				CFRelease(dns_server_ref);

			}
			enumerator->destroy( enumerator );

			CFDictionarySetValue(dict, CFSTR("ServerAddresses"), array_ref);
			CFRelease(array_ref);
		}

		/* Add in the DNS suffixes */
		if (suffixes_count > 0)
		{
			suffix_t *suffix = NULL;
			enumerator_t *enumerator;
			CFStringRef dns_suffix_ref = NULL;
			CFMutableArrayRef array_ref = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
			if (!array_ref)
			{
				DBG1(DBG_KNL, "failed to create array for DNS suffixes");
				break;
			}

			enumerator = this->suffixes->create_enumerator( this->suffixes );
			while ( enumerator->enumerate( enumerator, &suffix ) )
			{
				dns_suffix_ref = CFStringCreateWithCString(NULL, suffix->suffix, kCFStringEncodingUTF8);
				if (!dns_suffix_ref)
				{
					DBG1(DBG_KNL, "Failed to create CF string from DNS suffix '%s'", suffix->suffix);
					break;
				}
				CFArrayAppendValue(array_ref, dns_suffix_ref);
				CFRelease(dns_suffix_ref);

			}
			enumerator->destroy( enumerator );

			CFDictionarySetValue(dict, CFSTR("SearchDomains"), array_ref);
			CFRelease(array_ref);
		}
	} while ( 0 );

	return dict;
}

static bool copy_ip_key( SCDynamicStoreRef store, CFStringRef src_key, CFStringRef dst_key )
{
	CFMutableDictionaryRef dict = NULL;
	int one = 1;
	CFNumberRef one_ref = NULL;
	bool success = FALSE;

	/* Nothing to copy if src does not exist (and that's OK as far as we're
	 * concerned). */
	if (!key_exists(store, src_key))
	{
		return TRUE;
	}

	do
	{
		/* Open a mutable copy of the source dictionary. */
		dict = open_mutable_dict( store, src_key, FALSE );
		if (!dict)
		{
			/* We failed to get a mutable dictionary object for the IPv4
			 * key, which means we can't copy it so there's really nothing
			 * more to do. */
			DBG1(DBG_KNL, "Failed to open source dictionary");
			break;
		}

		/* Tedious. Create the number 1 into an object that we can pass into
		 * the IPv4/IPv6 dictionaries. */
		one_ref = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &one);
		if (!one_ref)
		{
			DBG1(DBG_KNL, "Failed to create number ref: %s", last_err_str());
			break;
		}

		/* Set the OverridePrimary flags, which indicates to the System
		 * Configuration that this new service should be the primary. */
		CFDictionarySetValue(dict, CFSTR("OverridePrimary"), one_ref);

		/* Write the modified dictionary into the store for the destination. */
		if ( !SCDynamicStoreSetValue(store, dst_key, dict) )
		{
			DBG1(DBG_KNL, "Failed to set settings to dynamic store: %s", last_err_str());
			break;
		}

		sleep(2);

		success = TRUE;
	} while ( 0 );

	RELEASE_IF( one_ref );
	RELEASE_IF( dict );

	return success;
}

/**
 * Updates (adds or removes as necessary) our DNS settings to the System
 * Configuration. If we have any DNS servers or suffixes, we will write our
 * service entries to the System Configuration. If we do not have any DNS
 * servers or suffixes, we will remove our service entries from the System
 * Configuration.
 */
static bool update_dns_settings( private_osx_attr_handler_t *this )
{
	bool success = FALSE, exists = FALSE;
	SCDynamicStoreRef store = NULL;
	CFStringRef primary_service = NULL;
	CFStringRef src_dns_key = NULL, dst_dns_key = NULL;
	CFStringRef src_ipv4_key = NULL, dst_ipv4_key = NULL;
	CFStringRef src_ipv6_key = NULL, dst_ipv6_key = NULL;
	CFMutableDictionaryRef dns_dict = NULL;

	do
	{
		/* Can't do anything without first opening the store */
		store = SCDynamicStoreCreate(NULL, CFSTR("osx-attr"), NULL, NULL);
		if (store == NULL)
		{
			DBG1(DBG_KNL, "Failed to create dynamic store for osx-attr");
			break;
		}

		/* Create our destination keys */
		dst_dns_key = create_dns_key( service_id );
		dst_ipv4_key = create_ipv4_key( service_id );
		dst_ipv6_key = create_ipv6_key( service_id );
		if (!dst_dns_key || !dst_ipv4_key || !dst_ipv6_key)
		{
			DBG1(DBG_KNL, "Failed to create destination DNS key");
			break;
		}

		/* Create the DNS dictionary we will write to System Configuration. If
		 * we fail to create the dictionary, we will ensure that our service
		 * entries are removed from System Configuration. */
		dns_dict = build_dns_dict( this );
		if (!dns_dict)
		{
			DBG2(DBG_KNL, "Removing service keys from System Configuration");

			success = true;
			/* No DNS dictionary built, remove all our keys */
			if ( key_exists( store, dst_dns_key ) &&
				 !SCDynamicStoreRemoveValue( store, dst_dns_key ) )
			{
				DBG1(DBG_KNL, "Failed to remove destination DNS key");
				success = false;
			}
			if ( key_exists( store, dst_ipv4_key ) &&
				 !SCDynamicStoreRemoveValue( store, dst_ipv4_key ) )
			{
				DBG1(DBG_KNL, "Failed to remove destination IPv4 key");
				success = false;
			}
			if ( key_exists( store, dst_ipv6_key ) &&
				 !SCDynamicStoreRemoveValue( store, dst_ipv6_key ) )
			{
				DBG1(DBG_KNL, "Failed to remove destination IPv6 key");
				success = false;
			}
			sleep(2);
			break;
		}

		/* We built our DNS dictionary. If our service DNS key does not already
		 * exist then we need to create it and the IPv4/IPv6 keys as well after
		 * we write the DNS dictionary.
		 */
		exists = key_exists(store, dst_dns_key);

		/* Write the DNS dictionary. */
		if ( !SCDynamicStoreSetValue(store, dst_dns_key, dns_dict) )
		{
			DBG1(DBG_KNL, "Failed to set DNS settings to dynamic store: %s", last_err_str());
			break;
		}

		DBG2(DBG_KNL, "Successfully wrote DNS server settings to System Configuration");

		if (!exists)
		{
			/* Get the primary service. This will be used to create our source
			 * keys. */
			primary_service = get_primary_service( store );
			if (!primary_service)
			{
				DBG1(DBG_KNL, "Failed to find primary service");
				break;
			}

			/* Build the rest of our source and destination keys */
			src_dns_key = create_dns_key( primary_service );
			src_ipv4_key = create_ipv4_key( primary_service );
			src_ipv6_key = create_ipv6_key( primary_service );
			if (!src_dns_key || !src_ipv4_key || !src_ipv6_key ||
				!dst_ipv4_key || !dst_ipv6_key)
			{
				/* Log already generated */
				break;
			}

			/* Copy the IPv4 and IPv6 keys. This function will also set the
			 * OverridePrimary flag. */
			if ( !copy_ip_key(store, src_ipv4_key, dst_ipv4_key) )
			{
				DBG1(DBG_KNL, "Failed to copy IPv4 to our service key");
				break;
			}
			DBG2(DBG_KNL, "Successfully wrote IPv4 server settings to System Configuration");

			if ( !copy_ip_key(store, src_ipv6_key, dst_ipv6_key) )
			{
				DBG1(DBG_KNL, "Failed to copy IPv6 to our service key");
				break;
			}
			DBG2(DBG_KNL, "Successfully wrote IPv6 server settings to System Configuration");
		}

		/* Jolly good */
		success = TRUE;

	} while ( 0 );

	RELEASE_IF(src_dns_key);
	RELEASE_IF(src_ipv4_key);
	RELEASE_IF(src_ipv6_key);
	RELEASE_IF(dst_dns_key);
	RELEASE_IF(dst_ipv4_key);
	RELEASE_IF(dst_ipv6_key);
	RELEASE_IF(dns_dict);
	RELEASE_IF(store);

	return success;
}

METHOD(attribute_handler_t, handle, bool,
	private_osx_attr_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	bool handled = FALSE;

	if ( type == INTERNAL_IP6_DNS )
	{
		/* We don't handle this yet - TBD */
		DBG1(DBG_KNL, "IPv6 DNS not yet stupported");
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

		this->mutex->lock( this->mutex );

		DBG2(DBG_KNL, "Adding DNS server %H to System Configuration", ip);

		INIT( entry,
			  .ip = ip->clone( ip ),
			  );
		this->servers->insert_last( this->servers, entry );
		handled = update_dns_settings(this);
		if ( !handled )
		{
			DBG1(DBG_KNL, "adding DNS server failed");
			this->servers->remove( this->servers, entry, NULL );
			server_destroy( entry );
		}
		else
		{
			DBG2(DBG_KNL, "DNS server %H added to System Configuration", ip);
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
			DBG1(DBG_KNL, "Given domain name length of %d is too big", data.len);
			return FALSE;
		}

		memcpy( suffix, data.ptr, data.len );

		DBG2(DBG_KNL, "Handling DNS suffix %s", suffix);

		this->mutex->lock( this->mutex );

		DBG2(DBG_KNL, "Adding DNS suffix %s to System Configuration", suffix);

		INIT( entry,
			  .suffix = strdup(suffix),
			  );
		this->suffixes->insert_last( this->suffixes, entry );
		handled = update_dns_settings(this);
		if ( !handled )
		{
			DBG1(DBG_KNL, "adding DNS suffix failed");
			this->suffixes->remove( this->suffixes, entry, NULL );
			suffix_destroy( entry );
		}
		else
		{
			DBG2(DBG_KNL, "DNS suffix %s added to System Configuration", suffix);
		}

		this->mutex->unlock( this->mutex );
	}

	return handled;
}

METHOD(attribute_handler_t, release, void,
	private_osx_attr_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	if ( type == INTERNAL_IP6_DNS )
	{
		/* We don't handle this yet - TBD */
		DBG1(DBG_KNL, "IPv6 DNS not yet stupported");
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

		DBG2(DBG_KNL, "Removing DNS server %H", ip);

		this->mutex->lock( this->mutex );

		// Find the server
		find_server( this->servers, ip, &entry );
		if ( entry )
		{
			this->servers->remove( this->servers, entry, NULL );
			server_destroy( entry );
			if ( !update_dns_settings(this) )
			{
				DBG1(DBG_KNL, "removing DNS server failed");
			}
			else
			{
				DBG2(DBG_KNL, "DNS server %H removed from System Configuration", ip);
			}
		}
		else
		{
			DBG2(DBG_KNL, "DNS server %H not in servers list - nothing more to do", ip);
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
			DBG1(DBG_KNL, "Given domain name length of %d is too big", data.len);
			return;
		}

		memcpy( suffix, data.ptr, data.len );

		DBG2(DBG_KNL, "Removing DNS suffix %s", suffix);

		this->mutex->lock( this->mutex );

		// Find the suffix
		find_suffix( this->suffixes, suffix, &entry );
		if ( entry )
		{
			this->suffixes->remove( this->suffixes, entry, NULL );
			suffix_destroy( entry );
			if ( ! update_dns_settings(this) )
			{
				DBG1(DBG_KNL, "removing DNS suffix failed");
			}
			else
			{
				DBG2(DBG_KNL, "DNS suffix %s removed from System Configuration", suffix);
			}
		}
		else
		{
			DBG2(DBG_KNL, "DNS suffix %s not in suffixes list - nothing more to do", suffix);
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
