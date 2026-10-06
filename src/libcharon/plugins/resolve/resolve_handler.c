/*
 * Copyright (C) 2012-2023 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
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

#include "resolve_handler.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utils/debug.h>
#include <utils/process.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>

/* path to resolvconf executable */
#define RESOLVCONF_EXEC "/sbin/resolvconf"

/* default interface/protocol used for resolvconf (should have high prio) */
#define RESOLVCONF_IFACE "lo.ipsec"

/* suffix added to lines in resolv.conf */
#define RESOLV_CONF_SUFFIX "   # by strongSwan"

typedef struct private_resolve_handler_t private_resolve_handler_t;

/**
 * Private data of an resolve_handler_t object.
 */
struct private_resolve_handler_t {

	/**
	 * Public resolve_handler_t interface.
	 */
	resolve_handler_t public;

	/**
	 * resolv.conf file to use
	 */
	char *file;

	/**
	 * Path/command for resolvconf(8)
	 */
	char *resolvconf;

	/**
	 * Interface name sent to resolvconf
	 */
	char *iface;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;

	/**
	 * Reference counting for DNS servers dns_server_t
	 */
	hashtable_t *servers;

	/**
	 * Reference counting for DNS search domains dns_domain_t
	 */
	hashtable_t *domains;
};

/**
 * Reference counting for DNS servers
 */
typedef struct {

	/**
	 * DNS server address
	 */
	host_t *server;

	/**
	 * Reference count
	 */
	u_int refcount;

} dns_server_t;

/**
 * Reference counting for DNS search domains
 */
typedef struct {
	/** DNS search domain */
	char *domain;
	/** reference count */
	u_int refcount;
} dns_domain_t;

/**
 * Hash DNS server address
 */
static u_int dns_server_hash(const void *key)
{
	host_t *host = (host_t*)key;
	return chunk_hash(host->get_address(host));
}

/**
 * Compare two DNS server addresses
 */
static bool dns_server_equals(const void *a, const void *b)
{
	host_t *ha = (host_t*)a, *hb = (host_t*)b;
	return chunk_equals(ha->get_address(ha), hb->get_address(hb));
}

/**
 * Convert a received DNS domain attribute to a sanitized, NUL-terminated
 * string. The value is responder-controlled and gets written to resolv.conf,
 * so replace any non-printable bytes (e.g. a newline that would otherwise
 * inject a nameserver line).
 */
static char *sanitize_domain(chunk_t data)
{
	chunk_t sane;
	char *domain;

	chunk_printable(data, &sane, '?');
	domain = strndup(sane.ptr, sane.len);
	chunk_free(&sane);
	return domain;
}

/**
 * Writes the current set of nameservers and search domains to resolv.conf
 */
static bool write_resolv_conf(private_resolve_handler_t *this)
{
	FILE *in, *out;
	enumerator_t *enumerator;
	dns_server_t *dns;
	dns_domain_t *dom;
	char line[1024];
	bool handled = FALSE;

	in = fopen(this->file, "r");
	/* allows us to stream from in to out */
	unlink(this->file);
	out = fopen(this->file, "w");
	if (out)
	{
		/* write our current set of servers */
		enumerator = this->servers->create_enumerator(this->servers);
		while (enumerator->enumerate(enumerator, NULL, &dns))
		{
			fprintf(out, "nameserver %H" RESOLV_CONF_SUFFIX "\n", dns->server);
		}
		enumerator->destroy(enumerator);

		/* write our current set of search domains as a single line */
		if (this->domains->get_count(this->domains))
		{
			fprintf(out, "search");
			enumerator = this->domains->create_enumerator(this->domains);
			while (enumerator->enumerate(enumerator, NULL, &dom))
			{
				fprintf(out, " %s", dom->domain);
			}
			enumerator->destroy(enumerator);
			fprintf(out, RESOLV_CONF_SUFFIX "\n");
		}

		if (in)
		{
			/* copy the rest of the file, except our previous entries */
			while (fgets(line, sizeof(line), in))
			{
				if (!strstr(line, RESOLV_CONF_SUFFIX "\n"))
				{
					fputs(line, out);
				}
			}
		}

		handled = TRUE;

		fclose(out);
	}
	if (in)
	{
		fclose(in);
	}
	return handled;
}

/**
 * Install the current set of nameservers and search domains by invoking
 * resolvconf. If there are none, remove the config.
 */
static bool invoke_resolvconf(private_resolve_handler_t *this)
{
	process_t *process;
	enumerator_t *enumerator;
	dns_server_t *dns;
	dns_domain_t *dom;
	FILE *shell;
	int in, out, retval;
	bool install = this->servers->get_count(this->servers) ||
				   this->domains->get_count(this->domains);

	process = process_start_shell(NULL, install ? &in : NULL, &out,
								  NULL, "2>&1 %s %s %s", this->resolvconf,
								  install ? "-a" : "-d", this->iface);
	if (!process)
	{
		return FALSE;
	}
	if (install)
	{
		shell = fdopen(in, "w");
		if (shell)
		{
			enumerator = this->servers->create_enumerator(this->servers);
			while (enumerator->enumerate(enumerator, NULL, &dns))
			{
				fprintf(shell, "nameserver %H\n", dns->server);
			}
			enumerator->destroy(enumerator);

			if (this->domains->get_count(this->domains))
			{
				fprintf(shell, "search");
				enumerator = this->domains->create_enumerator(this->domains);
				while (enumerator->enumerate(enumerator, NULL, &dom))
				{
					fprintf(shell, " %s", dom->domain);
				}
				enumerator->destroy(enumerator);
				fprintf(shell, "\n");
			}
			fclose(shell);
		}
		else
		{
			close(in);
			close(out);
			process->wait(process, NULL);
			return FALSE;
		}
	}
	else
	{
		DBG1(DBG_IKE, "removing DNS servers via resolvconf");
	}
	shell = fdopen(out, "r");
	if (shell)
	{
		while (TRUE)
		{
			char resp[128], *e;

			if (fgets(resp, sizeof(resp), shell) == NULL)
			{
				if (ferror(shell))
				{
					DBG1(DBG_IKE, "error reading from resolvconf");
				}
				break;
			}
			else
			{
				e = resp + strlen(resp);
				if (e > resp && e[-1] == '\n')
				{
					e[-1] = '\0';
				}
				DBG1(DBG_IKE, "resolvconf: %s", resp);
			}
		}
		fclose(shell);
	}
	else
	{
		close(out);
	}
	return process->wait(process, &retval) && retval == EXIT_SUCCESS;
}

/**
 * Install a received DNS search domain, reference counting duplicates.
 */
static bool handle_domain(private_resolve_handler_t *this, chunk_t data)
{
	dns_domain_t *found;
	char *domain;
	bool handled;

	if (!data.len)
	{
		return FALSE;
	}
	domain = sanitize_domain(data);

	this->mutex->lock(this->mutex);
	found = this->domains->get(this->domains, domain);
	if (!found)
	{
		INIT(found,
			.domain = domain,
			.refcount = 1,
		);
		this->domains->put(this->domains, found->domain, found);

		if (this->resolvconf)
		{
			DBG1(DBG_IKE, "installing DNS search domain %s via resolvconf",
				 domain);
			handled = invoke_resolvconf(this);
		}
		else
		{
			DBG1(DBG_IKE, "installing DNS search domain %s to %s", domain,
				 this->file);
			handled = write_resolv_conf(this);
		}
		if (!handled)
		{
			this->domains->remove(this->domains, found->domain);
			free(found->domain);
			free(found);
		}
	}
	else
	{
		DBG1(DBG_IKE, "DNS search domain %s already installed, increasing "
			 "refcount", domain);
		found->refcount++;
		handled = TRUE;
		free(domain);
	}
	this->mutex->unlock(this->mutex);

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS search domain failed");
	}
	return handled;
}

METHOD(attribute_handler_t, handle, bool,
	private_resolve_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	dns_server_t *found;
	host_t *addr;
	bool handled;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			addr = host_create_from_chunk(AF_INET, data, 0);
			break;
		case INTERNAL_IP6_DNS:
			addr = host_create_from_chunk(AF_INET6, data, 0);
			break;
		case INTERNAL_DNS_DOMAIN:
			return handle_domain(this, data);
		default:
			return FALSE;
	}

	if (!addr || addr->is_anyaddr(addr))
	{
		DESTROY_IF(addr);
		return FALSE;
	}

	this->mutex->lock(this->mutex);
	found = this->servers->get(this->servers, addr);
	if (!found)
	{
		INIT(found,
			.server = addr->clone(addr),
			.refcount = 1,
		);
		this->servers->put(this->servers, found->server, found);

		if (this->resolvconf)
		{
			DBG1(DBG_IKE, "installing DNS server %H via resolvconf", addr);
			handled = invoke_resolvconf(this);
		}
		else
		{
			DBG1(DBG_IKE, "installing DNS server %H to %s", addr, this->file);
			handled = write_resolv_conf(this);
		}
		if (!handled)
		{
			this->servers->remove(this->servers, found->server);
			found->server->destroy(found->server);
			free(found);
		}
	}
	else
	{
		DBG1(DBG_IKE, "DNS server %H already installed, increasing refcount",
			 addr);
		found->refcount++;
		handled = TRUE;
	}
	this->mutex->unlock(this->mutex);
	addr->destroy(addr);

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS server failed");
	}
	return handled;
}

/**
 * Release a previously installed DNS search domain.
 */
static void release_domain(private_resolve_handler_t *this, chunk_t data)
{
	dns_domain_t *found;
	char *domain;

	domain = sanitize_domain(data);

	this->mutex->lock(this->mutex);
	found = this->domains->get(this->domains, domain);
	if (found)
	{
		if (--found->refcount > 0)
		{
			DBG1(DBG_IKE, "DNS search domain %s still used, decreasing "
				 "refcount", domain);
		}
		else
		{
			this->domains->remove(this->domains, found->domain);
			free(found->domain);
			free(found);

			if (this->resolvconf)
			{
				DBG1(DBG_IKE, "removing DNS search domain %s via resolvconf",
					 domain);
				invoke_resolvconf(this);
			}
			else
			{
				DBG1(DBG_IKE, "removing DNS search domain %s from %s", domain,
					 this->file);
				write_resolv_conf(this);
			}
		}
	}
	this->mutex->unlock(this->mutex);

	free(domain);
}

METHOD(attribute_handler_t, release, void,
	private_resolve_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	dns_server_t *found;
	host_t *addr;
	int family;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		case INTERNAL_DNS_DOMAIN:
			release_domain(this, data);
			return;
		default:
			return;
	}
	addr = host_create_from_chunk(family, data, 0);

	this->mutex->lock(this->mutex);
	found = this->servers->get(this->servers, addr);
	if (found)
	{
		if (--found->refcount > 0)
		{
			DBG1(DBG_IKE, "DNS server %H still used, decreasing refcount",
				 addr);
		}
		else
		{
			this->servers->remove(this->servers, found->server);
			found->server->destroy(found->server);
			free(found);

			if (this->resolvconf)
			{
				DBG1(DBG_IKE, "removing DNS server %H via resolvconf", addr);
				invoke_resolvconf(this);
			}
			else
			{
				DBG1(DBG_IKE, "removing DNS server %H from %s", addr,
					 this->file);
				write_resolv_conf(this);
			}
		}
	}
	this->mutex->unlock(this->mutex);

	addr->destroy(addr);
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
	/** request DNS search domains? */
	bool domain;
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
	if (this->domain)
	{
		*type = INTERNAL_DNS_DOMAIN;
		*data = chunk_empty;
		this->domain = FALSE;
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
	private_resolve_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	attribute_enumerator_t *enumerator;
	bool v4, v6;

	v4 = has_host_family(vips, AF_INET);
	v6 = has_host_family(vips, AF_INET6);

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _attribute_enumerate,
			.destroy = (void*)free,
		},
		.v4 = v4,
		.v6 = v6,
		.domain = v4 || v6,
	);
	return &enumerator->public;
}

METHOD(resolve_handler_t, destroy, void,
	private_resolve_handler_t *this)
{
	this->servers->destroy(this->servers);
	this->domains->destroy(this->domains);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
resolve_handler_t *resolve_handler_create()
{
	private_resolve_handler_t *this;
	struct stat st;

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
		.servers = hashtable_create(dns_server_hash, dns_server_equals, 4),
		.domains = hashtable_create(hashtable_hash_str, hashtable_equals_str, 4),
		.file = lib->settings->get_str(lib->settings,
								"%s.plugins.resolve.file", RESOLV_CONF, lib->ns),
		.resolvconf = lib->settings->get_str(lib->settings,
								"%s.plugins.resolve.resolvconf.path",
								NULL, lib->ns),
		.iface = lib->settings->get_str(lib->settings,
								"%s.plugins.resolve.resolvconf.iface",
					lib->settings->get_str(lib->settings,
								"%s.plugins.resolve.resolvconf.iface_prefix",
								RESOLVCONF_IFACE, lib->ns), lib->ns),
	);

	if (!this->resolvconf && stat(RESOLVCONF_EXEC, &st) == 0)
	{
		this->resolvconf = RESOLVCONF_EXEC;
	}

	if (this->resolvconf)
	{
		DBG1(DBG_CFG, "using '%s' to install DNS servers", this->resolvconf);
	}
	else
	{
		DBG1(DBG_CFG, "install DNS servers in '%s'", this->file);
	}
	return &this->public;
}
