/* FreeS/WAN Virtual IP Management
 * Copyright (C) 2002 Mathieu Lafon - Arkoon Network Security
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

#include <freeswan.h>

#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "connections.h"
#include "whack.h"
#include "virtual.h"

#define F_VIRTUAL_NO          1
#define F_VIRTUAL_DHCP        2
#define F_VIRTUAL_IKE_CONFIG  4
#define F_VIRTUAL_PRIVATE     8
#define F_VIRTUAL_ALL         16
#define F_VIRTUAL_HOST        32

struct virtual_t {
	unsigned short flags;
	unsigned short n_net;
	ip_subnet net[0];
};

static ip_subnet *private_net_ok=NULL, *private_net_ko=NULL;
static unsigned short private_net_ok_len=0, private_net_ko_len=0;

/**
 * read %v4:x.x.x.x/y or %v6:xxxxxxxxx/yy
 * or %v4:!x.x.x.x/y if dstko not NULL
 */
static bool
_read_subnet(const char *src, size_t len, ip_subnet *dst, ip_subnet *dstko,
	bool *isok)
{
	bool ok;
	int af;

	if ((len > 4) && (strneq(src, "%v4:", 4)))
	{
		af = AF_INET;
	}
	else if ((len > 4) && (strneq(src, "%v6:", 4)))
	{
		af = AF_INET6;
	}
	else
	{
		return FALSE;
	}

	ok = (src[4] != '!');
	src += ok ? 4 : 5;
	len -= ok ? 4 : 5;

	if (!len)
		return FALSE;
	if (!ok && !dstko)
		return FALSE;

	passert ( ((ok)?(dst):(dstko))!=NULL );

	if (ttosubnet(src, len, af, ((ok)?(dst):(dstko))))
	{
		return FALSE;
	}
	if (isok)
		*isok = ok;
	return TRUE;
}

void
init_virtual_ip(const char *private_list)
{
	const char *next, *str=private_list;
	unsigned short ign = 0, i_ok, i_ko;
	ip_subnet sub;
	bool ok;

	/** Count **/
	private_net_ok_len=0;
	private_net_ko_len=0;

	while (str)
	{
		next = strchr(str,',');
		if (!next)
			next = str + strlen(str);
		if (_read_subnet(str, next-str, &sub, &sub, &ok))
			if (ok)
				private_net_ok_len++;
			else
				private_net_ko_len++;
		else
			ign++;
		str = *next ? next+1 : NULL;
	}

	if (!ign)
	{
		/** Allocate **/
		if (private_net_ok_len)
		{
			private_net_ok = (ip_subnet *)malloc(private_net_ok_len * sizeof(ip_subnet));
		}
		if (private_net_ko_len)
		{
			private_net_ko = (ip_subnet *)malloc(private_net_ko_len * sizeof(ip_subnet));
		}
		if ((private_net_ok_len && !private_net_ok)
		||  (private_net_ko_len && !private_net_ko))
		{
			loglog(RC_LOG_SERIOUS,
				"can't alloc in init_virtual_ip");
			free(private_net_ok);
			private_net_ok = NULL;
			free(private_net_ko);
			private_net_ko = NULL;
		}
		else
		{
			/** Fill **/
			str = private_list;
			i_ok = 0;
			i_ko = 0;

			while (str)
			{
				next = strchr(str,',');
				if (!next)
					next = str + strlen(str);
				if (_read_subnet(str, next-str,
				   &(private_net_ok[i_ok]), &(private_net_ko[i_ko]), &ok))
				{
					if (ok)
						i_ok++;
					else
						i_ko++;
				}
				str = *next ? next+1 : NULL;
			}
		}
	}
	else
		loglog(RC_LOG_SERIOUS,
			"%d bad entries in virtual_private - none loaded", ign);
}

/**
 * virtual string must be :
 * {vhost,vnet}:[%method]*
 *
 * vhost = accept only a host (/32)
 * vnet  = accept any network
 *
 * %no   = no virtual IP (accept public IP)
 * %dhcp = accept DHCP SA (0.0.0.0/0) of affected IP  [not implemented]
 * %ike  = accept affected IKE Config Mode IP         [not implemented]
 * %priv = accept system-wide private net list
 * %v4:x = accept ipv4 in list 'x'
 * %v6:x = accept ipv6 in list 'x'
 * %all  = accept all ips                             [only for testing]
 *
 * ex: vhost:%no,%dhcp,%priv,%v4:192.168.1.0/24
 */
struct virtual_t
*create_virtual(const struct connection *c, const char *string)
{
	unsigned short flags=0, n_net=0, i;
	const char *str = string, *next, *first_net=NULL;
	ip_subnet sub;
	struct virtual_t *v;

	if (!string || string[0] == '\0')
		return NULL;

	if (strlen(string) >= 6 && strneq(string,"vhost:",6))
	{
		flags |= F_VIRTUAL_HOST;
		str += 6;
	}
	else if (strlen(string) >= 5 && strneq(string,"vnet:",5))
		str += 5;
	else
		goto fail;

	/**
	 * Parse string : fill flags & count subnets
	 */
	while ((str) && (*str))
	{
		next = strchr(str,',');
		if (!next) next = str + strlen(str);
		if (next-str == 3 && strneq(str, "%no", 3))
			flags |= F_VIRTUAL_NO;
#if 0
		else if (next-str == 4 && strneq(str, "%ike", 4))
			flags |= F_VIRTUAL_IKE_CONFIG;
		else if (next-str == 5 && strneq(str, "%dhcp", 5))
			flags |= F_VIRTUAL_DHCP;
#endif
		else if (next-str == 5 && strneq(str, "%priv", 5))
			flags |= F_VIRTUAL_PRIVATE;
		else if (next-str == 4 && strneq(str, "%all", 4))
			flags |= F_VIRTUAL_ALL;
		else if (_read_subnet(str, next-str, &sub, NULL, NULL))
		{
			n_net++;
			if (!first_net)
				first_net = str;
		}
		else
			goto fail;
		
		str = *next ? next+1 : NULL;
	}

	v = (struct virtual_t *)malloc(sizeof(struct virtual_t) +
								  (n_net * sizeof(ip_subnet)));
	if (!v) goto fail;

	v->flags = flags;
	v->n_net = n_net;
	if (n_net && first_net)
	{
		/**
		 * Save subnets in newly allocated struct
		 */
		for (str = first_net, i = 0; str && *str; )
		{
			next = strchr(str,',');
			if (!next) next = str + strlen(str);
			if (_read_subnet(str, next-str, &(v->net[i]), NULL, NULL))
				i++;
			str = *next ? next+1 : NULL;
		}
	}

	return v;

fail:
	plog("invalid virtual string [%s] - "
		"virtual selection disabled for connection '%s'", string, c->name);
	return NULL;
}

bool
is_virtual_end(const struct end *that)
{
	return ((that->virt)?TRUE:FALSE);
}

bool
is_virtual_connection(const struct connection *c)
{
	return ((c->spd.that.virt)?TRUE:FALSE);
}

static bool
net_in_list(const ip_subnet *peer_net, const ip_subnet *list,
	unsigned short len)
{
	unsigned short i;

	if (!list || !len)
		return FALSE;

	for (i = 0; i < len; i++)
	{
		if (subnetinsubnet(peer_net, &(list[i])))
			return TRUE;
	}
	return FALSE;
}

bool
is_virtual_net_allowed(const struct connection *c, const ip_subnet *peer_net,
		const ip_address *his_addr)
{
	if (c->spd.that.virt == NULL)
		return FALSE;

	if ((c->spd.that.virt->flags & F_VIRTUAL_HOST)
	&&  !subnetishost(peer_net))
		return FALSE;

	if ((c->spd.that.virt->flags & F_VIRTUAL_NO)
	&&  subnetishost(peer_net) &&  addrinsubnet(his_addr, peer_net))
		return TRUE;

	if ((c->spd.that.virt->flags & F_VIRTUAL_PRIVATE)
	&&   net_in_list(peer_net, private_net_ok, private_net_ok_len)
	&&  !net_in_list(peer_net, private_net_ko, private_net_ko_len))
		return TRUE;

	if (c->spd.that.virt->n_net
	&&  net_in_list(peer_net, c->spd.that.virt->net, c->spd.that.virt->n_net))
		return TRUE;
	
	if (c->spd.that.virt->flags & F_VIRTUAL_ALL)
	{
		/** %all must only be used for testing - log it **/
		loglog(RC_LOG_SERIOUS, "Warning - "
			"v%s:%%all must only be used for testing",
			(c->spd.that.virt->flags & F_VIRTUAL_HOST) ? "host" : "net");
		return TRUE;
	}

	return FALSE;
}

