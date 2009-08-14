/* strongSwan IPsec interfaces management
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <freeswan.h>

#include <constants.h>
#include <defs.h>
#include <log.h>

#include "interfaces.h"
#include "exec.h"
#include "files.h"

/*
 * discover the default route via /proc/net/route
 */
void
get_defaultroute(defaultroute_t *defaultroute)
{
	FILE *fd;
	char line[BUF_LEN];
	bool first = TRUE;

	memset(defaultroute, 0, sizeof(defaultroute_t));

	fd = fopen("/proc/net/route", "r");

	if (!fd)
	{
		plog("could not open 'proc/net/route'");
		return;
	}

	while (fgets(line, sizeof(line), fd) != 0)
	{
		char iface[11];
		char destination[9];
		char gateway[11];
		char flags[5];
		char mask[9];

		int refcnt;
		int use;
		int metric;
		int items;

		/* proc/net/route returns IP addresses in host order */
		strcpy(gateway, "0h");

		/* skip the header line */
		if (first)
		{
			first = FALSE;
			continue;
		}

		/* parsing a single line of proc/net/route */
		items = sscanf(line, "%10s\t%8s\t%8s\t%5s\t%d\t%d\t%d\t%8s\t"
					 , iface, destination, gateway+2, flags, &refcnt, &use, &metric, mask);
		if (items < 8)
		{
			plog("parsing error while scanning /proc/net/route");
			continue;
		}

		/* check for defaultroute (destination 0.0.0.0 and mask 0.0.0.0) */
		if (streq(destination, "00000000") && streq(mask, "00000000"))
		{
			if (defaultroute->defined)
			{
				plog("multiple default routes - cannot cope with %%defaultroute!!!");
				defaultroute->defined = FALSE;
				fclose(fd);
				return;
			}
			ttoaddr(gateway, strlen(gateway), AF_INET, &defaultroute->nexthop);
			strncpy(defaultroute->iface, iface, IFNAMSIZ);
			defaultroute->defined = TRUE;
		}
	}
	fclose(fd);

	if (!defaultroute->defined)
	{
		plog("no default route - cannot cope with %%defaultroute!!!");
	}
	else
	{
		char addr_buf[20], nexthop_buf[20];
		struct ifreq physreq;

		int sock = socket(AF_INET, SOCK_DGRAM, 0);

		/* determine IP address of iface */
		if (sock < 0)
		{
			plog("could not open SOCK_DGRAM socket");
			defaultroute->defined = FALSE;
			return;
		}
		memset ((void*)&physreq, 0, sizeof(physreq));
		strncpy(physreq.ifr_name, defaultroute->iface, IFNAMSIZ);
		ioctl(sock, SIOCGIFADDR, &physreq);
		close(sock);
		defaultroute->addr.u.v4 = *((struct sockaddr_in *)&physreq.ifr_addr);

		addrtot(&defaultroute->addr, 0, addr_buf, sizeof(addr_buf));
		addrtot(&defaultroute->nexthop, 0, nexthop_buf, sizeof(nexthop_buf));

		DBG(DBG_CONTROL,
			DBG_log("Default route found: iface=%s, addr=%s, nexthop=%s"
				, defaultroute->iface, addr_buf, nexthop_buf)
		)

		/* for backwards-compatibility with the awk shell scripts
		 * store the defaultroute in /var/run/ipsec.info
		 */
		fd = fopen(INFO_FILE, "w");

		if (fd)
		{
			fprintf(fd, "defaultroutephys=%s\n", defaultroute->iface );
			fprintf(fd, "defaultroutevirt=ipsec0\n");
			fprintf(fd, "defaultrouteaddr=%s\n", addr_buf);
			fprintf(fd, "defaultroutenexthop=%s\n", nexthop_buf);
			fclose(fd);
		}
	}
	return;
}
