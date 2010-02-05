/* strongSwan IPsec interfaces management
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 *               2009 Heiko Hund - Astaro AG
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

#ifdef START_PLUTO

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

/*
 * Get the default route information via rtnetlink
 */
void
get_defaultroute(defaultroute_t *defaultroute)
{
	union {
		struct {
			struct nlmsghdr nh;
			struct rtmsg    rt;
		} m;
		char buf[4096];
	} rtu;

	struct nlmsghdr *nh;
	uint32_t best_metric = ~0;
	ssize_t msglen;
	int fd;

	bzero(&rtu, sizeof(rtu));
	rtu.m.nh.nlmsg_len = NLMSG_LENGTH(sizeof(rtu.m.rt));
	rtu.m.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	rtu.m.nh.nlmsg_type = RTM_GETROUTE;
	rtu.m.rt.rtm_family = AF_INET;
	rtu.m.rt.rtm_table = RT_TABLE_UNSPEC;
	rtu.m.rt.rtm_protocol = RTPROT_UNSPEC;
	rtu.m.rt.rtm_type = RTN_UNICAST;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd == -1)
	{
		plog("could not create rtnetlink socket");
		return;
	}

	if (send(fd, &rtu, rtu.m.nh.nlmsg_len, 0) == -1)
	{
		plog("could not write to rtnetlink socket");
		close(fd);
		return;
	}

	msglen = recv(fd, &rtu, sizeof(rtu), MSG_WAITALL);
	if (msglen == -1)
	{
		plog("could not read from rtnetlink socket");
		close(fd);
		return;
	}

	close(fd);

	for (nh = &rtu.m.nh; NLMSG_OK(nh, msglen); nh = NLMSG_NEXT(nh, msglen))
	{
		struct rtmsg *rt;
		struct rtattr *rta;
		uint32_t rtalen, metric = 0;
		struct in_addr gw = { .s_addr = INADDR_ANY };
		int iface_idx = -1;

		if (nh->nlmsg_type == NLMSG_ERROR)
		{
			plog("error from rtnetlink");
			return;
		}

		if (nh->nlmsg_type == NLMSG_DONE)
			break;

		rt = NLMSG_DATA(nh);
		if ( rt->rtm_dst_len != 0
		||  (rt->rtm_table != RT_TABLE_MAIN
		  && rt->rtm_table != RT_TABLE_DEFAULT) )
			continue;

		rta = RTM_RTA(rt);
		rtalen = RTM_PAYLOAD(nh);
		while ( RTA_OK(rta, rtalen) )
		{
			switch (rta->rta_type)
			{
			case RTA_GATEWAY:
				gw = *(struct in_addr *) RTA_DATA(rta);
				break;
			case RTA_OIF:
				iface_idx = *(int *) RTA_DATA(rta);
				break;
			case RTA_PRIORITY:
				metric = *(uint32_t *) RTA_DATA(rta);
				break;
			}
			rta = RTA_NEXT(rta, rtalen);
		}

		if (metric < best_metric
		&&  iface_idx != -1)
		{
			struct ifreq req;

			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd < 0)
			{
				plog("could not open AF_INET socket");
				break;
			}
			bzero(&req, sizeof(req));
			req.ifr_ifindex = iface_idx;
			if (ioctl(fd, SIOCGIFNAME, &req) < 0 ||
				ioctl(fd, SIOCGIFADDR, &req) < 0)
			{
				plog("could not read interface data, ignoring route");
				close(fd);
				break;
			}

			strncpy(defaultroute->iface, req.ifr_name, IFNAMSIZ);
			defaultroute->addr.u.v4 = *((struct sockaddr_in *) &req.ifr_addr);
			defaultroute->nexthop.u.v4.sin_family = AF_INET;

			if (gw.s_addr == INADDR_ANY)
			{
				if (ioctl(fd, SIOCGIFDSTADDR, &req) < 0 ||
					((struct sockaddr_in*) &req.ifr_dstaddr)->sin_addr.s_addr == INADDR_ANY)
				{
					DBG_log("Ignoring default route to device %s because we can't get it's destination",
							req.ifr_name);
					close(fd);
					break;
				}

				defaultroute->nexthop.u.v4 = *((struct sockaddr_in *) &req.ifr_dstaddr);
			}
			else
				defaultroute->nexthop.u.v4.sin_addr = gw;

			close(fd);

			DBG(DBG_CONTROL,
				char addr[20];
				char nexthop[20];
				addrtot(&defaultroute->addr, 0, addr, sizeof(addr));
				addrtot(&defaultroute->nexthop, 0, nexthop, sizeof(nexthop));

				DBG_log(
					( !defaultroute->defined
					? "Default route found: iface=%s, addr=%s, nexthop=%s"
					: "Better default route: iface=%s, addr=%s, nexthop=%s"
					), defaultroute->iface, addr, nexthop
				)
			);

			best_metric = metric;
			defaultroute->defined = TRUE;
		}
	}
	defaultroute->supported = TRUE;

	if (!defaultroute->defined)
		plog("no default route - cannot cope with %%defaultroute!!!");
}

#else /* !START_PLUTO */

/**
 * Pluto disabled, fall back to %any
 */
void
get_defaultroute(defaultroute_t *defaultroute)
{
	defaultroute->supported = FALSE;
}
#endif /* START_PLUTO */

