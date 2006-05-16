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
 *
 * RCSID $Id: interfaces.c,v 1.15 2006/02/05 10:51:55 as Exp $
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <freeswan.h>
#include <ipsec_tunnel.h>

#include <constants.h>
#include <defs.h>
#include <log.h>

#include "interfaces.h"
#include "exec.h"
#include "files.h"

#define MIN(a,b) ( ((a)>(b)) ? (b) : (a) )

#define N_IPSEC_IF      4

struct st_ipsec_if {
	char name[IFNAMSIZ];
	char phys[IFNAMSIZ];
	int up;
};

static struct st_ipsec_if _ipsec_if[N_IPSEC_IF];

static char *
_find_physical_iface(int sock, char *iface)
{
    static char _if[IFNAMSIZ];
    char *b;
    struct ifreq req;
    FILE *fd;
    char line[BUF_LEN];

    strncpy(req.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req)==0)
    {
	if (req.ifr_flags & IFF_UP)
	{
	    strncpy(_if, iface, IFNAMSIZ);
	    return _if;
	}
    }
    else
    {
	/* If there is a file named /var/run/dynip/<iface>, look if we
	 * can get interface name from there (IP_PHYS)
	 */
	b = (char *)alloc_bytes(strlen(DYNIP_DIR) + strlen(iface) + 10, "iface");
	if (b)
	{
	    sprintf(b, "%s/%s", DYNIP_DIR, iface);
	    fd = fopen(b, "r");
	    pfree(b);
	    if (fd)
	    {
		memset(_if, 0, sizeof(_if));
		memset(line, 0, sizeof(line));
		while (fgets(line, sizeof(line), fd) != 0)
		{
		    if ((strncmp(line,"IP_PHYS=\"", 9) == 0)
		    && (line[strlen(line) - 2] == '"')
		    && (line[strlen(line) - 1] == '\n'))
		    {
			strncpy(_if, line + 9, MIN(strlen(line) - 11, IFNAMSIZ));
			break;
		    }
		    else if ((strncmp(line,"IP_PHYS=", 8) == 0)
		    && (line[8] != '"')
		    && (line[strlen(line) - 1] == '\n'))
		    {
			strncpy(_if, line + 8, MIN(strlen(line) - 9, IFNAMSIZ));
			break;
		    }
		}
		fclose(fd);

		if (*_if)
		{
		    strncpy(req.ifr_name, _if, IFNAMSIZ);
		    if (ioctl(sock, SIOCGIFFLAGS, &req) == 0)
		    {
			if (req.ifr_flags & IFF_UP)
			    return _if;
		    }
		}
	    }
	}
    }
    return NULL;
}

int
starter_iface_find(char *iface, int af, ip_address *dst, ip_address *nh)
{
    char *phys;
    struct ifreq req;
    struct sockaddr_in *sa = (struct sockaddr_in *)(&req.ifr_addr);
    int sock;

    if (!iface)
	return -1;

    sock = socket(af, SOCK_DGRAM, 0);
    if (sock < 0)
	return -1;

    phys = _find_physical_iface(sock, iface);
    if (!phys)
	goto failed;

    strncpy(req.ifr_name, phys, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req)!=0)
	goto failed;
    if (!(req.ifr_flags & IFF_UP))
	 goto failed;

    if ((req.ifr_flags & IFF_POINTOPOINT)
    && nh
    && ioctl(sock, SIOCGIFDSTADDR, &req) == 0)
    {
	if (sa->sin_family == af)
	    initaddr((const void *)&sa->sin_addr, sizeof(struct in_addr), af, nh);
    }
    if ((dst) && (ioctl(sock, SIOCGIFADDR, &req) == 0))
    {
	if (sa->sin_family == af)
	    initaddr((const void *)&sa->sin_addr, sizeof(struct in_addr), af, dst);
    }
    close(sock);
    return 0;

failed:
    close(sock);
    return -1;
}

static int
valid_str(char *str, unsigned int *pn, char **pphys
, defaultroute_t *defaultroute)
{
    if (streq(str, "%defaultroute"))
    {
	if (!defaultroute->defined)
	{
	    return 0;
	}
	*pn = 0;
	*pphys = defaultroute->iface;
    }
    else
    {
	if (strlen(str) < 8 
	|| str[0] != 'i' || str[1] != 'p' || str[2] !='s' || str[3] != 'e'
	|| str[4] != 'c' || str[5] < '0'  || str[5] > '9' || str[6] != '=')
	{
	    return 0;
	}
	*pn = str[5] - '0';
	*pphys = &(str[7]);
    }
    return 1;
}

static int
_iface_up (int sock,  struct st_ipsec_if *iface, char *phys
, unsigned int mtu, bool nat_t)
{
    struct ifreq req;
    struct ipsectunnelconf *shc=(struct ipsectunnelconf *)&req.ifr_data;
    short phys_flags;
    int ret = 0;
    /* sscholz@astaro.com: for network mask 32 bit
    struct sockaddr_in *inp;
    */

    strncpy(req.ifr_name, phys, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req) !=0 )
	return ret;
    phys_flags = req.ifr_flags;

    strncpy(req.ifr_name, iface->name, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req) != 0)
	return ret;

    if ((!(req.ifr_flags & IFF_UP)) || (!iface->up))
    {
	DBG(DBG_CONTROL,
	    DBG_log("attaching interface %s to %s", iface->name, phys)
	)
	ret = 1;
    }

    if ((*iface->phys) && (strcmp(iface->phys, phys) != 0 ))
    {
	/* tncfg --detach if phys has changed */
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	ioctl(sock, IPSEC_DEL_DEV, &req);
	ret = 1;
    }

    /* tncfg --attach */
    strncpy(req.ifr_name, iface->name, IFNAMSIZ);
    strncpy(shc->cf_name, phys, sizeof(shc->cf_name));
    ioctl(sock, IPSEC_SET_DEV, &req);

    /* set ipsec addr = phys addr */
    strncpy(req.ifr_name, phys, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFADDR, &req) == 0)
    {
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	ioctl(sock, SIOCSIFADDR, &req);
    }

    /* set ipsec mask = phys mask */
    strncpy(req.ifr_name, phys, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFNETMASK, &req) == 0)
    {
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	/* sscholz@astaro.com: changed netmask to 32 bit
	 * in order to prevent network routes from being created

	inp = (struct sockaddr_in *)&req.ifr_addr;
	inp->sin_addr.s_addr = 0xFFFFFFFFL;

         */
	ioctl(sock, SIOCSIFNETMASK, &req);
    }

    /* set other flags & addr */
    strncpy(req.ifr_name, iface->name, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req)==0)
    {
/* removed by sscholz@astaro.com (caused trouble with DSL/ppp0) */
/*	if (phys_flags & IFF_POINTOPOINT)
	{
	    req.ifr_flags |= IFF_POINTOPOINT;
	    req.ifr_flags &= ~IFF_BROADCAST;
	    ioctl(sock, SIOCSIFFLAGS, &req);
	    strncpy(req.ifr_name, phys, IFNAMSIZ);
	    if (ioctl(sock, SIOCGIFDSTADDR, &req) == 0)
	    {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ);
		ioctl(sock, SIOCSIFDSTADDR, &req);
	    }
	}
	else
 */
	if (phys_flags & IFF_BROADCAST)
	{
	    req.ifr_flags &= ~IFF_POINTOPOINT;
	    req.ifr_flags |= IFF_BROADCAST;
	    ioctl(sock, SIOCSIFFLAGS, &req);
	    strncpy(req.ifr_name, phys, IFNAMSIZ);
	    if (ioctl(sock, SIOCGIFBRDADDR, &req) == 0)
	    {
		strncpy(req.ifr_name, iface->name, IFNAMSIZ);
		ioctl(sock, SIOCSIFBRDADDR, &req);
	    }
	}
	else
	{
	    req.ifr_flags &= ~IFF_POINTOPOINT;
	    req.ifr_flags &= ~IFF_BROADCAST;
	    ioctl(sock, SIOCSIFFLAGS, &req);
	}
    }

    /*
     * guess MTU = phys interface MTU - ESP Overhead
     *
     * ESP overhead : 10+16+7+2+12=57 -> 60 by security
     * NAT-T overhead : 20
     */
    if (mtu == 0)
    {
	strncpy(req.ifr_name, phys, IFNAMSIZ);
	ioctl(sock, SIOCGIFMTU, &req);
	mtu = req.ifr_mtu - 60;
	if (nat_t)
	    mtu -= 20;
    }
    /* set MTU */
    if (mtu)
    {
	strncpy(req.ifr_name, iface->name, IFNAMSIZ);
	req.ifr_mtu = mtu;
	ioctl(sock, SIOCSIFMTU, &req);
    }

    /* ipsec interface UP */
    strncpy(req.ifr_name, iface->name, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req) == 0)
    {
	req.ifr_flags |= IFF_UP;
	ioctl(sock, SIOCSIFFLAGS, &req);
    }

    iface->up = 1;
    strncpy(iface->phys, phys, IFNAMSIZ);
    return ret;
}

static int
_iface_down(int sock, struct st_ipsec_if *iface)
{
    struct ifreq req;
    int ret = 0;

    iface->up = 0;

    strncpy(req.ifr_name, iface->name, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &req)!=0)
	return ret;

    if (req.ifr_flags & IFF_UP)
    {
	DBG(DBG_CONTROL,
	    DBG_log("shutting down interface %s/%s", iface->name, iface->phys)
	)
	req.ifr_flags &= ~IFF_UP;
	ioctl(sock, SIOCSIFFLAGS, &req);
	ret = 1;
    }

    /* unset addr */
    memset(&req.ifr_addr, 0, sizeof(req.ifr_addr));
    req.ifr_addr.sa_family = AF_INET;
    ioctl(sock, SIOCSIFADDR, &req);

    /* tncfg --detach */
    ioctl(sock, IPSEC_DEL_DEV, &req);

    memset(iface->phys, 0, sizeof(iface->phys));

    return ret;
}

void
starter_ifaces_init(void)
{
    int i;

    memset(_ipsec_if, 0, sizeof(_ipsec_if));
    for (i = 0; i < N_IPSEC_IF; i++)
	snprintf(_ipsec_if[i].name, IFNAMSIZ, "ipsec%d", i);
}

void
starter_ifaces_clear (void)
{
    int sock;
    unsigned int i;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
	return;

    for (i = 0; i < N_IPSEC_IF; i++)
	_iface_down (sock, &(_ipsec_if[i]));
}

int
starter_ifaces_load(char **ifaces, unsigned int omtu, bool nat_t
, defaultroute_t *defaultroute)
{
    char *tmp_phys, *phys;
    int n;
    char **i;
    int sock;
    int j, found;
    int ret = 0;
    struct ifreq physreq, ipsecreq; // re-attach interface
    struct sockaddr_in *inp1, *inp2; // re-attach interface

    DBG(DBG_CONTROL,
	DBG_log("starter_ifaces_load()")
    )

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
	return -1;

    for (j = 0; j < N_IPSEC_IF; j++)
    {
	found = 0;

	for (i = ifaces; i && *i; i++)
	{
	    if (valid_str(*i, &n, &tmp_phys, defaultroute)
	    && tmp_phys
	    && n >= 0
	    && n < N_IPSEC_IF)
	    {
		if (n==j)
		{
		    if (found)
		    {
			plog( "ignoring duplicate entry for interface ipsec%d", j);
		    }
		    else
		    {
			found++;
			phys = _find_physical_iface(sock, tmp_phys);

			/* Re-attach ipsec interface if IP address changes
			 * sscholz@astaro.com
			 */
			if (phys)
			{
			    memset ((void*)&physreq, 0, sizeof(physreq));
			    memset ((void*)&ipsecreq, 0, sizeof(ipsecreq));
			    strncpy(physreq.ifr_name, phys, IFNAMSIZ);
			    sprintf(ipsecreq.ifr_name, "ipsec%d", j);
			    ioctl(sock, SIOCGIFADDR, &physreq);
			    ioctl(sock, SIOCGIFADDR, &ipsecreq);
			    inp1 = (struct sockaddr_in *)&physreq.ifr_addr;
			    inp2 = (struct sockaddr_in *)&ipsecreq.ifr_addr;
			    if (inp1->sin_addr.s_addr != inp2->sin_addr.s_addr)
			    {
				plog("IP address of physical interface changed "
				     "-> reinit of ipsec interface");
				_iface_down (sock, &(_ipsec_if[n]));
			    }
			    ret += _iface_up (sock, &(_ipsec_if[n]), phys, omtu, nat_t);
			}
			else
			{
			    ret += _iface_down (sock, &(_ipsec_if[n]));
			}
		    }
		}
	    }
	    else if (j == 0)
	    {
		/* Only log in the first loop */
		plog("ignoring invalid interface '%s'", *i);
	    }
	}
	if (!found)
	    ret += _iface_down (sock, &(_ipsec_if[j]));
    }

    close(sock);
    return ret; /* = number of changes - 'whack --listen' if > 0 */
}

/*
 * initialize a defaultroute_t struct
 */
static void
init_defaultroute(defaultroute_t *defaultroute)
{
    memset(defaultroute, 0, sizeof(defaultroute_t));
}

/*
 * discover the default route via /proc/net/route
 */
void
get_defaultroute(defaultroute_t *defaultroute)
{
    FILE *fd;
    char line[BUF_LEN];
    bool first = TRUE;

    init_defaultroute(defaultroute);

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
