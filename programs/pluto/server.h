/* get-next-event loop
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: server.h,v 1.2 2004/03/22 21:53:20 as Exp $
 */

extern int ctl_fd;	/* file descriptor of control (whack) socket */
extern struct sockaddr_un ctl_addr;	/* address of control (whack) socket */

extern int info_fd;	/* file descriptor of control (info) socket */
extern struct sockaddr_un info_addr;	/* address of control (info) socket */

extern err_t init_ctl_socket(void);
extern void delete_ctl_socket(void);

extern bool listening;	/* should we pay attention to IKE messages? */


/* interface: a terminal point for IKE traffic, IPsec transport mode
 * and IPsec tunnels.
 * Essentially:
 * - an IP device (eg. eth1), and
 * - its partner, an ipsec device (eg. ipsec0), and
 * - their shared IP address (eg. 10.7.3.2)
 * Note: the port for IKE is always implicitly UDP/pluto_port.
 */
struct iface {
    char *vname;	/* virtual (ipsec) device name */
    char *rname;	/* real device name */
    ip_address addr;	/* interface IP address */
    int fd;	/* file descriptor of socket for IKE UDP messages */
    struct iface *next;
#ifdef NAT_TRAVERSAL
    bool ike_float;
#endif
    enum { IFN_ADD, IFN_KEEP, IFN_DELETE } change;
};

extern struct iface *interfaces;	/* public interfaces */

extern bool use_interface(const char *rifn);
extern void find_ifaces(void);
extern void show_ifaces_status(void);
extern void free_ifaces(void);
extern void show_debug_status(void);
extern void call_server(void);

/* in rcv_info.c */
extern err_t init_info_socket(void);
extern void delete_info_socket(void);
