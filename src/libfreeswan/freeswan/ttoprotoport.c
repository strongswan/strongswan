/*
 * conversion from protocol/port string to protocol and port
 * Copyright (C) 2002 Mario Strasser <mast@gmx.net>,
 *                    Zuercher Hochschule Winterthur,
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
 * RCSID $Id: ttoprotoport.c,v 1.1 2004/03/15 20:35:26 as Exp $
 */

#include "internal.h"
#include "freeswan.h"

/*
 * ttoprotoport - converts from protocol/port string to protocol and port
 */
err_t
ttoprotoport(src, src_len, proto, port, has_port_wildcard)
char *src;		/* input string */
size_t src_len;		/* length of input string, use strlen() if 0 */
u_int8_t *proto;	/* extracted protocol number */
u_int16_t *port;	/* extracted port number if it exists */
int *has_port_wildcard;	/* set if port is %any */
{
    char *end, *service_name;
    char proto_name[16];
    int proto_len;
    long int l;
    struct protoent *protocol;
    struct servent *service;

    /* get the length of the string */
    if (!src_len) src_len = strlen(src);

    /* locate delimiter '/' between protocol and port */
    end = strchr(src, '/');
    if (end != NULL) {
      proto_len = end - src;
      service_name = end + 1;
    } else {
      proto_len = src_len;
      service_name = src + src_len;
    }

   /* copy protocol name*/
    memset(proto_name, '\0', sizeof(proto_name));
    memcpy(proto_name, src, proto_len);

    /* extract protocol by trying to resolve it by name */
    protocol = getprotobyname(proto_name);
    if (protocol != NULL) {
	*proto = protocol->p_proto;
    }
    else  /* failed, now try it by number */
    {
	l = strtol(proto_name, &end, 0);

	if (*proto_name && *end)
	    return "<protocol> is neither a number nor a valid name";

	if (l < 0 || l > 0xff)
            return "<protocol> must be between 0 and 255";

	*proto = (u_int8_t)l;
    }

    /* is there a port wildcard? */
    *has_port_wildcard = (strcmp(service_name, "%any") == 0);
   
    if (*has_port_wildcard)
    {
	*port = 0;
	return NULL;
    }

    /* extract port by trying to resolve it by name */
    service = getservbyname(service_name, NULL);
    if (service != NULL) {
        *port = ntohs(service->s_port);
    }
    else /* failed, now try it by number */
    {
	l = strtol(service_name, &end, 0);

	if (*service_name && *end)
	    return "<port> is neither a number nor a valid name";

	if (l < 0 || l > 0xffff)
	    return "<port> must be between 0 and 65535";

	*port = (u_int16_t)l;
    }
    return NULL;
}

