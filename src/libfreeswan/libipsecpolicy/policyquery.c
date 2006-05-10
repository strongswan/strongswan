/* routines that interface with pluto to get policy information
 * Copyright (C) 2003       Michael Richardson <mcr@freeswan.org>
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
 * RCSID $Id: policyquery.c,v 1.1 2004/03/15 20:35:25 as Exp $
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>
#include <freeswan/ipsec_policy.h>

#include "libipsecpolicy.h"

static int policy_query_socket = -1;
static u_int32_t policy_seq = 1;

u_int32_t ipsec_policy_seq(void)
{
  return ++policy_seq;
}

err_t ipsec_policy_init(void)
{
  struct sockaddr_un sn;

  if(policy_query_socket != -1) {
    return NULL;
  }

  policy_query_socket = socket(PF_UNIX, SOCK_STREAM, 0);
  if(policy_query_socket == -1) {
    return "failed to open policy socket";
  }

  /* now connect it */
  sn.sun_family = AF_UNIX;
  strcpy(sn.sun_path, IPSEC_POLICY_SOCKET);
  
  if(connect(policy_query_socket, (struct sockaddr *)&sn, sizeof(sn)) != 0) {
    int saveerrno = errno;
    close(policy_query_socket);
    policy_query_socket=-1;
    errno = saveerrno;
    return "failed to connect policy socket";
  }

  /* okay, I think we are done */
  return NULL;
}

err_t ipsec_policy_final(void)
{
  if(policy_query_socket != -1) {
    close(policy_query_socket);
    policy_query_socket = -1;
  }
  
  return NULL;
}

err_t ipsec_policy_readmsg(int policysock,
			   unsigned char *buf,
			   size_t buflen)
{
  struct ipsec_policy_msg_head ipmh;

  if(read(policysock, &ipmh, sizeof(ipmh))
     != sizeof(ipmh)) {
    return "read failed";
  }

  /* got the header, sanitize it, and find out how much more to read */
  switch(ipmh.ipm_version) {
  case IPSEC_POLICY_MSG_REVISION:
    break;
    
  default:
    /* XXX go deal with older versions, error for now */
    fprintf(stderr, "Bad magic header: %u\n", ipmh.ipm_version);
    return "bad policy msg version magic";
  }

  if(ipmh.ipm_msg_len > buflen) {
    return "buffer too small for this message";
  }

  buflen = ipmh.ipm_msg_len;
  memcpy(buf, &ipmh, sizeof(ipmh));
  buf += sizeof(ipmh);
  buflen -= sizeof(ipmh);

  if(read(policysock, buf, buflen) != buflen) {
    return "short read from socket";
  }
  
  return NULL;
}

err_t ipsec_policy_sendrecv(unsigned char *buf,
			    size_t buflen)
{
  err_t ret;
  ipsec_policy_init();

  if(write(policy_query_socket, buf, buflen)
     != buflen) {
    return "write failed";
  }

  ret = ipsec_policy_readmsg(policy_query_socket,
			     buf, buflen);
  
  ipsec_policy_final();
  
  return ret;
}


err_t ipsec_policy_lookup(int fd, struct ipsec_policy_cmd_query *result)
{
  int len;

  /* clear it out */
  memset(result, 0, sizeof(*result));

  /* setup it up */
  result->head.ipm_version = IPSEC_POLICY_MSG_REVISION;
  result->head.ipm_msg_len = sizeof(*result);
  result->head.ipm_msg_type = IPSEC_CMD_QUERY_HOSTPAIR;
  result->head.ipm_msg_seq = ipsec_policy_seq();
  
  /* suck out the data on the sockets */
  len = sizeof(result->query_local);
  if(getsockname(fd, (struct sockaddr *)&result->query_local, &len) != 0) {
    return "getsockname failed";
  }

  len = sizeof(result->query_remote);
  if(getpeername(fd, (struct sockaddr *)&result->query_remote, &len) != 0) {
    return "getpeername failed";
  }

  return ipsec_policy_sendrecv((unsigned char *)result, sizeof(*result));
}

