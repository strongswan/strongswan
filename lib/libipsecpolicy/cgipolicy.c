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
 * RCSID $Id: cgipolicy.c,v 1.1 2004/03/15 20:35:24 as Exp $
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

/*
 * this version is appropriate for when one is called from a perl CGI,
 * running under Apache. It extracts the appropriate things out of standard 
 * CGI environment variables, namely: 
 *   $SERVER_ADDR  us
 *   $REMOTE_ADDR  them
 */

err_t ipsec_policy_cgilookup(struct ipsec_policy_cmd_query *result)
{
  err_t ret;
  char *us, *them;

  /* clear it all out */
  memset(result, 0, sizeof(*result));

  /* setup it up */
  result->head.ipm_version = IPSEC_POLICY_MSG_REVISION;
  result->head.ipm_msg_len = sizeof(*result);
  result->head.ipm_msg_type = IPSEC_CMD_QUERY_HOSTPAIR;
  result->head.ipm_msg_seq = ipsec_policy_seq();


  us   = getenv("SERVER_ADDR");
  them = getenv("REMOTE_ADDR");
  if(!us || !them) {
    return "$SERVER_ADDR and $REMOTE_ADDR must be set";
  }

  ret = ttoaddr(us, 0, AF_INET, &result->query_local);
  if(ret != NULL) {
    return ret;
  }

  ret = ttoaddr(them, 0, AF_INET, &result->query_remote);
  if(ret != NULL) {
    return ret;
  }
  
  return ipsec_policy_sendrecv((unsigned char *)result, sizeof(*result));
}

