/* interface to fake kernel interface, used for testing pluto in-vitro.
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2003 Herbert Xu.
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
 * RCSID $Id$
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <freeswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "constants.h"
#include "defs.h"
#include "kernel.h"
#include "kernel_noklips.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

void
init_noklips(void)
{
  return;
}

/* asynchronous messages from our queue */
static void
noklips_dequeue(void)
{
}

/* asynchronous messages directly from PF_KEY socket */
static void
noklips_event(void)
{
}

static void
noklips_register_response(const struct sadb_msg *msg UNUSED)
{
}

static void
noklips_register(void)
{
}

static bool
noklips_raw_eroute(const ip_address *this_host UNUSED
				   , const ip_subnet *this_client UNUSED
				   , const ip_address *that_host UNUSED
				   , const ip_subnet *that_client UNUSED
				   , ipsec_spi_t spi UNUSED
				   , unsigned int satype UNUSED
				   , unsigned int transport_proto UNUSED
				   , const struct pfkey_proto_info *proto_info UNUSED
				   , time_t use_lifetime UNUSED
				   , unsigned int op UNUSED
				   , const char *text_said UNUSED)
{
  return TRUE;
}

static bool
noklips_add_sa(const struct kernel_sa *sa UNUSED
			   , bool replace UNUSED)
{
  return TRUE;
}

static bool
noklips_grp_sa(const struct kernel_sa *sa0 UNUSED
			   , const struct kernel_sa *sa1 UNUSED)
{
  return TRUE;
}

static bool
noklips_del_sa(const struct kernel_sa *sa UNUSED)
{
  return TRUE;
}


const struct kernel_ops noklips_kernel_ops = {
		type: KERNEL_TYPE_NONE,
		async_fdp: NULL,
		
		init: init_noklips,
		pfkey_register: noklips_register,
		pfkey_register_response: noklips_register_response,
		process_queue: noklips_dequeue,
		process_msg: noklips_event,
		raw_eroute: noklips_raw_eroute,
		add_sa: noklips_add_sa,
		grp_sa: noklips_grp_sa,
		del_sa: noklips_del_sa,
		get_sa: NULL,
		get_spi: NULL,
		inbound_eroute: FALSE,
		policy_lifetime: FALSE
};
