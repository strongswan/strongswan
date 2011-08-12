/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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

#include <errno.h>
#include <unistd.h>

#ifndef HOST_NAME_MAX        /* POSIX 1003.1-2001 says <unistd.h> defines this */
# define HOST_NAME_MAX  255 /* upper bound, according to SUSv2 */
#endif

#include <utils/identification.h>

#include <freeswan.h>

#include "myid.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "connections.h"
#include "packet.h"
#include "whack.h"

enum myid_state myid_state = MYID_UNKNOWN;

identification_t *myids[MYID_SPECIFIED+1];    /* %myid */

/**
 * Fills in myid from environment variable IPSECmyid or defaultrouteaddr
 */
void init_myid(void)
{
	myid_state = MYID_UNKNOWN;
	{
		enum myid_state s;

		for (s = MYID_UNKNOWN; s <= MYID_SPECIFIED; s++)
		{
			myids[s] = identification_create_from_string("%any");
		}
	}
	set_myid(MYID_SPECIFIED, getenv("IPSECmyid"));
	set_myid(MYID_IP, getenv("defaultrouteaddr"));
	set_myFQDN();
}

/**
 *  Free myid module
 */
void free_myid(void)
{
	enum myid_state s;

	for (s = MYID_UNKNOWN; s <= MYID_SPECIFIED; s++)
	{
		DESTROY_IF(myids[s]);
	}
}

void set_myid(enum myid_state s, char *idstr)
{
	if (idstr)
	{
		myids[s]->destroy(myids[s]);
		myids[s] = identification_create_from_string(idstr);
		if (s == MYID_SPECIFIED)
		{
				myid_state = MYID_SPECIFIED;
		}
	}
}

void set_myFQDN(void)
{
	char FQDN[HOST_NAME_MAX + 1];
	int r = gethostname(FQDN, sizeof(FQDN));
	size_t len;

	if (r != 0)
	{
		log_errno((e, "gethostname() failed in set_myFQDN"));
	}
	else
	{
		FQDN[sizeof(FQDN) - 1] = '\0';  /* insurance */
		len = strlen(FQDN);

		if (len > 0 && FQDN[len-1] == '.')
		{
			/* nuke trailing . */
			FQDN[len-1] = '\0';
		}
		if (!strcaseeq(FQDN, "localhost.localdomain"))
		{
			myids[MYID_HOSTNAME]->destroy(myids[MYID_HOSTNAME]);
			myids[MYID_HOSTNAME] = identification_create_from_string(FQDN);
		}
	}
}

void show_myid_status(void)
{
	whack_log(RC_COMMENT, "%%myid = '%Y'", myids[myid_state]);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
