/*
 * DNS KEY lookup helper - command implementation
 * Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h> 

#include <freeswan.h>

#include <errno.h>
#include <arpa/nameser.h>
#include <lwres/netdb.h>
#include <time.h>

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/types.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/buffer.h>
#include <isc/region.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <lwres/netdb.h>
#include <lwres/async.h>


#include "lwdnsq.h"

static void cmd_not_implemented(dnskey_glob *gs, const char *what)
{
  fprintf(gs->cmdproto_out, "0 FATAL unimplemented command \"%s\"\n", what);
}

void output_transaction_line(dnskey_glob *gs,
			    char *id,
			    int ttl,
			    char *cmd,
			    char *data)
{
	time_t t;

	t=time(NULL);
	
	/* regularlize time for regression testing */
	if(gs->regress) {
		t=3145915;
	}

	if(data) {
		fprintf(gs->cmdproto_out,
			"%s %ld %d %s %s\n",
			id, t, ttl, cmd, data);
	} else {
		fprintf(gs->cmdproto_out,
			"%s %ld %d %s\n",
			id, t, ttl, cmd);
	}
		
}
	
void output_transaction_line_limited(dnskey_glob *gs,
				   char *id,
				   int ttl,
				   char *cmd,
				   int   max,
				   char *data)
{
	time_t t;

	t=time(NULL);
	
	/* regularlize time for regression testing */
	if(gs->regress) {
		t=3145915;
	}

	fprintf(gs->cmdproto_out,
			"%s %ld %d %s %.*s\n",
			id, t, ttl, cmd, max, data);
}
	
			    
#if 0
again:

	lwres_getrrsetbyname_xmit(ctx, &las);
	timeout.tv_sec = lwres_async_timeout(ctx);
	sock = lwres_async_fd(ctx);

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	ret2 = select(sock + 1, &readfds, NULL, NULL, &timeout);
	
	/*
	 * What happened with select?
	 */
	if (ret2 < 0) {
		success = LWRES_R_IOERROR;
		goto out3;
	}
	if (ret2 == 0) {
		success = LWRES_R_TIMEOUT;
		goto out3;
	}

 out:
	if (ctx != NULL)
		lwres_context_destroy(&ctx);

 out2:	

#endif
	

void lookup_key(dnskey_glob *gs,
		int    argc,
		char **argv)
{
	char *id;
	char *fqdn;
	char simplebuf[80];

	/* process arguments */
	/* KEY 31459 east.uml.freeswan.org */
	if(argc!=3) {
		snprintf(simplebuf, sizeof(simplebuf), "wrong number of arguments %d", argc);
		output_transaction_line(gs, "0", 0, "FATAL", simplebuf);
		return;
	}

	id=argv[1];
	fqdn=argv[2];
	
	lookup_thing(gs, dns_rdatatype_key, "KEY", id, fqdn);
}

void lookup_key4(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "key4");
}

void lookup_key6(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "key6");
}


void lookup_txt(dnskey_glob *gs,
		int    argc,
		char **argv)
{
	char *id;
	char *fqdn;
	char simplebuf[80];

	/* process arguments */
	/* KEY 31459 east.uml.freeswan.org */
	if(argc != 3) {
		snprintf(simplebuf, sizeof(simplebuf), "wrong number of arguments to TXT: %d", argc);
		output_transaction_line(gs, "0", 0, "FATAL", simplebuf);
		return;
	}

	id=argv[1];
	fqdn=argv[2];

	lookup_thing(gs, dns_rdatatype_txt, "TXT", id, fqdn);
}

void lookup_txt4(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
	char *id;
	char *ipv4;
	struct in_addr in4;
	char simplebuf[80];

	/* process arguments */
	/* KEY 31459 east.uml.freeswan.org */
	if(argc != 3) {
		snprintf(simplebuf, sizeof(simplebuf), "wrong number of arguments to TXT: %d", argc);
		output_transaction_line(gs, "0", 0, "FATAL", simplebuf);
		return;
	}

	id=argv[1];
	ipv4=argv[2];

	if(inet_pton(AF_INET, ipv4, &in4) <= 0) {
		snprintf(simplebuf, sizeof(simplebuf), "invalid IPv4 address: %s", ipv4);
		output_transaction_line(gs, "0", 0, "FATAL", simplebuf);
		return;
	}
		
	snprintf(simplebuf, 80, "%d.%d.%d.%d.in-addr.arpa",
		 in4.s_addr & 0xff,
		 (in4.s_addr & 0xff00) >> 8,
		 (in4.s_addr & 0xff0000) >> 16,
		 (in4.s_addr & 0xff000000) >> 24);

	lookup_thing(gs, dns_rdatatype_txt, "TXT4", id, simplebuf);
}

void lookup_txt6(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "txt6");
}

void lookup_ipseckey(dnskey_glob *gs,
		int    argc,
		char **argv)
{
  cmd_not_implemented(gs, "ipseckey");
}

void lookup_ipseckey4(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "ipseckey4");
}

void lookup_ipseckey6(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "ipseckey6");
}

void lookup_oe4(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "oe4");
}

void lookup_oe6(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "oe6");
}

void lookup_a(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "a");
}

void lookup_aaaa(dnskey_glob *gs,
		 int    argc,
		 char **argv)
{
  cmd_not_implemented(gs, "aaaa");
}





	
/*
 * $Log: cmds.c,v $
 * Revision 1.1  2004/03/15 20:35:28  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.11  2003/09/03 01:13:24  mcr
 * 	first attempt at async capable lwdnsq.
 *
 * Revision 1.10  2003/05/22 16:33:51  mcr
 * 	added trailing . to CNAME return and cleaned up "CNAMEFROM" output.
 *
 * Revision 1.9  2003/05/14 15:47:39  mcr
 * 	processing of IP address into pieces was not done with
 * 	the right order of operations.
 *
 * Revision 1.8  2003/02/27 09:27:17  mcr
 * 	adjusted lwdnsq so that it adheres to contract - TXT records
 * 	are returned in a single piece. Requires custom decoding.
 * 	implemented "txt4" lookup type.
 *
 * Revision 1.7  2003/01/14 07:53:29  dhr
 *
 * - attempt to diagnose lack of lwdnsq
 * - increase too-small buffer size
 *
 * Revision 1.6  2003/01/14 03:01:14  dhr
 *
 * improve diagnostics; tidy
 *
 * Revision 1.5  2002/12/12 06:03:41  mcr
 * 	added --regress option to force times to be regular
 *
 * Revision 1.4  2002/11/25 18:37:28  mcr
 * 	added AD- marking of each record that was DNSSEC verified.
 *
 * Revision 1.3  2002/11/16 02:53:53  mcr
 * 	lwdnsq - with new contract added.
 *
 * Revision 1.2  2002/11/12 04:33:44  mcr
 * 	print DNSSEC status as we process CNAMEs.
 *
 * Revision 1.1  2002/10/30 02:25:31  mcr
 * 	renamed version of files from dnskey/
 *
 * Revision 1.4  2002/10/18 23:11:02  mcr
 * 	if we get ENOENT, then see if we can get a CNAME. If so, then
 * 	follow it.
 * 	Be careful when following them to avoid recursion.
 *
 * Revision 1.3  2002/10/18 04:08:47  mcr
 * 	use -ldns routines to decode lwres results and format them nicely.
 *
 * Revision 1.2  2002/10/09 20:13:34  mcr
 * 	first set of real code - lookup KEY records in forward.
 *
 * Revision 1.1  2002/09/30 18:55:54  mcr
 * 	skeleton for dnskey helper program.
 *
 * Revision 1.1  2002/09/30 16:50:23  mcr
 * 	documentation for "dnskey" helper
 *
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 2
 * End:
 *
 */
