/*
 * A program to dump the IPsec status of the socket found on stdin.
 * Run me from inetd, for instance.
 * Copyright (C) 2003                Michael Richardson <mcr@freeswan.org>
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

char showpolicy_version[] = "RCSID $Id: showpolicy.c,v 1.1 2004/03/15 20:35:31 as Exp $";

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <getopt.h>
#include "freeswan.h"
#include "freeswan/ipsec_policy.h"

char *program_name;

static void
help(void)
{
    fprintf(stderr,
	"Usage:\n\n"
	"showpolicy"
	    " [--cgi]        lookup the particulars from CGI variables.\n"
	    " [--socket]     lookup the particulars from the socket on stdin.\n"
	    " [--textual]    dump output in human friendly form\n"
	    " [--plaintext X]    string to dump if no security\n"
	    " [--vpntext X]      string to dump if VPN configured tunnel\n"
	    " [--privacytext X]  string to dump if just plain DNS OE\n"
	    " [--dnssectext X]   string to dump if just DNSSEC OE\n"
            "\n\n"
	"FreeS/WAN %s\n",
	ipsec_version_code());
}

static const struct option long_opts[] = {
    /* name, has_arg, flag, val */
    { "help",        no_argument, NULL, 'h' },
    { "version",     no_argument, NULL, 'V' },
    { "socket",      no_argument, NULL, 'i' },
    { "cgi",         no_argument, NULL, 'g' },
    { "textual",     no_argument, NULL, 't' },
    { "plaintext",   required_argument, NULL, 'c' },
    { "vpntext",     required_argument, NULL, 'v' },
    { "privacytext", required_argument, NULL, 'p' },
    { "dnssectext",  required_argument, NULL, 's' },
    { 0,0,0,0 }
};

void dump_policyreply(struct ipsec_policy_cmd_query *q)
{
  char src[ADDRTOT_BUF], dst[ADDRTOT_BUF];

  /* now print it! */
  addrtot(&q->query_local,  0, src, sizeof(src));
  addrtot(&q->query_remote, 0, dst, sizeof(dst));
  
  printf("Results of query on %s -> %s with seq %d\n",
	 src, dst, q->head.ipm_msg_seq);
  
  printf("Received reply of %d bytes.\n", q->head.ipm_msg_len);

  printf("Strength:   %d\n", q->strength);
  printf("Bandwidth:  %d\n", q->bandwidth);
  printf("authdetail: %d\n", q->auth_detail);
  printf("esp_detail: %d\n", q->esp_detail);
  printf("comp_detail: %d\n",q->comp_detail);
  
  printf("credentials: %d\n", q->credential_count);
  if(q->credential_count > 0) {
    int c;

    for(c=0; c<q->credential_count; c++) {
      switch(q->credentials[c].ii_format) {
      case CERT_DNS_SIGNED_KEY:
	printf("\tDNSSEC identity: %s (SIG %s)\n",
	       q->credentials[c].ii_credential.ipsec_dns_signed.fqdn,
	       q->credentials[c].ii_credential.ipsec_dns_signed.dns_sig);
	break;
	
      case CERT_RAW_RSA:
	printf("\tlocal identity: %s\n",
	       q->credentials[c].ii_credential.ipsec_raw_key.id_name);

      case CERT_NONE:
	printf("\tDNS identity: %s\n",
	       q->credentials[c].ii_credential.ipsec_dns_signed.fqdn);
	break;
	
      default:
	printf("\tUnknown identity type %d", q->credentials[c].ii_format);
	break;
      }
    }
  }
}


int main(int argc, char *argv[])
{
  struct ipsec_policy_cmd_query q;
  err_t ret;
  int   c;

  /* set the defaults */
  char lookup_style = 'i';
  char output_style = 's';
  
  char *plaintext   = "clear";
  char *vpntext     = "vpn";
  char *privacytext = "private";
  char *dnssectext  = "secure";

  while((c = getopt_long(argc, argv, "hVighc:v:p:s:", long_opts, 0))!=EOF) {
    switch (c) {
    default:
    case 'h':	        /* --help */
      help();
      return 0;	/* GNU coding standards say to stop here */
      
    case 'V':               /* --version */
      fprintf(stderr, "FreeS/WAN %s\n", ipsec_version_code());
      return 0;	/* GNU coding standards say to stop here */
      
    case 'i':
      if(isatty(0)) {
	printf("please run this connected to a socket\n");
	exit(1);
      }
      
      lookup_style = 'i';
      break;

    case 'g':
      lookup_style = 'g';
      break;
      
    case 't':
      output_style = 't';
      break;

    case 'c':
      plaintext = optarg;
      break;

    case 'v':
      vpntext = optarg;
      break;

    case 'p':
      privacytext = optarg;
      break;
      
    case 's':
      dnssectext = optarg;
      break;
    }
  }
	
  if((ret = ipsec_policy_init()) != NULL) {
    perror(ret);
    exit(2);
  }

  switch(lookup_style) {
  case 'i':
    if((ret = ipsec_policy_lookup(0, &q)) != NULL) {
      perror(ret);
      exit(3);
    }
    break;
    
  case 'g':
    if((ret = ipsec_policy_cgilookup(&q)) != NULL) {
      perror(ret);
      exit(3);
    }
    break;
    
  default:
    abort();
    break;
  }


  if(output_style == 't') {
    dump_policyreply(&q);
  } else {
    /* start by seeing if there was any crypto */
    if(q.strength < IPSEC_PRIVACY_PRIVATE) {
      /* no, so say clear */
      puts(plaintext);
      exit(0);
    }

    /* we now it is crypto, but authentic is it? */
    if(q.credential_count == 0) {
      puts(vpntext);
      exit(0);
    }

    switch(q.credentials[0].ii_format) {
    case CERT_DNS_SIGNED_KEY:
      puts(dnssectext);
      exit(0);

    case CERT_RAW_RSA:
      puts(vpntext);
      exit(0);
      
    default:
      puts(privacytext);
      exit(0);
    }
  }
  
  exit(0);
}

/*
 * $Log: showpolicy.c,v $
 * Revision 1.1  2004/03/15 20:35:31  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.4  2003/05/14 15:46:44  mcr
 * 	switch statement was missing break statements and was running on.
 *
 * Revision 1.3  2003/05/14 02:12:27  mcr
 * 	addition of CGI-focused interface to policy lookup interface
 *
 * Revision 1.2  2003/05/13 03:25:34  mcr
 * 	print credentials, if any were provided.
 *
 * Revision 1.1  2003/05/11 00:45:08  mcr
 * 	program to interogate ipsec policy of stdin.
 * 	run this from inetd.
 *
 *
 *
 */
