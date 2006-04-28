/* send out an IKE "ping" packet.
 * Copyright (C) 2002 Michael Richardson
 * Copyright (C) 2002 D. Hugh Redelmeier.
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
 * RCSID $Id: ikeping.c,v 1.1 2004/03/15 20:35:27 as Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>
#include <poll.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/packet.h"

#ifndef ISAKMP_XCHG_ECHOREQUEST
#define ISAKMP_XCHG_ECHOREQUEST 30      /* Echo Request */
#define ISAKMP_XCHG_ECHOREPLY   31      /* Echo Reply   */
#endif

#ifndef ISAKMP_XCGH_ECHOREQUEST_PRIV
#define ISAKMP_XCHG_ECHOREQUEST_PRIV 244     /* Private Echo Request */
#define ISAKMP_XCHG_ECHOREPLY_PRIV   245     /* Private Echo Reply   */
#endif


/* what exchange number to use for outgoing requests */
static int exchange_number;

static void
help(void)
{
    fprintf(stderr,
	"Usage:\n\n"
	"ikeping"
	    " [--listen]     causes IKEping to open a socket and reply to requests.\n"
	    " [--verbose]    causes IKEping to hexdump all packets sent/received.\n"
	    " [--ikeport <port-number>]      port to listen on/send from\n"
	    " [--ikeaddress <address>]       address to listen on/send from\n"
	    " [--inet]       just send/listen on IPv4 socket\n"
	    " [--inet6]      just send/listen on IPv6 socket\n"
	    " [--version]    just dump version number and exit\n"
	    " [--exchangenum num]    use num instead of 244 for the exchange type.\n"
	    " [--wait seconds]    time to wait for replies, defaults to 10 seconds.\n"
	    " host/port ...\n\n"
	"FreeS/WAN %s\n",
	ipsec_version_code());
}

static void
hton_ping(struct isakmp_hdr *ih)
{
	u_int32_t *ihp;

	ihp=(u_int32_t *)ih;

	/* put it in network byte order. */
	/* cookies are byte viewed anyway */
	ihp[4]=htonl(ihp[4]);
	ih->isa_msgid  = htonl(ih->isa_msgid);
	ih->isa_length = htonl(ih->isa_length);
}

static void
ntoh_ping(struct isakmp_hdr *ih)
{
	u_int32_t *ihp;

	ihp=(u_int32_t *)ih;

	/* put it in network byte order. */
	/* cookies are byte viewed anyway */
	ihp[4]=ntohl(ihp[4]);
	ih->isa_msgid  = ntohl(ih->isa_msgid);
	ih->isa_length = ntohl(ih->isa_length);
}


/*
 * send an IKE ping
 *
 */
static void
send_ping(int afamily,
	  int s,
	  ip_address *raddr,
	  int rport)
{
	struct isakmp_hdr ih;
	int i, raddrlen;

	raddrlen=0;

	for(i=0; i<COOKIE_SIZE; i++) {
		ih.isa_icookie[i]=rand()&0xff;		
	}
	     
	for(i=0; i<COOKIE_SIZE; i++) {
		ih.isa_rcookie[i]=rand()&0xff;		
	}
	     
	ih.isa_np    = NOTHING_WRONG;
	ih.isa_version = (1 << ISA_MAJ_SHIFT) | 0;
	ih.isa_xchg  = (exchange_number ?
			exchange_number : ISAKMP_XCHG_ECHOREQUEST_PRIV);
	ih.isa_flags =0;
	ih.isa_msgid =rand();
	ih.isa_length=0;

	switch(afamily) {
	case AF_INET:
		raddr->u.v4.sin_port = htons(rport);
		raddrlen=sizeof(raddr->u.v4);
		break;
	  
	case AF_INET6:
		raddr->u.v6.sin6_port = htons(rport);
		raddrlen=sizeof(raddr->u.v6);
		break;
	}

	hton_ping(&ih);

	if(sendto(s, &ih, sizeof(ih), 0, (struct sockaddr *)raddr, raddrlen) < 0) {
		perror("sendto");
		exit(5);
	}
}

/*
 * send an IKE ping
 *
 */
static void
reply_packet(int afamily,
	     int s,
	     ip_address *dst_addr,
	     int         dst_len,
	     struct isakmp_hdr *op)
{
	int i, tmp;

	tmp=afamily;  /* shut up compiler */

	for(i=0; i<COOKIE_SIZE; i++) {
		tmp=op->isa_icookie[i];
		op->isa_icookie[i]=op->isa_rcookie[i];
		op->isa_rcookie[i]=tmp;
	}
	     
	op->isa_np    = NOTHING_WRONG;
	op->isa_version = (1 << ISA_MAJ_SHIFT) | 0;
	op->isa_xchg  = ISAKMP_XCHG_ECHOREPLY;
	op->isa_flags =0;
	op->isa_msgid =rand();
	op->isa_length=0;

	hton_ping(op);

	if(sendto(s, op, sizeof(*op), 0, (struct sockaddr *)dst_addr, dst_len) < 0) {
		perror("sendto");
		exit(5);
	}
}

/*
 * receive and decode packet.
 *
 */
static void
receive_ping(int afamily, int s, int reply)
{
	ip_address sender;
	struct isakmp_hdr ih;
	char   buf[64];
	int n, rport, sendlen;
	const char *xchg_name;
	int xchg;

	rport = 500;
	xchg  = 0;
	sendlen=sizeof(sender);
	n = recvfrom(s, &ih, sizeof(ih), 0, (struct sockaddr *)&sender, &sendlen);

	addrtot(&sender, 0, buf, sizeof(buf));
	switch(afamily) {
	case AF_INET:
		rport = sender.u.v4.sin_port;
		break;
	  
	case AF_INET6:
		rport = sender.u.v6.sin6_port;
		break;
	}

	if((unsigned int)n < sizeof(ih)) {
		fprintf(stderr, "read short packet (%d) from %s/%d\n",
			n, buf, rport);
		return;
	}

	/* translate from network byte order */
	ntoh_ping(&ih);


	if(ih.isa_xchg == ISAKMP_XCHG_ECHOREQUEST       ||
	   ih.isa_xchg == ISAKMP_XCHG_ECHOREQUEST_PRIV  ||
	   (exchange_number!=0 && ih.isa_xchg == exchange_number)) {
		xchg_name="echo-request";
		xchg=ISAKMP_XCHG_ECHOREQUEST;
	} else if(ih.isa_xchg == ISAKMP_XCHG_ECHOREPLY ||
		  ih.isa_xchg == ISAKMP_XCHG_ECHOREPLY_PRIV ||
		  (exchange_number!=0 && ih.isa_xchg == exchange_number+1)) {
		xchg_name="echo-reply";
	} else {
		xchg_name="";
	}

	printf("received %d(%s) packet from %s/%d of len: %d\n",
	       ih.isa_xchg, xchg_name, buf, ntohs(rport), n);
	printf("\trcookie=%08x_%08x icookie=%08x_%08x msgid=%08x\n",
	       *(u_int32_t *)(ih.isa_icookie), 
	       *(u_int32_t *)(ih.isa_icookie+4), 
	       *(u_int32_t *)(ih.isa_rcookie), 
	       *(u_int32_t *)(ih.isa_rcookie+4),
	       ih.isa_msgid);
	printf("\tnp=%03d  version=%d.%d    xchg=%s(%d)\n",
	       ih.isa_np,
	       ih.isa_version >> ISA_MAJ_SHIFT,
	       ih.isa_version & ISA_MIN_MASK,
	       xchg_name,
	       ih.isa_xchg);

	if(reply && xchg==ISAKMP_XCHG_ECHOREQUEST) {
		reply_packet(afamily, s, &sender, sendlen, &ih);
	}
}

static const struct option long_opts[] = {
    /* name, has_arg, flag, val */
    { "help",        no_argument, NULL, 'h' },
    { "version",     no_argument, NULL, 'V' },
    { "verbose",     no_argument, NULL, 'v' },
    { "listen",      no_argument, NULL, 's' },
    { "ikeport",     required_argument, NULL, 'p' },
    { "ikeaddress",  required_argument, NULL, 'b' },
    { "inet",        no_argument, NULL, '4' },
    { "inet6",       no_argument, NULL, '6' },
    { "exchangenum", required_argument, NULL, 'n' },
    { "wait",        required_argument, NULL, 'w' },
    { 0,0,0,0 }
};

int
main(int argc, char **argv)
{
  char *foo;
  const char *errstr;
  int   s;
  int   listen_only;
  int   lport,dport;
  int   afamily;
  int   pfamily;
  int   c;
  int   numSenders, numReceived, noDNS;
  int   waitTime;
  int   verbose, timedOut;
  ip_address laddr, raddr;

  afamily=AF_INET;
  pfamily=PF_INET;
  lport=500;
  dport=500;
  waitTime=10;
  verbose=0;
  listen_only=0;
  noDNS=0;
  bzero(&laddr, sizeof(laddr));

  while((c = getopt_long(argc, argv, "hVnvsp:b:46E:w:", long_opts, 0))!=EOF) {
    switch (c) {
      case 'h':	        /* --help */
	help();
	return 0;	/* GNU coding standards say to stop here */
	
      case 'V':               /* --version */
	fprintf(stderr, "FreeS/WAN %s\n", ipsec_version_code());
	return 0;	/* GNU coding standards say to stop here */
	
      case 'v':	/* --label <string> */
	verbose++;
	continue;
	
      case 'n':
	      noDNS=1;
	      break;
	
      case 'E':
	exchange_number=strtol(optarg, &foo, 0);
	if(optarg==foo || exchange_number < 1 || exchange_number>255) {
	  fprintf(stderr, "Invalid exchange number '%s' (should be 1<=x<255)\n",
		  optarg);
	  exit(1);
	}
	continue;
	
	
      case 's':
	listen_only++;
	continue;
	
      case 'p':
	lport=strtol(optarg, &foo, 0);
	if(optarg==foo || lport <0 || lport>65535) {
	  fprintf(stderr, "Invalid port number '%s' (should be 0<=x<65536)\n",
		  optarg);
	  exit(1);
	}
	continue;
	
      case 'w':
	waitTime=strtol(optarg, &foo, 0);
	if(optarg==foo || waitTime < 0) {
	  fprintf(stderr, "Invalid waittime number '%s' (should be 0<=x)\n",
		  optarg);
	  exit(1);
	}
	continue;
	
      case 'b':
	errstr = ttoaddr(optarg, strlen(optarg), afamily, &laddr);
	if(errstr!=NULL) {
	  fprintf(stderr, "Invalid local address '%s': %s\n",
		  optarg, errstr);
	  exit(1);
	}
	continue;
	
      case '4':
	afamily=AF_INET;
	pfamily=PF_INET;
	continue;
	
      case '6':
	afamily=AF_INET6;
	pfamily=PF_INET6;
	continue;
	
      default:
	assert(FALSE);	/* unknown return value */
    }
  }

  s=socket(pfamily, SOCK_DGRAM, IPPROTO_UDP);
  if(s < 0) {
    perror("socket");
    exit(3);
  }

  switch(afamily) {
  case AF_INET:
	  laddr.u.v4.sin_port = htons(lport);
	  if(bind(s, (struct sockaddr *)&laddr.u.v4, sizeof(laddr.u.v4)) < 0) {
		  perror("v4 bind");
		  exit(5);
	  }
	  break;
	  
  case AF_INET6:
	  laddr.u.v6.sin6_port = htons(lport);
	  if(bind(s, (struct sockaddr *)&laddr.u.v6, sizeof(laddr.u.v6)) < 0) {
		  perror("v6 bind");
		  exit(5);
	  }
	  break;
  }

  numSenders = 0;

  if(!listen_only) {
	  while(optind < argc) {
		  char *port;
		  char *host;
		  char  namebuf[128];

		  host = argv[optind];

		  port = strchr(host, '/');
		  dport=500;
		  if(port) {
			 *port='\0';
			  port++;
			  dport= strtol(port, &foo, 0);
			  if(port==foo || dport < 0 || dport > 65535) {
				  fprintf(stderr, "Invalid port number '%s' "
					  "(should be 0<=x<65536)\n",
					  port);
				  exit(1);
			  }
		  }

		  errstr = ttoaddr(host, strlen(host),
				   afamily, &raddr);
		  if(errstr!=NULL) {
			  fprintf(stderr, "Invalid remote address '%s': %s\n",
				  host, errstr);
			  exit(1);
		  }

		  addrtot(&raddr, 0, namebuf, sizeof(namebuf));

		  printf("Sending packet to %s/%d\n", namebuf, dport);
			 
		  send_ping(afamily, s, &raddr, dport);
		  numSenders++;
		  optind++;
	  }
  }

  timedOut = 0;
  numReceived=0;

  /* really should catch ^C and print stats on exit */
  while(numSenders > 0 || listen_only) {
	  struct pollfd  ready;
	  int n;

	  ready.fd = s;
	  ready.events = POLLIN;

	  n = poll(&ready, 1, waitTime);
	  if(n < 0) {
		  perror("poll");
		  exit(1);
	  }
	  
	  if(n == 0 && !listen_only) {
		  break;
	  }

	  if(n == 1) {
		  numReceived++;
		  receive_ping(afamily, s, listen_only);
	  }
  }

  if(numReceived > 0) {
    printf("%d packets sent, %d packets received. %d packet loss\n",
  	   numSenders, numReceived, numSenders*100/numReceived);
  }
  exit(0);
}

/*
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 4
 * End:
 *
 */
