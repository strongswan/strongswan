/*
 * manipulate eroutes
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1997, 1998, 1999, 2000, 2001  Richard Guy Briggs.
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

char eroute_c_version[] = "RCSID $Id: eroute.c,v 1.3 2005/02/24 20:03:46 as Exp $";


#include <sys/types.h>
#include <linux/types.h> /* new */
#include <string.h>
#include <errno.h>
#include <stdlib.h> /* system(), strtoul() */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>


#include <unistd.h>
#include <freeswan.h>
#if 0
#include <linux/autoconf.h>	/* CONFIG_IPSEC_PFKEYv2 */
#endif
/* permanently turn it on since netlink support has been disabled */

#include <signal.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"

#include <stdio.h>
#include <getopt.h>

char *program_name;
char me[] = "ipsec eroute";
extern char *optarg;
extern int optind, opterr, optopt;
char *eroute_af_opt, *said_af_opt, *edst_opt, *spi_opt, *proto_opt, *said_opt, *dst_opt, *src_opt;
char *transport_proto_opt, *src_port_opt, *dst_port_opt;
int action_type = 0;

int pfkey_sock;
fd_set pfkey_socks;
uint32_t pfkey_seq = 0;

#define EMT_IFADDR	  1	/* set enc if addr */
#define EMT_SETSPI	  2	/* Set SPI properties */
#define EMT_DELSPI	  3	/* Delete an SPI */
#define EMT_GRPSPIS	  4	/* Group SPIs (output order)  */
#define EMT_SETEROUTE	  5	/* set an extended route */
#define EMT_DELEROUTE	  6	/* del an extended route */
#define EMT_TESTROUTE	  7	/* try to find route, print to console */
#define EMT_SETDEBUG	  8	/* set debug level if active */
#define EMT_UNGRPSPIS	  9	/* UnGroup SPIs (output order)  */
#define EMT_CLREROUTE	 10	/* clear the extended route table */
#define EMT_CLRSPIS	 11	/* clear the spi table */
#define EMT_REPLACEROUTE 12	/* set an extended route */
#define EMT_GETDEBUG	 13	/* get debug level if active */
#define EMT_INEROUTE	 14	/* set incoming policy for IPIP on a chain */

static void
add_port(int af, ip_address * addr, short port)
{
    switch (af)
    {
    case AF_INET:
	addr->u.v4.sin_port = port;
	break;
    case AF_INET6:
	addr->u.v6.sin6_port = port;
	break;
    }
}

static void
usage(char* arg)
{
    fprintf(stdout, "usage: %s --{add,addin,replace} --eraf <inet | inet6> --src <src>/<srcmaskbits>|<srcmask> --dst <dst>/<dstmaskbits>|<dstmask> [ --transport-proto <protocol> ] [ --src-port <source-port> ] [ --dst-port <dest-port> ] <SA>\n", arg);
    fprintf(stdout, "            where <SA> is '--af <inet | inet6> --edst <edst> --spi <spi> --proto <proto>'\n");
    fprintf(stdout, "                       OR '--said <said>'\n");
    fprintf(stdout, "                       OR '--said <%%passthrough | %%passthrough4 | %%passthrough6 | %%drop | %%reject | %%trap | %%hold | %%pass>'.\n");
    fprintf(stdout, "       %s --del --eraf <inet | inet6>--src <src>/<srcmaskbits>|<srcmask> --dst <dst>/<dstmaskbits>|<dstmask> [ --transport-proto <protocol> ] [ --src-port <source-port> ] [ --dst-port <dest-port> ]\n", arg);
    fprintf(stdout, "       %s --clear\n", arg);
    fprintf(stdout, "       %s --help\n", arg);
    fprintf(stdout, "       %s --version\n", arg);
    fprintf(stdout, "       %s\n", arg);
    fprintf(stdout, "        [ --debug ] is optional to any %s command.\n", arg);
    fprintf(stdout, "        [ --label <label> ] is optional to any %s command.\n", arg);
    exit(1);
}

static struct option const longopts[] =
{
	{"dst", 1, 0, 'D'},
	{"src", 1, 0, 'S'},
	{"eraf", 1, 0, 'f'},
	{"add", 0, 0, 'a'},
	{"addin", 0, 0, 'A'},
	{"replace", 0, 0, 'r'},
	{"clear", 0, 0, 'c'},
	{"del", 0, 0, 'd'},
	{"af", 1, 0, 'i'},
	{"edst", 1, 0, 'e'},
	{"proto", 1, 0, 'p'},
	{"transport-proto", 1, 0, 'P'},
	{"src-port", 1, 0, 'Q'},
	{"dst-port", 1, 0, 'R'},
	{"help", 0, 0, 'h'},
	{"spi", 1, 0, 's'},
	{"said", 1, 0, 'I'},
	{"version", 0, 0, 'v'},
	{"label", 1, 0, 'l'},
	{"optionsfrom", 1, 0, '+'},
	{"debug", 0, 0, 'g'},
	{0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
    /* int fd; */
    char *endptr;
    /* int ret; */
    int c, previous = -1;
    const char* error_s;
    int debug = 0;

    int error = 0;

    char ipaddr_txt[ADDRTOT_BUF];
    struct sadb_ext *extensions[SADB_EXT_MAX + 1];
    struct sadb_msg *pfkey_msg;
    ip_address pfkey_address_s_ska;
    /*struct sockaddr_in pfkey_address_d_ska;*/
    ip_address pfkey_address_sflow_ska;
    ip_address pfkey_address_dflow_ska;
    ip_address pfkey_address_smask_ska;
    ip_address pfkey_address_dmask_ska;

    int transport_proto = 0;
    int src_port = 0;
    int dst_port = 0;
    ip_said said;
    ip_subnet s_subnet, d_subnet;
    int eroute_af = 0;
    int said_af = 0;

    int argcount = argc;

    const char permitted_options[] =
	"%s: Only one of '--add', '--addin', '--replace', '--clear', or '--del' options permitted.\n";

    program_name = argv[0];
    eroute_af_opt = said_af_opt = edst_opt = spi_opt = proto_opt = said_opt = dst_opt = src_opt = NULL;

    while((c = getopt_long(argc, argv, ""/*"acdD:e:i:hprs:S:f:vl:+:g"*/, longopts, 0)) != EOF)
    {
	switch(c)
	{
	case 'g':
	    debug = 1;
	    pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
	    argcount--;
	    break;
	case 'a':
	    if (action_type)
	    {
		fprintf(stderr, permitted_options, program_name);
		exit(1);
	    }
	    action_type = EMT_SETEROUTE;
	    break;
	case 'A':
	    if (action_type)
	    {
		fprintf(stderr, permitted_options, program_name);
		exit(1);
	    }
	    action_type = EMT_INEROUTE;
	    break;
	case 'r':
	    if (action_type)
	    {
		fprintf(stderr, permitted_options, program_name);
		exit(1);
	    }
	    action_type = EMT_REPLACEROUTE;
	    break;
	case 'c':
	    if (action_type)
	    {
		fprintf(stderr, permitted_options, program_name);
		exit(1);
	    }
	    action_type = EMT_CLREROUTE;
	    break;
	case 'd':
	    if (action_type)
	    {
		fprintf(stderr, permitted_options, program_name);
		exit(1);
	    }
	    action_type = EMT_DELEROUTE;
	    break;
	case 'e':
	    if (said_opt)
	    {
		fprintf(stderr, "%s: Error, EDST parameter redefined:%s, already defined in SA:%s\n"
				, program_name, optarg, said_opt);
		exit (1);
	    }
	    if (edst_opt)
	    {
		fprintf(stderr, "%s: Error, EDST parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, edst_opt);
		exit (1);
	    }
	    error_s = ttoaddr(optarg, 0, said_af, &said.dst);
	    if (error_s != NULL)
	    {
		fprintf(stderr, "%s: Error, %s converting --edst argument:%s\n"
				, program_name, error_s, optarg);
		exit (1);
	    }
	    edst_opt = optarg;
	    break;
	case 'h':
	case '?':
	    usage(program_name);
	    exit(1);
	case 's':
	    if (said_opt)
	    {
		fprintf(stderr, "%s: Error, SPI parameter redefined:%s, already defined in SA:%s\n"
				, program_name, optarg, said_opt);
		exit (1);
	    }
	    if (spi_opt)
	    {
		fprintf(stderr, "%s: Error, SPI parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, spi_opt);
		exit (1);
	    }
	    said.spi = htonl(strtoul(optarg, &endptr, 0));
	    if (!(endptr == optarg + strlen(optarg)))
	    {
		fprintf(stderr, "%s: Invalid character in SPI parameter: %s\n"
				, program_name, optarg);
		exit (1);
	    }
	    if (ntohl(said.spi) < 0x100)
	    {
		fprintf(stderr, "%s: Illegal reserved spi: %s => 0x%x Must be larger than 0x100.\n"
				, program_name, optarg, ntohl(said.spi));
		exit(1);
	    }
	    spi_opt = optarg;
	    break;
	case 'p':
	    if (said_opt)
	    {
		fprintf(stderr, "%s: Error, PROTO parameter redefined:%s, already defined in SA:%s\n"
				, program_name, optarg, said_opt);
		exit (1);
	    }
	    if (proto_opt)
	    {
		fprintf(stderr, "%s: Error, PROTO parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, proto_opt);
		exit (1);
	    }
#if 0
	    if (said.proto)
	    {
		fprintf(stderr, "%s: Warning, PROTO parameter redefined:%s\n"
				, program_name, optarg);
		exit (1);
	    }
#endif
	    if (!strcmp(optarg, "ah"))
		said.proto = SA_AH;
	    if (!strcmp(optarg, "esp"))
		said.proto = SA_ESP;
	    if (!strcmp(optarg, "tun"))
		said.proto = SA_IPIP;
	    if (!strcmp(optarg, "comp"))
		said.proto = SA_COMP;
	    if (said.proto == 0)
	    {
		fprintf(stderr, "%s: Invalid PROTO parameter: %s\n"
				, program_name, optarg);
		exit (1);
	    }
	    proto_opt = optarg;
	    break;
	case 'I':
	    if (said_opt)
	    {
		fprintf(stderr, "%s: Error, SAID parameter redefined:%s, already defined in SA:%s\n"
				, program_name, optarg, said_opt);
		exit (1);
	    }
	    if (proto_opt)
	    {
		fprintf(stderr, "%s: Error, PROTO parameter redefined in SA:%s, already defined as:%s\n"
				, program_name, optarg, proto_opt);
		exit (1);
	    }
	    if (edst_opt)
	    {
		fprintf(stderr, "%s: Error, EDST parameter redefined in SA:%s, already defined as:%s\n"
				, program_name, optarg, edst_opt);
		exit (1);
	    }
	    if (spi_opt)
	    {
		fprintf(stderr, "%s: Error, SPI parameter redefined in SA:%s, already defined as:%s\n"
				, program_name, optarg, spi_opt);
		exit (1);
	    }
	    if (said_af_opt)
	    {
		fprintf(stderr, "%s: Error, address family parameter redefined in SA:%s, already defined as:%s\n"
				, program_name, optarg, said_af_opt);
		exit (1);
	    }
	    error_s = ttosa(optarg, 0, &said);
	    if (error_s != NULL)
	    {
		fprintf(stderr, "%s: Error, %s converting --sa argument:%s\n"
				, program_name, error_s, optarg);
		exit (1);
	    }
	    else if (ntohl(said.spi) < 0x100)
	    {
		fprintf(stderr, "%s: Illegal reserved spi: %s => 0x%x Must be larger than or equal to 0x100.\n"
				, program_name, optarg, said.spi);
		exit(1);
	    }
	    said_af = addrtypeof(&said.dst);
	    said_opt = optarg;
	    break;
	case 'v':
	    fprintf(stdout, "%s %s\n", me, ipsec_version_code());
	    fprintf(stdout, "See `ipsec --copyright' for copyright information.\n");
	    exit(1);
	case 'D':
	    if (dst_opt)
	    {
		fprintf(stderr, "%s: Error, --dst parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, dst_opt);
		exit (1);
	    }
	    error_s = ttosubnet(optarg, 0, eroute_af, &d_subnet);
	    if (error_s != NULL)
	    {
		fprintf(stderr, "%s: Error, %s converting --dst argument: %s\n"
				, program_name, error_s, optarg);
		exit (1);
	    }
	    dst_opt = optarg;
	    break;
	case 'S':
	    if (src_opt)
	    {
		fprintf(stderr, "%s: Error, --src parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, src_opt);
		exit (1);
	    }
	    error_s = ttosubnet(optarg, 0, eroute_af, &s_subnet);
	    if (error_s != NULL)
	    {
		fprintf(stderr, "%s: Error, %s converting --src argument: %s\n"
				, program_name, error_s, optarg);
		exit (1);
	    }
	    src_opt = optarg;
	    break;
	case 'P':
	    if (transport_proto_opt)
	    {
		fprintf(stderr, "%s: Error, --transport-proto parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, transport_proto_opt);
		exit(1);
	    }
	    transport_proto_opt = optarg;
	    break;
	case 'Q':
	    if (src_port_opt)
	    {
		fprintf(stderr, "%s: Error, --src-port parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, src_port_opt);
		exit(1);
	    }
	    src_port_opt = optarg;
	    break;
	case 'R':
	    if (dst_port_opt)
	    {
		fprintf(stderr, "%s: Error, --dst-port parameter redefined:%s, already defined as:%s\n"
				, program_name, optarg, dst_port_opt);
		exit(1);
	    }
	    dst_port_opt = optarg;
	    break;
	case 'l':
	    program_name = malloc(strlen(argv[0])
			+ 10 /* update this when changing the sprintf() */
			+ strlen(optarg));
	    sprintf(program_name, "%s --label %s", argv[0], optarg);
	    argcount -= 2;
	    break;
	case 'i': /* specifies the address family of the SAID, stored in said_af */
	    if (said_af_opt)
	    {
		fprintf(stderr, "%s: Error, address family of SAID redefined:%s, already defined as:%s\n"
				, program_name, optarg, said_af_opt);
		exit (1);
	    }
	    if (!strcmp(optarg, "inet"))
		said_af = AF_INET;
	    if (!strcmp(optarg, "inet6"))
		said_af = AF_INET6;
	    if (said_af == 0)
	    {
		fprintf(stderr, "%s: Invalid address family parameter for SAID: %s\n"
				, program_name, optarg);
		exit (1);
	    }
	    said_af_opt = optarg;
	    break;
	case 'f': /* specifies the address family of the eroute, stored in eroute_af */
	    if (eroute_af_opt)
	    {
		fprintf(stderr, "%s: Error, address family of eroute redefined:%s, already defined as:%s\n"
				, program_name, optarg, eroute_af_opt);
		exit (1);
	    }
	    if (!strcmp(optarg, "inet"))
		eroute_af = AF_INET;
	    if (!strcmp(optarg, "inet6"))
		eroute_af = AF_INET6;
	    if (eroute_af == 0)
	    {
		fprintf(stderr, "%s: Invalid address family parameter for eroute: %s\n"
				, program_name, optarg);
		exit (1);
	    }
	    eroute_af_opt = optarg;
	    break;
	case '+': /* optionsfrom */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    /* no return on error */
	    break;
	default:
	    break;
	}
	previous = c;
    }

    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: argc=%d\n", program_name, argc);
    }
	
    if (argcount == 1)
    {
	system("cat /proc/net/ipsec_eroute");
	exit(0);
    }

    /* Sanity checks */

    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: action_type=%d\n", program_name, action_type);
    }

    if (transport_proto_opt != 0)
    {
	struct protoent * proto = getprotobyname(transport_proto_opt);

	if (proto != 0)
	{
	    transport_proto = proto->p_proto;
	}
	else
	{
	    transport_proto = strtoul(transport_proto_opt, &endptr, 0);

	    if ((*endptr != '\0')
	    || (transport_proto == 0 && endptr == transport_proto_opt))
	    {
		fprintf(stderr, "%s: Invalid character in --transport-proto parameter: %s\n"
				, program_name, transport_proto_opt);
		exit (1);
	    }
	    if (transport_proto > 255)
	    {
		fprintf(stderr, "%s: --transport-proto parameter: %s must be in the range 0 to 255 inclusive\n"
				, program_name, transport_proto_opt);
		exit (1);
	    }
	}
    }

    if (src_port_opt != 0 || dst_port_opt != 0)
    {
	switch (transport_proto)
	{
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	    break;
	default:
	    fprintf(stderr, "%s: --transport-proto with either UDP or TCP must be specified if --src-port or --dst-port is used\n"
	    		, program_name);
	    exit(1);
	}
    }

    if (src_port_opt)
    {
	struct servent * ent = getservbyname(src_port_opt, 0);

	if (ent != 0)
	{
	    src_port = ent->s_port;
	}
	else
	{
	    src_port = strtoul(src_port_opt, &endptr, 0);

	    if ((*endptr != '\0')
	    || (src_port == 0 && endptr == src_port_opt))
	    {
		fprintf(stderr, "%s: Invalid character in --src-port parameter: %s\n"
				, program_name, src_port_opt);
		exit (1);
	    }
	    if (src_port > 65535)
	    {
		fprintf(stderr, "%s: --src-port parameter: %s must be in the range 0 to 65535 inclusive\n"
				, program_name, src_port_opt);
	    }
	    src_port = htons(src_port);
	}
    }

    if (dst_port_opt)
    {
	struct servent * ent = getservbyname(dst_port_opt, 0);

	if (ent != 0)
	{
	    dst_port = ent->s_port;
	}
	else
	{
	    dst_port = strtoul(dst_port_opt, &endptr, 0);

	    if ((*endptr != '\0')
	    || (dst_port == 0 && endptr == dst_port_opt))
	    {
		fprintf(stderr, "%s: Invalid character in --dst-port parameter: %s\n"
				, program_name, dst_port_opt);
		exit (1);
	    }
	    if (dst_port > 65535)
	    {
		fprintf(stderr, "%s: --dst-port parameter: %s must be in the range 0 to 65535 inclusive\n"
				, program_name, dst_port_opt);
	    }
	    dst_port = htons(dst_port);
	}
    }

    switch(action_type)
    {
    case EMT_SETEROUTE:
    case EMT_REPLACEROUTE:
    case EMT_INEROUTE:
	if (!(said_af_opt && edst_opt && spi_opt && proto_opt) && !(said_opt))
	{
	    fprintf(stderr, "%s: add and addin options must have SA specified.\n"
			, program_name);
	    exit(1);
	}
    case EMT_DELEROUTE:
	if (!src_opt)
	{
	    fprintf(stderr, "%s: Error -- %s option '--src' is required.\n"
			, program_name, (action_type == EMT_SETEROUTE) ? "add" : "del");
	    exit(1);
	}
	if (!dst_opt)
	{
	    fprintf(stderr, "%s: Error -- %s option '--dst' is required.\n"
			, program_name, (action_type == EMT_SETEROUTE) ? "add" : "del");
	    exit(1);
	}
    case EMT_CLREROUTE:
	break;
    default:
	fprintf(stderr, "%s: exactly one of '--add', '--addin', '--replace', '--del' or '--clear' options must be specified.\n"
			"Try %s --help' for usage information.\n"
			, program_name, program_name);
	exit(1);
    }

    if ((pfkey_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0)
    {
	fprintf(stderr, "%s: Trouble opening PF_KEY family socket with error: "
			, program_name);
	switch(errno)
	{
	case ENOENT:
	    fprintf(stderr, "device does not exist.  See FreeS/WAN installation procedure.\n");
	    break;
	case EACCES:
	    fprintf(stderr, "access denied.  ");
	    if (getuid() == 0)
	    {
		fprintf(stderr, "Check permissions.  Should be 600.\n");
	    }
	    else
	    {
		fprintf(stderr, "You must be root to open this file.\n");
	    }
	    break;
	case EUNATCH:
	    fprintf(stderr, "KLIPS not loaded.\n");
	    break;
	case ENODEV:
	    fprintf(stderr, "KLIPS not loaded or enabled.\n");
	    break;
	case EBUSY:
	    fprintf(stderr, "KLIPS is busy.  Most likely a serious internal error occured in a previous command. "
	    		    "Please report as much detail as possible to development team.\n");
	    break;
	case EINVAL:
	    fprintf(stderr, "Invalid argument, KLIPS not loaded or check kernel log messages for specifics.\n");
	    break;
	case ENOBUFS:
	case ENOMEM:
	case ENFILE:
	    fprintf(stderr, "No kernel memory to allocate socket.\n");
	    break;
	case EMFILE:
	    fprintf(stderr, "Process file table overflow.\n");
	    break;
	case ESOCKTNOSUPPORT:
	    fprintf(stderr, "Socket type not supported.\n");
	    break;
	case EPROTONOSUPPORT:
	    fprintf(stderr, "Protocol version not supported.\n");
	    break;
	case EAFNOSUPPORT:
	    fprintf(stderr, "KLIPS not loaded or enabled.\n");
	    break;
	default:
	    fprintf(stderr, "Unknown file open error %d.  Please report as much detail as possible to development team.\n"
	    		, errno);
	}
	exit(1);
    }

    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: PFKEYv2 socket successfully openned=%d.\n"
			, program_name, pfkey_sock);
    }

    /* Build an SADB_X_ADDFLOW or SADB_X_DELFLOW message to send down. */
    /* It needs <base, SA, address(SD), flow(SD), mask(SD)> minimum. */
    pfkey_extensions_init(extensions);

    error = pfkey_msg_hdr_build(&extensions[0]
		, (action_type == EMT_SETEROUTE || action_type == EMT_REPLACEROUTE
		|| action_type == EMT_INEROUTE)? SADB_X_ADDFLOW : SADB_X_DELFLOW
	    	, proto2satype(said.proto)
		, 0
		, ++pfkey_seq
		, getpid()
	    );

    if (error)
    {
	fprintf(stderr, "%s: Trouble building message header, error=%d.\n"
			, program_name, error);
	pfkey_extensions_free(extensions);
	exit(1);
    }

    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: pfkey_msg_hdr_build successfull.\n"
			, program_name);
    }

    switch (action_type)
    {
    case EMT_SETEROUTE:
    case EMT_REPLACEROUTE:
    case EMT_INEROUTE:
    case EMT_CLREROUTE:
	error = pfkey_sa_build(&extensions[SADB_EXT_SA]
		    , SADB_EXT_SA
		    , said.spi /* in network order */
		    , 0
		    , 0
		    , 0
		    , 0
		    , (action_type == EMT_CLREROUTE) ? SADB_X_SAFLAGS_CLEARFLOW : 0
		);

	if (error)
	{
	    fprintf(stderr, "%s: Trouble building sa extension, error=%d.\n"
			, program_name, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_sa_build successful.\n"
	    		, program_name);
	}
    default:
	break;
    }

    switch (action_type)
    {
    case EMT_SETEROUTE:
    case EMT_REPLACEROUTE:
    case EMT_INEROUTE:
	anyaddr(said_af, &pfkey_address_s_ska);
	error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC]
			, SADB_EXT_ADDRESS_SRC
			, 0
			, 0
			, sockaddrof(&pfkey_address_s_ska)
		);
	if (error)
	{
	    addrtot(&pfkey_address_s_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
	    fprintf(stderr, "%s: Trouble building address_s extension (%s), error=%d.\n"
			, program_name, ipaddr_txt, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_address_build successful for src.\n"
	    		, program_name);
	}

	error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST]
			, SADB_EXT_ADDRESS_DST
			, 0
			, 0
			, sockaddrof(&said.dst)
		);

	if (error)
	{
	    addrtot(&said.dst, 0, ipaddr_txt, sizeof(ipaddr_txt));
	    fprintf(stderr, "%s: Trouble building address_d extension (%s), error=%d.\n"
			, program_name, ipaddr_txt, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_address_build successful for dst.\n"
	    		, program_name);
	}
    default:
	break;
    }
	
    switch (action_type)
    {
    case EMT_SETEROUTE:
    case EMT_REPLACEROUTE:
    case EMT_INEROUTE:
    case EMT_DELEROUTE:
	networkof(&s_subnet, &pfkey_address_sflow_ska); /* src flow */
	add_port(eroute_af, &pfkey_address_sflow_ska, src_port);

	error = pfkey_address_build(&extensions[SADB_X_EXT_ADDRESS_SRC_FLOW]
			, SADB_X_EXT_ADDRESS_SRC_FLOW
			, 0
			, 0
			, sockaddrof(&pfkey_address_sflow_ska)
		);

	if (error)
	{
	    addrtot(&pfkey_address_sflow_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
	    fprintf(stderr, "%s: Trouble building address_sflow extension (%s), error=%d.\n",
			program_name, ipaddr_txt, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_address_build successful for src flow.\n"
			, program_name);
	}
	
	networkof(&d_subnet, &pfkey_address_dflow_ska); /* dst flow */
	add_port(eroute_af, &pfkey_address_dflow_ska, dst_port);

	error = pfkey_address_build(&extensions[SADB_X_EXT_ADDRESS_DST_FLOW]
			, SADB_X_EXT_ADDRESS_DST_FLOW
			, 0
			, 0
			, sockaddrof(&pfkey_address_dflow_ska)
		);

	if (error)
	{
	    addrtot(&pfkey_address_dflow_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
	    fprintf(stderr, "%s: Trouble building address_dflow extension (%s), error=%d.\n"
			, program_name, ipaddr_txt, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_address_build successful for dst flow.\n"
	    		, program_name);
	}
		
	maskof(&s_subnet, &pfkey_address_smask_ska); /* src mask */
	add_port(eroute_af, &pfkey_address_smask_ska, src_port ? ~0:0);

	error = pfkey_address_build(&extensions[SADB_X_EXT_ADDRESS_SRC_MASK]
			, SADB_X_EXT_ADDRESS_SRC_MASK
			, 0
			, 0
			, sockaddrof(&pfkey_address_smask_ska)
		);

	if (error)
	{
	    addrtot(&pfkey_address_smask_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
	    fprintf(stderr, "%s: Trouble building address_smask extension (%s), error=%d.\n"
			, program_name, ipaddr_txt, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_address_build successful for src mask.\n"
	    		, program_name);
	}
		
	maskof(&d_subnet, &pfkey_address_dmask_ska); /* dst mask */
	add_port(eroute_af, &pfkey_address_dmask_ska, dst_port ? ~0:0);

	error = pfkey_address_build(&extensions[SADB_X_EXT_ADDRESS_DST_MASK]
			, SADB_X_EXT_ADDRESS_DST_MASK
			, 0
			, 0
			, sockaddrof(&pfkey_address_dmask_ska)
		);

	if (error)
	{
	    addrtot(&pfkey_address_dmask_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
	    fprintf(stderr, "%s: Trouble building address_dmask extension (%s), error=%d.\n"
			, program_name, ipaddr_txt, error);
	    pfkey_extensions_free(extensions);
	    exit(1);
	}
	if (debug)
	{
	    fprintf(stdout, "%s: DEBUG: pfkey_address_build successful for dst mask.\n"
	    		, program_name);
	}
    }
	
    if (transport_proto != 0)
    {
	error = pfkey_x_protocol_build(&extensions[SADB_X_EXT_PROTOCOL]
			, transport_proto);
	
	if (error)
	{
	    fprintf(stderr, "%s: Trouble building transport protocol extension, error=%d.\n"
			, program_name, error);
	    exit(1);
	}
    }

    error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);
     
    if (error)
    {
	fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n"
			, program_name, error);
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
	exit(1);
    }
    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: pfkey_msg_build successful.\n"
			, program_name);
    }

    error = write(pfkey_sock
		, pfkey_msg
		, pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN
	    )
	    != (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);
	    
    if (error)
    {
	fprintf(stderr, "%s: pfkey write failed, returning %d with errno=%d.\n"
			, program_name, error, errno);
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);

	switch (errno)
	{
	case EINVAL:
	    fprintf(stderr, "Invalid argument, check kernel log messages for specifics.\n");
	    break;
	case ENXIO:
	    if (action_type == EMT_SETEROUTE || action_type == EMT_REPLACEROUTE)
	    {
		fprintf(stderr, "Invalid mask.\n");
		break;
	    }
	    if (action_type == EMT_DELEROUTE)
	    {
		fprintf(stderr, "Mask not found.\n");
		break;
	    }
	case EFAULT:
	    if (action_type == EMT_SETEROUTE || action_type == EMT_REPLACEROUTE)
	    {
		fprintf(stderr, "Invalid address.\n");
		break;
	    }
	    if (action_type == EMT_DELEROUTE)
	    {
		fprintf(stderr, "Address not found.\n");
		break;
	    }
	case EACCES:
	    fprintf(stderr, "access denied.  ");
	    if (getuid() == 0)
	    {
		fprintf(stderr, "Check permissions.  Should be 600.\n");
	    }
	    else 
	    {
		fprintf(stderr, "You must be root to open this file.\n");
	    }
	    break;
	case EUNATCH:
	    fprintf(stderr, "KLIPS not loaded.\n");
	    break;
	case EBUSY:
	    fprintf(stderr, "KLIPS is busy.  Most likely a serious internal error occured in a previous command. "
			    "Please report as much detail as possible to development team.\n");
	    break;
	case ENODEV:
	    fprintf(stderr, "KLIPS not loaded or enabled.\n");
	    fprintf(stderr, "No device?!?\n");
	    break;
	case ENOBUFS:
	    fprintf(stderr, "No kernel memory to allocate SA.\n");
	    break;
	case ESOCKTNOSUPPORT:
	    fprintf(stderr, "Algorithm support not available in the kernel.  Please compile in support.\n");
	    break;
	case EEXIST:
	    fprintf(stderr, "eroute already in use.  Delete old one first.\n");
	    break;
	case ENOENT:
	    if (action_type == EMT_INEROUTE)
	    {
		fprintf(stderr, "non-existant IPIP SA.\n");
		break;
	    }
	    fprintf(stderr, "eroute doesn't exist.  Can't delete.\n");
	    break;
	case ENOSPC:
	    fprintf(stderr, "no room in kernel SAref table.  Cannot process request.\n");
	    break;
	case ESPIPE:
	    fprintf(stderr, "kernel SAref table internal error.  Cannot process request.\n");
	    break;
	default:
	    fprintf(stderr, "Unknown socket write error %d.  Please report as much detail as possible to development team.\n"
	    		, errno);
	}
/*	fprintf(stderr, "%s: socket write returned errno %d\n",
			program_name, errno);*/
	exit(1);
    }
    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: pfkey write successful.\n"
			, program_name);
    }

    if (pfkey_msg)
    {
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
    }

    (void) close(pfkey_sock);  /* close the socket */

    if (debug)
    {
	fprintf(stdout, "%s: DEBUG: write ok\n", program_name);
    }

    exit(0);
}
