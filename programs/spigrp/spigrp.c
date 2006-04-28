/*
 * SA grouping
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

char spigrp_c_version[] = "RCSID $Id: spigrp.c,v 1.2 2004/06/07 15:16:34 as Exp $";


#include <sys/types.h>
#include <linux/types.h> /* new */
#include <string.h>
#include <errno.h>
#include <sys/stat.h> /* open() */
#include <fcntl.h> /* open() */
#include <stdlib.h> /* system(), strtoul() */

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <freeswan.h>
#if 0
#include <linux/autoconf.h>	/* CONFIG_IPSEC_PFKEYv2 */
#endif

#include <signal.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_ah.h"


char *program_name;

int pfkey_sock;
fd_set pfkey_socks;
uint32_t pfkey_seq = 0;
 
struct said_af {
 	int af;
 	ip_said said;
}; /* to store the given saids and their address families in an array */
 /* XXX: Note that we do *not* check if the address families of all SAID?s are the same.
  *      This can make it possible to group SAs for IPv4 addresses with SAs for
  *      IPv6 addresses (perhaps some kind of IPv4-over-secIPv6 or vice versa).
  *      Do not know, if this is a bug or feature */

static void
usage(char *s)
{
	fprintf(stdout, "usage: Note: position of options and arguments is important!\n");
	fprintf(stdout, "usage: %s [ --debug ] [ --label <label> ] af1 dst1 spi1 proto1 [ af2 dst2 spi2 proto2 [ af3 dst3 spi3 proto3 [ af4 dst4 spi4 proto4 ] ] ]\n", s);
	fprintf(stdout, "usage: %s [ --debug ] [ --label <label> ] --said <SA1> [ <SA2> [ <SA3> [ <SA4> ] ] ]\n", s);
	fprintf(stdout, "usage: %s --help\n", s);
	fprintf(stdout, "usage: %s --version\n", s);
	fprintf(stdout, "usage: %s\n", s);
	fprintf(stdout, "        [ --debug ] is optional to any %s command.\n", s);
	fprintf(stdout, "        [ --label <label> ] is optional to any %s command.\n", s);
}

	
int
main(int argc, char **argv)
{
	int i, nspis;
	char *endptr;
	int said_opt = 0;

	const char* error_s = NULL;
	char ipaddr_txt[ADDRTOT_BUF];
	int debug = 0;
	int j;
	struct said_af said_af_array[4];

	int error = 0;

	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
#if 0
	ip_address pfkey_address_s_ska;
#endif
	
	program_name = argv[0];
	for(i = 0; i < 4; i++) {
		memset(&said_af_array[i], 0, sizeof(struct said_af));
	}

        if(argc > 1 && strcmp(argv[1], "--debug") == 0) {
		debug = 1;
		if(debug) {
			fprintf(stdout, "\"--debug\" option requested.\n");
		}
		argv += 1;
		argc -= 1;
		pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
        }

	if(debug) {
		fprintf(stdout, "argc=%d (%d incl. --debug option).\n",
			argc,
			argc + 1);
	}

        if(argc > 1 && strcmp(argv[1], "--label") == 0) {
		if(argc > 2) {
			program_name = malloc(strlen(argv[0])
					      + 10 /* update this when changing the sprintf() */
					      + strlen(argv[2]));
			sprintf(program_name, "%s --label %s",
				argv[0],
				argv[2]);
			if(debug) {
				fprintf(stdout, "using \"%s\" as a label.\n", program_name);
			}
			argv += 2;
			argc -= 2;
		} else {
			fprintf(stderr, "%s: --label option requires an argument.\n",
				program_name);
			exit(1);
		}
        }
  
	if(debug) {
		fprintf(stdout, "...After check for --label option.\n");
	}

	if(argc == 1) {
		system("cat /proc/net/ipsec_spigrp");
		exit(0);
	}

	if(debug) {
		fprintf(stdout, "...After check for no option to print /proc/net/ipsec_spigrp.\n");
	}

        if(strcmp(argv[1], "--help") == 0) {
		if(debug) {
			fprintf(stdout, "\"--help\" option requested.\n");
		}
                usage(program_name);
                exit(1);
        }

	if(debug) {
		fprintf(stdout, "...After check for --help option.\n");
	}

        if(strcmp(argv[1], "--version") == 0) {
		if(debug) {
			fprintf(stdout, "\"--version\" option requested.\n");
		}
                fprintf(stderr, "%s, %s\n", program_name, spigrp_c_version);
                exit(1);
        }

	if(debug) {
		fprintf(stdout, "...After check for --version option.\n");
	}

        if(strcmp(argv[1], "--said") == 0) {
		if(debug) {
			fprintf(stdout, "processing %d args with --said flag.\n", argc);
		}
		said_opt = 1;
        }
	
	if(debug) {
		fprintf(stdout, "...After check for --said option.\n");
	}

	if(said_opt) {
		if (argc < 3 /*|| argc > 5*/) {
			fprintf(stderr, "expecting 3 or more args with --said, got %d.\n", argc);
			usage(program_name);
                	exit(1);
		}
		nspis = argc - 2;
	} else {
		if ((argc < 5) || (argc > 17) || ((argc % 4) != 1)) {
			fprintf(stderr, "expecting 5 or more args without --said, got %d.\n", argc);
			usage(program_name);
                	exit(1);
		}
		nspis = argc / 4;
	}

	if(debug) {
		fprintf(stdout, "processing %d nspis.\n", nspis);
	}

	for(i = 0; i < nspis; i++) {
		if(debug) {
			fprintf(stdout, "processing spi #%d.\n", i);
		}

		if(said_opt) {
			error_s = ttosa((const char *)argv[i+2], 0, (ip_said*)&(said_af_array[i].said));
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting --sa argument:%s\n",
					program_name, error_s, argv[i+2]);
				exit (1);
			}
			said_af_array[i].af = addrtypeof(&(said_af_array[i].said.dst));
			if(debug) {
				addrtot(&said_af_array[i].said.dst, 0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stdout, "said[%d].dst=%s.\n", i, ipaddr_txt);
			}
		} else {
			if(!strcmp(argv[i*4+4], "ah")) {
				said_af_array[i].said.proto = SA_AH;
			}
			if(!strcmp(argv[i*4+4], "esp")) {
				said_af_array[i].said.proto = SA_ESP;
			}
			if(!strcmp(argv[i*4+4], "tun")) {
				said_af_array[i].said.proto = SA_IPIP;
			}
			if(!strcmp(argv[i*4+4], "comp")) {
				said_af_array[i].said.proto = SA_COMP;
			}
			if(said_af_array[i].said.proto == 0) {
				fprintf(stderr, "%s: Badly formed proto: %s\n",
					program_name, argv[i*4+4]);
				exit(1);
			}
			said_af_array[i].said.spi = htonl(strtoul(argv[i*4+3], &endptr, 0));
			if(!(endptr == argv[i*4+3] + strlen(argv[i*4+3]))) {
				fprintf(stderr, "%s: Badly formed spi: %s\n",
					program_name, argv[i*4+3]);
				exit(1);
			}
			if(!strcmp(argv[i*4+1], "inet")) {
				said_af_array[i].af = AF_INET;
			}
			if(!strcmp(argv[i*4+1], "inet6")) {
				said_af_array[i].af = AF_INET6;
			}
			if((said_af_array[i].af != AF_INET) && (said_af_array[i].af != AF_INET6)) {
				fprintf(stderr, "%s: Address family %s not supported\n",
					program_name, argv[i*4+1]);
				exit(1);
			}
			error_s = ttoaddr(argv[i*4+2], 0, said_af_array[i].af, &(said_af_array[i].said.dst));
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting %dth address argument:%s\n",
					program_name, error_s, i, argv[i*4+2]);
				exit (1);
			}
		}
		if(debug) {
			fprintf(stdout, "SA %d contains: ", i+1);
			fprintf(stdout, "\n");
			fprintf(stdout, "proto = %d\n", said_af_array[i].said.proto);
			fprintf(stdout, "spi = %08x\n", said_af_array[i].said.spi);
			addrtot(&said_af_array[i].said.dst, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stdout, "edst = %s\n", ipaddr_txt);
		}
	}	

	if(debug) {
		fprintf(stdout, "Opening pfkey socket.\n");
	}

	if((pfkey_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
		fprintf(stderr, "%s: Trouble opening PF_KEY family socket with error: ",
			program_name);
		switch(errno) {
		case ENOENT:
			fprintf(stderr, "device does not exist.  See FreeS/WAN installation procedure.\n");
			break;
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if(getuid() == 0) {
				fprintf(stderr, "Check permissions.  Should be 600.\n");
			} else {
				fprintf(stderr, "You must be root to open this file.\n");
			}
			break;
		case EUNATCH:
			fprintf(stderr, "Netlink not enabled OR KLIPS not loaded.\n");
			break;
		case ENODEV:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			break;
		case EBUSY:
			fprintf(stderr, "KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
			break;
		case EINVAL:
			fprintf(stderr, "Invalid argument, KLIPS not loaded or check kernel log messages for specifics.\n");
			break;
		case ENOBUFS:
			fprintf(stderr, "No kernel memory to allocate SA.\n");
			break;
		case ESOCKTNOSUPPORT:
			fprintf(stderr, "Algorithm support not available in the kernel.  Please compile in support.\n");
			break;
		case EEXIST:
			fprintf(stderr, "SA already in use.  Delete old one first.\n");
			break;
		case ENXIO:
			fprintf(stderr, "SA does not exist.  Cannot delete.\n");
			break;
		case EAFNOSUPPORT:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			break;
		default:
			fprintf(stderr, "Unknown file open error %d.  Please report as much detail as possible to development team.\n", errno);
		}
		exit(1);
	}

	for(i = 0; i < (((nspis - 1) < 2) ? 1 : (nspis - 1)); i++) {
		if(debug) {
			fprintf(stdout, "processing %dth pfkey message.\n", i);
		}

		pfkey_extensions_init(extensions);
		for(j = 0; j < ((nspis == 1) ? 1 : 2); j++) {
			if(debug) {
				fprintf(stdout, "processing %dth said of %dth pfkey message.\n", j, i);
			}

			/* Build an SADB_X_GRPSA message to send down. */
			/* It needs <base, SA, SA2, address(D,D2) > minimum. */
			if(!j) {
				if((error = pfkey_msg_hdr_build(&extensions[0],
								SADB_X_GRPSA,
								proto2satype(said_af_array[i].said.proto),
								0,
								++pfkey_seq,
								getpid()))) {
					fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
						program_name, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			} else {
				if(debug) {
					fprintf(stdout, "setting x_satype proto=%d satype=%d\n",
						said_af_array[i+j].said.proto,
						proto2satype(said_af_array[i+j].said.proto)
						);
				}

				if((error = pfkey_x_satype_build(&extensions[SADB_X_EXT_SATYPE2],
								 proto2satype(said_af_array[i+j].said.proto)
					))) {
					fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
						program_name, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			}

			if((error = pfkey_sa_build(&extensions[!j ? SADB_EXT_SA : SADB_X_EXT_SA2],
						   !j ? SADB_EXT_SA : SADB_X_EXT_SA2,
						   said_af_array[i+j].said.spi, /* in network order */
						   0,
						   0,
						   0,
						   0,
						   0))) {
				fprintf(stderr, "%s: Trouble building sa extension, error=%d.\n",
					program_name, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			
#if 0
			if(!j) {
				anyaddr(said_af_array[i].af, &pfkey_address_s_ska); /* Is the address family correct ?? */
				if((error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
								SADB_EXT_ADDRESS_SRC,
								0,
								0,
								sockaddrof(&pfkey_address_s_ska)))) {
					addrtot(&pfkey_address_s_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
					fprintf(stderr, "%s: Trouble building address_s extension (%s), error=%d.\n",
						program_name, ipaddr_txt, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			}
#endif			
			if((error = pfkey_address_build(&extensions[!j ? SADB_EXT_ADDRESS_DST : SADB_X_EXT_ADDRESS_DST2],
							!j ? SADB_EXT_ADDRESS_DST : SADB_X_EXT_ADDRESS_DST2,
							0,
							0,
							sockaddrof(&said_af_array[i+j].said.dst)))) {
				addrtot(&said_af_array[i+j].said.dst,
					0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stderr, "%s: Trouble building address_d extension (%s), error=%d.\n",
					program_name, ipaddr_txt, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			
		}

		if((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
			fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n",
				program_name, error);
			pfkey_extensions_free(extensions);
			pfkey_msg_free(&pfkey_msg);
			exit(1);
		}
		
		if((error = write(pfkey_sock,
				  pfkey_msg,
				  pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) !=
		   (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
			fprintf(stderr, "%s: pfkey write failed, returning %d with errno=%d.\n",
				program_name, error, errno);
			pfkey_extensions_free(extensions);
			pfkey_msg_free(&pfkey_msg);
			switch(errno) {
			case EACCES:
				fprintf(stderr, "access denied.  ");
				if(getuid() == 0) {
					fprintf(stderr, "Check permissions.  Should be 600.\n");
				} else {
					fprintf(stderr, "You must be root to open this file.\n");
				}
				break;
			case EUNATCH:
				fprintf(stderr, "Netlink not enabled OR KLIPS not loaded.\n");
				break;
			case EBUSY:
				fprintf(stderr, "KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
				break;
			case EINVAL:
				fprintf(stderr, "Invalid argument, check kernel log messages for specifics.\n");
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
				fprintf(stderr, "SA already in use.  Delete old one first.\n");
				break;
			case ENOENT:
				fprintf(stderr, "device does not exist.  See FreeS/WAN installation procedure.\n");
				break;
			case ENXIO:
				fprintf(stderr, "SA does not exist.  Cannot delete.\n");
				break;
			case ENOSPC:
				fprintf(stderr, "no room in kernel SAref table.  Cannot process request.\n");
				break;
			case ESPIPE:
				fprintf(stderr, "kernel SAref table internal error.  Cannot process request.\n");
				break;
			default:
				fprintf(stderr, "Unknown socket write error %d.  Please report as much detail as possible to development team.\n", errno);
			}
			exit(1);
		}
		if(pfkey_msg) {
			pfkey_extensions_free(extensions);
			pfkey_msg_free(&pfkey_msg);
		}
	}

	(void) close(pfkey_sock);  /* close the socket */
	exit(0);
}
