/*
 * All-in-one program to set Security Association parameters
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002  Richard Guy Briggs.
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

char spi_c_version[] = "RCSID $Id: spi.c,v 1.7 2004/10/14 20:03:26 as Exp $";

#include <asm/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>
/* #include <linux/netdevice.h> */
#include <net/if.h>
/* #include <linux/types.h> */ /* new */
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* #include <sys/socket.h> */

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */
#include <netdb.h>

#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <freeswan.h>
#if 0
#include <linux/autoconf.h>    /* CONFIG_IPSEC_PFKEYv2 */
#endif
     #include <signal.h>
     #include <sys/socket.h>
     #include <pfkeyv2.h>
     #include <pfkey.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_ipe4.h"
#include "freeswan/ipsec_ah.h"
#include "freeswan/ipsec_esp.h"
#include "freeswan/ipsec_sa.h"  /* IPSEC_SAREF_NULL */

/* 	
 * 	Manual conn support for ipsec_alg (modular algos).
 * 	Rather ugly to include from pluto dir but avoids
 * 	code duplication.
 */
#ifndef NO_KERNEL_ALG
#include "../pluto/alg_info.h"
#include "../pluto/constants.h"
struct connection;
#include "../pluto/kernel_alg.h"
#endif /* NO_KERNEL_ALG */

char *program_name;
int debug = 0;
int saref = 0;
char *command;
extern char *optarg;
extern int optind, opterr, optopt;
char scratch[2];
char *iv = NULL, *enckey = NULL, *authkey = NULL;
size_t ivlen = 0, enckeylen = 0, authkeylen = 0;
ip_address edst, dst, src;
int address_family = 0;
unsigned char proto = 0;
int alg = 0;

#ifndef NO_KERNEL_ALG
/* 
 * 	Manual connection support for modular algos (ipsec_alg) --Juanjo.
 */
#define XF_OTHER_ALG (XF_CLR-1)	/* define magic XF_ symbol for alg_info's */
#include <assert.h>
const char *alg_string = NULL;	/* algorithm string */
struct alg_info_esp *alg_info = NULL;	/* algorithm info got from string */
struct esp_info *esp_info = NULL;	/* esp info from 1st (only) element */
const char *alg_err;		/* auxiliar for parsing errors */
int proc_read_ok = 0;		/* /proc/net/pf_key_support read ok */
#endif /* NO_KERNEL_ALG */

int replay_window = 0;
char sa[SATOT_BUF];

extern unsigned int pfkey_lib_debug; /* used by libfreeswan/pfkey_v2_build */
int pfkey_sock;
fd_set pfkey_socks;
uint32_t pfkey_seq = 0;
enum life_severity {
	life_soft = 0,
	life_hard = 1,
	life_maxsever = 2
};
enum life_type {
	life_alloc = 0,
	life_bytes = 1,
	life_addtime = 2,
	life_usetime = 3,
	life_packets = 4,
	life_maxtype = 5
};

#define streql(_a,_b) (!strcmp((_a),(_b)))

static const char *usage_string = "\
Usage:\n\
	in the following, <SA> is: --af <inet | inet6> --edst <dstaddr> --spi <spi> --proto <proto>\n\
                               OR: --said <proto><.|:><spi>@<dstaddr>\n\
	                  <life> is: --life <soft|hard>-<allocations|bytes|addtime|usetime|packets>=<value>[,...]\n\
spi --clear\n\
spi --help\n\
spi --version\n\
spi\n\
spi --del <SA>\n\
spi --ip4 <SA> --src <encap-src> --dst <encap-dst>\n\
spi --ip6 <SA> --src <encap-src> --dst <encap-dst>\n\
spi --ah <algo> <SA> [<life> ][ --replay_window <replay_window> ] --authkey <key>\n\
	where <algo> is one of:	hmac-md5-96 | hmac-sha1-96\n\
spi --esp <algo> <SA> [<life> ][ --replay_window <replay-window> ] --enckey <ekey> --authkey <akey>\n\
	where <algo> is one of:	3des-md5-96 | 3des-sha1-96\n\
spi --esp <algo> <SA> [<life> ][ --replay_window <replay-window> ] --enckey <ekey>\n\
	where <algo> is:	3des\n\
spi --comp <algo> <SA>\n\
	where <algo> is:	deflate\n\
[ --debug ] is optional to any spi command.\n\
[ --label <label> ] is optional to any spi command.\n\
[ --listenreply ]   is optional, and causes the command to stick\n\
                    around and listen to what the PF_KEY socket says.\n\
";


static void
usage(char *s, FILE *f)
{
	/* s argument is actually ignored, at present */
	fprintf(f, "%s:%s", s, usage_string);
	exit(-1);
}

int
parse_life_options(uint32_t life[life_maxsever][life_maxtype],
		   char *life_opt[life_maxsever][life_maxtype],
		   char *optarg)
{
	char *optargp = optarg;
	char *endptr;
	
	do {
		int life_severity, life_type;
		char *optargt = optargp;
		
		if(strncmp(optargp, "soft", sizeof("soft")-1) == 0) {
			life_severity = life_soft;
			optargp += sizeof("soft")-1;
		} else if(strncmp(optargp, "hard", sizeof("hard")-1) == 0) {
			life_severity = life_hard;
			optargp += sizeof("hard")-1;
		} else {
			fprintf(stderr,
				"%s: missing lifetime severity in %s, optargt=0p%p, optargp=0p%p, sizeof(\"soft\")=%d\n",
				program_name,
				optargt,
				optargt,
				optargp,
				(int)sizeof("soft"));
			usage(program_name, stderr);
			return(1);
		}
		if(debug) {
			fprintf(stdout,
				"%s: debug: life_severity=%d, optargt=0p%p=\"%s\", optargp=0p%p=\"%s\", sizeof(\"soft\")=%d\n",
				program_name,
				life_severity,
				optargt,
				optargt,
				optargp,
				optargp,
				(int)sizeof("soft"));
		}
		if(*(optargp++) != '-') {
			fprintf(stderr,
				"%s: expected '-' after severity of lifetime parameter to --life option.\n",
				program_name);
			usage(program_name, stderr);
			return(1);
		}
		if(debug) {
			fprintf(stdout,
				"%s: debug: optargt=0p%p=\"%s\", optargp=0p%p=\"%s\", strlen(optargt)=%d, strlen(optargp)=%d, strncmp(optargp, \"addtime\", sizeof(\"addtime\")-1)=%d\n",
				program_name,
				optargt,
				optargt,
				optargp,
				optargp,
				(int)strlen(optargt),
				(int)strlen(optargp),
				strncmp(optargp, "addtime", sizeof("addtime")-1));
		}
		if(strncmp(optargp, "allocations", sizeof("allocations")-1) == 0) {
			life_type = life_alloc;
			optargp += sizeof("allocations")-1;
		} else if(strncmp(optargp, "bytes", sizeof("bytes")-1) == 0) {
			life_type = life_bytes;
			optargp += sizeof("bytes")-1;
		} else if(strncmp(optargp, "addtime", sizeof("addtime")-1) == 0) {
			life_type = life_addtime;
			optargp += sizeof("addtime")-1;
		} else if(strncmp(optargp, "usetime", sizeof("usetime")-1) == 0) {
			life_type = life_usetime;
			optargp += sizeof("usetime")-1;
		} else if(strncmp(optargp, "packets", sizeof("packets")-1) == 0) {
			life_type = life_packets;
			optargp += sizeof("packets")-1;
		} else {
			fprintf(stderr,
				"%s: missing lifetime type after '-' in %s\n",
				program_name,
				optargt);
			usage(program_name, stderr);
			return(1);
		}
		if(debug) {
			fprintf(stdout,
				"%s: debug: life_type=%d\n",
				program_name,
				life_type);
		}
		if(life_opt[life_severity][life_type] != NULL) {
			fprintf(stderr,
				"%s: Error, lifetime parameter redefined:%s, already defined as:0p%p\n",
				program_name,
				optargt,
				life_opt[life_severity][life_type]);
			return(1);
		}
		if(*(optargp++) != '=') {
			fprintf(stderr,
				"%s: expected '=' after type of lifetime parameter to --life option.\n",
				program_name);
			usage(program_name, stderr);
			return(1);
		}
		if(debug) {
			fprintf(stdout,
				"%s: debug: optargt=0p%p, optargt+strlen(optargt)=0p%p, optargp=0p%p, strlen(optargp)=%d\n",
				program_name,
				optargt,
				optargt+strlen(optargt),
				optargp,
				(int)strlen(optargp));
		}
		if(strlen(optargp) == 0) {
			fprintf(stderr,
				"%s: expected value after '=' in --life option. optargt=0p%p, optargt+strlen(optargt)=0p%p, optargp=0p%p\n",
				program_name,
				optargt,
				optargt+strlen(optargt),
				optargp);
			usage(program_name, stderr);
			return(1);
		}
		life[life_severity][life_type] = strtoul(optargp, &endptr, 0);

		if(!((endptr == optargp + strlen(optargp)) || (endptr == optargp + strcspn(optargp, ", ")))) {
			fprintf(stderr,
				"%s: Invalid character='%c' at offset %d in lifetime option parameter: '%s', parameter string is %d characters long, %d valid value characters found.\n",
				program_name,
				*endptr,
				(int)(endptr - optarg),
				optarg,
				(int)strlen(optarg),
				(int)(strcspn(optargp, ", ") - 1));
			return(1);
		}
		life_opt[life_severity][life_type] = optargt;
		if(debug) {
			fprintf(stdout, "%s lifetime %s set to %d.\n",
				program_name, optargt, life[life_severity][life_type]);
		}
		optargp=endptr+1;
	} while(*endptr==',' || isspace(*endptr));
	
	return(0);
}

int
pfkey_register(uint8_t satype) {
	/* for registering SA types that can be negotiated */
	int error;
	ssize_t wlen;
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;

	pfkey_extensions_init(extensions);
	error = pfkey_msg_hdr_build(&extensions[0],
				    SADB_REGISTER,
				    satype,
				    0,
				    ++pfkey_seq,
				    getpid());
	if(error != 0) {
		fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		return(1);
	}

	error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);
	if(error != 0) {
		fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		return(1);
	}
	wlen = write(pfkey_sock, pfkey_msg,
		     pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);
	if(wlen != (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		/* cleanup code here */
		if(wlen < 0)
			fprintf(stderr, "%s: Trouble writing to channel PF_KEY: %s\n",
				program_name,
				strerror(errno));
		else
			fprintf(stderr, "%s: write to channel PF_KEY truncated.\n",
				program_name);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		return(1);
	}
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
	
	return(0);
}

static struct option const longopts[] =
{
	{"ah", 1, 0, 'H'},
	{"esp", 1, 0, 'P'},
	{"comp", 1, 0, 'Z'},
	{"ip4", 0, 0, '4'},
	{"ip6", 0, 0, '6'},
	{"del", 0, 0, 'd'},

	{"authkey", 1, 0, 'A'},
	{"enckey", 1, 0, 'E'},
	{"edst", 1, 0, 'e'},
	{"spi", 1, 0, 's'},
	{"proto", 1, 0, 'p'},
	{"af", 1, 0, 'a'},
	{"replay_window", 1, 0, 'w'},
	{"iv", 1, 0, 'i'},
	{"dst", 1, 0, 'D'},
	{"src", 1, 0, 'S'},
	{"said", 1, 0, 'I'},

	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"clear", 0, 0, 'c'},
	{"label", 1, 0, 'l'},
	{"debug", 0, 0, 'g'},
	{"optionsfrom", 1, 0, '+'},
	{"life", 1, 0, 'f'},
	{"saref", 0, 0, 'r'},
	{"listenreply", 0, 0, 'R'},
	{0, 0, 0, 0}
};

int
main(int argc, char *argv[])
{
	char *endptr;
	__u32 spi = 0;
	int c, previous = -1;
/*	int ret; */
	ip_said said;
	size_t sa_len;
	const char* error_s;
	char ipaddr_txt[ADDRTOT_BUF];
	char ipsaid_txt[SATOT_BUF];

	int error = 0;
	ssize_t io_error;
	int argcount = argc;
	pid_t mypid;
	int listenreply = 0;

	unsigned char authalg, encryptalg;
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
	char *iv_opt, *akey_opt, *ekey_opt, *alg_opt, *edst_opt, *spi_opt, *proto_opt, *af_opt, *said_opt, *dst_opt, *src_opt;
#if 0
	ip_address pfkey_address_p_ska;
	ip_address pfkey_ident_s_ska;
	ip_address pfkey_ident_d_ska;
#endif
	uint32_t life[life_maxsever][life_maxtype];
	char *life_opt[life_maxsever][life_maxtype];
	
	program_name = argv[0];
	mypid = getpid();

	memset(&said, 0, sizeof(said));
	iv_opt = akey_opt = ekey_opt = alg_opt = edst_opt = spi_opt = proto_opt = af_opt = said_opt = dst_opt = src_opt = NULL;
	{
		int i,j;
		for(i = 0; i < life_maxsever; i++) {
			for(j = 0; j < life_maxtype; j++) {
				life_opt[i][j] = NULL;
				life[i][j] = 0;
			}
		}
	}

	while((c = getopt_long(argc, argv, ""/*"H:P:Z:46dcA:E:e:s:a:w:i:D:S:hvgl:+:f:"*/, longopts, 0)) != EOF) {
		switch(c) {
		case 'g':
			debug = 1;
			pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
			argcount--;
			break;

		case 'R':
			listenreply = 1;
			argcount--;
			break;

		case 'r':
			saref = 1;
			argcount--;
			break;

		case 'l':
			program_name = malloc(strlen(argv[0])
					      + 10 /* update this when changing the sprintf() */
					      + strlen(optarg));
			sprintf(program_name, "%s --label %s",
				argv[0],
				optarg);
			argcount -= 2;
			break;
		case 'H':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					program_name);
				exit(1);
			}
			if       (!strcmp(optarg, "hmac-md5-96")) {
				alg = XF_AHHMACMD5;
			} else if(!strcmp(optarg, "hmac-sha1-96")) {
				alg = XF_AHHMACSHA1;
			} else {
				fprintf(stderr, "%s: Unknown authentication algorithm '%s' follows '--ah' option.\n",
					program_name, optarg);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case 'P':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					program_name);
				exit(1);
			}
			if       (!strcmp(optarg, "3des-md5-96")) {
				alg = XF_ESP3DESMD596;
			} else if(!strcmp(optarg, "3des-sha1-96")) {
				alg = XF_ESP3DESSHA196;
			} else if(!strcmp(optarg, "3des")) {
				alg = XF_ESP3DES;
#ifndef NO_KERNEL_ALG
			} else if((alg_info=alg_info_esp_create_from_str(optarg, &alg_err))) {
				int esp_ealg_id, esp_aalg_id;
				alg = XF_OTHER_ALG;
				if (alg_info->alg_info_cnt>1) {
					fprintf(stderr, "%s: Invalid encryption algorithm '%s' "
						"follows '--esp' option: lead too many(%d) "
						"transforms\n",
						program_name, optarg, alg_info->alg_info_cnt);
					exit(1);
				}
				alg_string=optarg;
				esp_info=&alg_info->esp[0];
				if (debug) {
					fprintf(stdout, "%s: alg_info: cnt=%d ealg[0]=%d aalg[0]=%d\n",
						program_name, 
						alg_info->alg_info_cnt,
						esp_info->encryptalg,
						esp_info->authalg);
				}
				esp_ealg_id=esp_info->esp_ealg_id;
				esp_aalg_id=esp_info->esp_aalg_id;
				if (kernel_alg_proc_read()==0) {
					proc_read_ok++;
					if (!kernel_alg_esp_enc_ok(esp_ealg_id, 0, 0))
					{
						fprintf(stderr, "%s: ESP encryptalg=%d (\"%s\") "
								"not present\n",
							program_name,
							esp_ealg_id,
							enum_name(&esp_transformid_names, esp_ealg_id));
						exit(1);
					}
					if (!kernel_alg_esp_auth_ok(esp_aalg_id, 0))
					{
						fprintf(stderr, "%s: ESP authalg=%d (\"%s\")"
								"not present\n",
							program_name,
							esp_aalg_id,
							enum_name(&auth_alg_names, esp_aalg_id));
						exit(1);
					}
				}
#endif /* NO_KERNEL_ALG */
			} else {
				fprintf(stderr, "%s: Invalid encryption algorithm '%s' follows '--esp' option.\n",
					program_name, optarg);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case 'Z':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					program_name);
				exit(1);
			}
			if       (!strcmp(optarg, "deflate")) {
				alg = XF_COMPDEFLATE;
			} else {
				fprintf(stderr, "%s: Unknown compression algorithm '%s' follows '--comp' option.\n",
					program_name, optarg);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case '4':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear' options permitted.\n",
					program_name);
				exit(1);
			}
		       	alg = XF_IP4;
			address_family = AF_INET;
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case '6':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear' options permitted.\n",
					program_name);
				exit(1);
			}
		       	alg = XF_IP6;
			address_family = AF_INET6;
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case 'd':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					program_name);
				exit(1);
			}
			alg = XF_DEL;
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case 'c':
			if(alg) {
				fprintf(stderr, "%s: Only one of '--ah', '--esp', '--comp', '--ip4', '--ip6', '--del' or '--clear'  options permitted.\n",
					program_name);
				exit(1);
			}
			alg = XF_CLR;
			if(debug) {
				fprintf(stdout, "%s: Algorithm %d selected.\n",
					program_name,
					alg);
			}
			alg_opt = optarg;
			break;
		case 'e':
			if(said_opt) {
				fprintf(stderr, "%s: Error, EDST parameter redefined:%s, already defined in SA:%s\n",
					program_name, optarg, said_opt);
				exit (1);
			}				
			if(edst_opt) {
				fprintf(stderr, "%s: Error, EDST parameter redefined:%s, already defined as:%s\n",
					program_name, optarg, edst_opt);
				exit (1);
			}
			error_s = ttoaddr(optarg, 0, address_family, &edst);
			if(error_s != NULL) {
				if(error_s) {
					fprintf(stderr, "%s: Error, %s converting --edst argument:%s\n",
						program_name, error_s, optarg);
					exit (1);
				}
			}
			edst_opt = optarg;
			if(debug) {
				addrtot(&edst, 0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stdout, "%s: edst=%s.\n",
					program_name,
					ipaddr_txt);
			}
			break;
		case 's':
			if(said_opt) {
				fprintf(stderr, "%s: Error, SPI parameter redefined:%s, already defined in SA:%s\n",
					program_name, optarg, said_opt);
				exit (1);
			}				
			if(spi_opt) {
				fprintf(stderr, "%s: Error, SPI parameter redefined:%s, already defined as:%s\n",
					program_name, optarg, spi_opt);
				exit (1);
			}				
			spi = strtoul(optarg, &endptr, 0);
			if(!(endptr == optarg + strlen(optarg))) {
				fprintf(stderr, "%s: Invalid character in SPI parameter: %s\n",
					program_name, optarg);
				exit (1);
			}
			if(spi < 0x100) {
				fprintf(stderr, "%s: Illegal reserved spi: %s => 0x%x Must be larger than 0x100.\n",
					program_name, optarg, spi);
				exit(1);
			}
			spi_opt = optarg;
			break;
		case 'p':
			if(said_opt) {
				fprintf(stderr, "%s: Error, PROTO parameter redefined:%s, already defined in SA:%s\n",
					program_name, optarg, said_opt);
				exit (1);
			}				
			if(proto_opt) {
				fprintf(stderr, "%s: Error, PROTO parameter redefined:%s, already defined as:%s\n",
					program_name, optarg, proto_opt);
				exit (1);
			}
			if(!strcmp(optarg, "ah"))
				proto = SA_AH;
			if(!strcmp(optarg, "esp"))
				proto = SA_ESP;
			if(!strcmp(optarg, "tun"))
				proto = SA_IPIP;
			if(!strcmp(optarg, "comp"))
				proto = SA_COMP;
			if(proto == 0) {
				fprintf(stderr, "%s: Invalid PROTO parameter: %s\n",
					program_name, optarg);
				exit (1);
			}
			proto_opt = optarg;
			break;
		case 'a':
			if(said_opt) {
				fprintf(stderr, "%s: Error, ADDRESS FAMILY parameter redefined:%s, already defined in SA:%s\n",
					program_name, optarg, said_opt);
				exit (1);
			}				
			if(af_opt) {
				fprintf(stderr, "%s: Error, ADDRESS FAMILY parameter redefined:%s, already defined as:%s\n",
					program_name, optarg, af_opt);
				exit (1);
			}
			if(strcmp(optarg, "inet") == 0) {
				address_family = AF_INET;
				/* currently we ensure that all addresses belong to the same address family */
				anyaddr(address_family, &dst);
				anyaddr(address_family, &edst);
				anyaddr(address_family, &src);
			}
			if(strcmp(optarg, "inet6") == 0) {
				address_family = AF_INET6;
				/* currently we ensure that all addresses belong to the same address family */
				anyaddr(address_family, &dst);
				anyaddr(address_family, &edst);
				anyaddr(address_family, &src);
			}
			if((strcmp(optarg, "inet") != 0) && (strcmp(optarg, "inet6") != 0)) {
				fprintf(stderr, "%s: Invalid ADDRESS FAMILY parameter: %s.\n",
					program_name, optarg);
				exit (1);
			}
			af_opt = optarg;
			break;
		case 'I':
			if(said_opt) {
				fprintf(stderr, "%s: Error, SAID parameter redefined:%s, already defined in SA:%s\n",
					program_name, optarg, said_opt);
				exit (1);
			}				
			if(proto_opt) {
				fprintf(stderr, "%s: Error, PROTO parameter redefined in SA:%s, already defined as:%s\n",
					program_name, optarg, proto_opt);
				exit (1);
			}
			if(edst_opt) {
				fprintf(stderr, "%s: Error, EDST parameter redefined in SA:%s, already defined as:%s\n",
					program_name, optarg, edst_opt);
				exit (1);
			}
			if(spi_opt) {
				fprintf(stderr, "%s: Error, SPI parameter redefined in SA:%s, already defined as:%s\n",
					program_name, optarg, spi_opt);
				exit (1);
			}
			error_s = ttosa(optarg, 0, &said);
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting --sa argument:%s\n",
					program_name, error_s, optarg);
				exit (1);
			}
			if(debug) {
				satot(&said, 0, ipsaid_txt, sizeof(ipsaid_txt));
				fprintf(stdout, "%s: said=%s.\n",
					program_name,
					ipsaid_txt);
			}
			/* init the src and dst with the same address family */
			if(address_family == 0) {
				address_family = addrtypeof(&said.dst);
			} else if(address_family != addrtypeof(&said.dst)) {
				fprintf(stderr, "%s: Error, specified address family (%d) is different that of SAID: %s\n",
					program_name, address_family, optarg);
				exit (1);
			}
			anyaddr(address_family, &dst);
			anyaddr(address_family, &edst);
			anyaddr(address_family, &src);
			said_opt = optarg;
			break;
		case 'A':
			if(optarg[0] == '0') {
				switch(optarg[1]) {
				case 't':
				case 'x':
				case 's':
					break;
				default:
					fprintf(stderr, "%s: Authentication key must have a '0x', '0t' or '0s' prefix to select the format: %s\n",
						program_name, optarg);
					exit(1);
				}
			}
			authkeylen = atodata(optarg, 0, NULL, 0);
			if(!authkeylen) {
				fprintf(stderr, "%s: unknown format or syntax error in authentication key: %s\n",
					program_name, optarg);
				exit (1);
			}
			authkey = malloc(authkeylen);
			if(authkey == NULL) {
				fprintf(stderr, "%s: Memory allocation error.\n", program_name);
				exit(1);
			}
			memset(authkey, 0, authkeylen);
			authkeylen = atodata(optarg, 0, authkey, authkeylen);
			akey_opt = optarg;
			break;
		case 'E':
			if(optarg[0] == '0') {
				switch(optarg[1]) {
				case 't':
				case 'x':
				case 's':
					break;
				default:
					fprintf(stderr, "%s: Encryption key must have a '0x', '0t' or '0s' prefix to select the format: %s\n",
						program_name, optarg);
					exit(1);
				}
			}
			enckeylen = atodata(optarg, 0, NULL, 0);
			if(!enckeylen) {
				fprintf(stderr, "%s: unknown format or syntax error in encryption key: %s\n",
					program_name, optarg);
				exit (1);
			}
			enckey = malloc(enckeylen);
			if(enckey == NULL) {
				fprintf(stderr, "%s: Memory allocation error.\n", program_name);
				exit(1);
			}
			memset(enckey, 0, enckeylen);
			enckeylen = atodata(optarg, 0, enckey, enckeylen);
			ekey_opt = optarg;
			break;
		case 'w':
			replay_window = strtoul(optarg, &endptr, 0);
			if(!(endptr == optarg + strlen(optarg))) {
				fprintf(stderr, "%s: Invalid character in replay_window parameter: %s\n",
					program_name, optarg);
				exit (1);
			}
			if((replay_window < 0x1) || (replay_window > 64)) {
				fprintf(stderr, "%s: Failed -- Illegal window size: arg=%s, replay_window=%d, must be 1 <= size <= 64.\n",
					program_name, optarg, replay_window);
				exit(1);
			}
			break;
		case 'i':
			if(optarg[0] == '0') {
				switch(optarg[1]) {
				case 't':
				case 'x':
				case 's':
					break;
				default:
					fprintf(stderr, "%s: IV must have a '0x', '0t' or '0s' prefix to select the format, found '%c'.\n",
						program_name, optarg[1]);
					exit(1);
				}
			}
			ivlen = atodata(optarg, 0, NULL, 0);
			if(!ivlen) {
				fprintf(stderr, "%s: unknown format or syntax error in IV: %s\n",
					program_name, optarg);
				exit (1);
			}
			iv = malloc(ivlen);
			if(iv == NULL) {
				fprintf(stderr, "%s: Memory allocation error.\n", program_name);
				exit(1);
			}
			memset(iv, 0, ivlen);
			ivlen = atodata(optarg, 0, iv, ivlen);
			iv_opt = optarg;
			break;
		case 'D':
			if(dst_opt) {
				fprintf(stderr, "%s: Error, DST parameter redefined:%s, already defined as:%s\n",
					program_name, optarg, dst_opt);
				exit (1);
			}				
			error_s = ttoaddr(optarg, 0, address_family, &dst);
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting --dst argument:%s\n",
					program_name, error_s, optarg);
				exit (1);
			}
			dst_opt = optarg;
			if(debug) {
				addrtot(&dst, 0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stdout, "%s: dst=%s.\n",
					program_name,
					ipaddr_txt);
			}
			break;
		case 'S':
			if(src_opt) {
				fprintf(stderr, "%s: Error, SRC parameter redefined:%s, already defined as:%s\n",
					program_name, optarg, src_opt);
				exit (1);
			}				
			error_s = ttoaddr(optarg, 0, address_family, &src);
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting --src argument:%s\n",
					program_name, error_s, optarg);
				exit (1);
			}
			src_opt = optarg;
			if(debug) {
				addrtot(&src, 0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stdout, "%s: src=%s.\n",
					program_name,
					ipaddr_txt);
			}
			break;
		case 'h':
			usage(program_name, stdout);
			exit(0);
		case '?':
			usage(program_name, stderr);
			exit(1);
		case 'v':
			fprintf(stdout, "%s, %s\n", program_name, spi_c_version);
			exit(1);
		case '+': /* optionsfrom */
			optionsfrom(optarg, &argc, &argv, optind, stderr);
			/* no return on error */
			break;
		case 'f':
			if(parse_life_options(life,
					   life_opt,
					   optarg) != 0) {
				exit(1);
			};
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%c', update option processing.\n",
				program_name, c);
			exit(1);
		}
		previous = c;
	}
	if(debug) {
		fprintf(stdout, "%s: All options processed.\n",
				program_name);
	}

	if(argcount == 1) {
		system("cat /proc/net/ipsec_spi");
		exit(0);
	}

	switch(alg) {
#ifndef NO_KERNEL_ALG
	case XF_OTHER_ALG: 
		/* validate keysizes */
		if (proc_read_ok) {
		       const struct sadb_alg *alg_p;
		       size_t keylen, minbits, maxbits;

		       alg_p=kernel_alg_sadb_alg_get(SADB_SATYPE_ESP,SADB_EXT_SUPPORTED_ENCRYPT, 
				       esp_info->encryptalg);
		       assert(alg_p);
		       keylen=enckeylen * 8;

		       if (alg_p->sadb_alg_id==ESP_3DES || alg_p->sadb_alg_id==ESP_DES) {
			       maxbits=minbits=alg_p->sadb_alg_minbits * 8 /7;
		       } else {
			       minbits=alg_p->sadb_alg_minbits;
			       maxbits=alg_p->sadb_alg_maxbits;
		       }
		       /* 
			* if explicit keylen told in encrypt algo, eg "aes128"
			* check actual keylen "equality"
			*/
		       if (esp_info->esp_ealg_keylen &&
			       esp_info->esp_ealg_keylen!=keylen) {
			       fprintf(stderr, "%s: invalid encryption keylen=%d, "
					       "required %d by encrypt algo string=\"%s\"\n",
				       program_name, 
				       (int)keylen,
				       (int)esp_info->esp_ealg_keylen,
				       alg_string);
			       exit(1);

		       }
		       /* thanks DES for this sh*t */

		       if (minbits > keylen || maxbits < keylen) {
			       fprintf(stderr, "%s: invalid encryption keylen=%d, "
					       "must be between %d and %d bits\n",
					       program_name, 
					       (int)keylen, (int)minbits, (int)maxbits);
			       exit(1);
		       }
		       alg_p=kernel_alg_sadb_alg_get(SADB_SATYPE_ESP,SADB_EXT_SUPPORTED_AUTH, 
				       esp_info->authalg);
		       assert(alg_p);
		       keylen=authkeylen * 8;
		       minbits=alg_p->sadb_alg_minbits;
		       maxbits=alg_p->sadb_alg_maxbits;
		       if (minbits > keylen || maxbits < keylen) {
			       fprintf(stderr, "%s: invalid auth keylen=%d, "
					       "must be between %d and %d bits\n",
					       program_name, 
					       (int)keylen, (int)minbits, (int)maxbits);
			       exit(1);
		       }

		}
#endif /* NO_KERNEL_ALG */
	case XF_IP4:
	case XF_IP6:
	case XF_DEL:
	case XF_AHHMACMD5:
	case XF_AHHMACSHA1:
	case XF_ESP3DESMD596:
	case XF_ESP3DESSHA196:
	case XF_ESP3DES:
	case XF_COMPDEFLATE:
		if(!said_opt) {
			if(isanyaddr(&edst)) {
				fprintf(stderr, "%s: SA destination not specified.\n",
					program_name);
				exit(1);
			}
			if(!spi) {
				fprintf(stderr, "%s: SA SPI not specified.\n",
					program_name);
				exit(1);
			}
			if(!proto) {
				fprintf(stderr, "%s: SA PROTO not specified.\n",
					program_name);
				exit(1);
			}
			initsaid(&edst, htonl(spi), proto, &said);
		} else {
			proto = said.proto;
			spi = ntohl(said.spi);
			edst = said.dst;
		}
		if((address_family != 0) && (address_family != addrtypeof(&said.dst))) {
			fprintf(stderr, "%s: Defined address family and address family of SA missmatch.\n",
				program_name);
			exit(1);
		}
		sa_len = satot(&said, 0, sa, sizeof(sa));

		if(debug) {
			fprintf(stdout, "%s: SA valid.\n",
				program_name);
		}
		break;
	case XF_CLR:
		break;
	default:
		fprintf(stderr, "%s: No action chosen.  See '%s --help' for usage.\n",
			program_name, program_name);
		exit(1);
	}

	switch(alg) {
	case XF_CLR:
	case XF_DEL:
	case XF_IP4:
	case XF_IP6:
	case XF_AHHMACMD5:
	case XF_AHHMACSHA1:
	case XF_ESP3DESMD596:
	case XF_ESP3DESSHA196:
	case XF_ESP3DES:
	case XF_COMPDEFLATE:
#ifndef NO_KERNEL_ALG
	case XF_OTHER_ALG:
#endif /* NO_KERNEL_ALG */
		break;
	default:
		fprintf(stderr, "%s: No action chosen.  See '%s --help' for usage.\n",
			program_name, program_name);
		exit(1);
	}
	if(debug) {
		fprintf(stdout, "%s: Algorithm ok.\n",
			program_name);
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

#ifdef MANUAL_IS_NOT_ABLE_TO_NEGOTIATE
	/* for registering SA types that can be negotiated */
	if(pfkey_register(SADB_SATYPE_AH) != 0) {
		exit(1);
	}
	if(pfkey_register(SADB_SATYPE_ESP) != 0) {
		exit(1);
	}
	if(pfkey_register(SADB_X_SATYPE_IPIP) != 0) {
		exit(1);
	}
	if(pfkey_register(SADB_X_SATYPE_COMP) != 0) {
		exit(1);
	}
#endif /* MANUAL_IS_NOT_ABLE_TO_NEGOTIATE */

	/* Build an SADB_ADD message to send down. */
	/* It needs <base, SA, address(SD), key(AE)> minimum. */
	/*   Lifetime(HS) could be added before addresses. */
	pfkey_extensions_init(extensions);
	if(debug) {
		fprintf(stdout, "%s: extensions=0p%p &extensions=0p%p extensions[0]=0p%p &extensions[0]=0p%p cleared.\n",
			program_name,
			extensions,
			&extensions,
			extensions[0],
			&extensions[0]);
	}
	if((error = pfkey_msg_hdr_build(&extensions[0],
					(alg == XF_DEL ? SADB_DELETE : alg == XF_CLR ? SADB_FLUSH : SADB_ADD),
					proto2satype(proto),
					0,
					++pfkey_seq,
					mypid))) {
		fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}
	if(debug) {
		fprintf(stdout, "%s: extensions=0p%p &extensions=0p%p extensions[0]=0p%p &extensions[0]=0p%p set w/msghdr.\n",
			program_name,
			extensions,
			&extensions,
			extensions[0],
			&extensions[0]);
	}
	if(debug) {
		fprintf(stdout, "%s: base message assembled.\n", program_name);
	}
	
	switch(alg) {
	case XF_AHHMACMD5:
	case XF_ESP3DESMD596:
		authalg = SADB_AALG_MD5_HMAC;
		break;
	case XF_AHHMACSHA1:
	case XF_ESP3DESSHA196:
		authalg = SADB_AALG_SHA1_HMAC;
		break;
#ifndef NO_KERNEL_ALG
	case XF_OTHER_ALG:
		authalg= esp_info->authalg;
		if(debug) {
			fprintf(stdout, "%s: debug: authalg=%d\n",
				program_name, authalg);
		}
		break;
#endif /* NO_KERNEL_ALG */
	case XF_ESP3DESMD5:
	default:
		authalg = SADB_AALG_NONE;
	}
	switch(alg) {
	case XF_ESP3DES:
	case XF_ESP3DESMD596:
	case XF_ESP3DESSHA196:
		encryptalg = SADB_EALG_3DES_CBC;
		break;
	case XF_COMPDEFLATE:
		encryptalg = SADB_X_CALG_DEFLATE;
		break;
#ifndef NO_KERNEL_ALG
	case XF_OTHER_ALG:
		encryptalg= esp_info->encryptalg;
		if(debug) {
			fprintf(stdout, "%s: debug: encryptalg=%d\n",
				program_name, encryptalg);
		}
		break;
#endif /* NO_KERNEL_ALG */
	default:
		encryptalg = SADB_EALG_NONE;
	}
	if(!(alg == XF_CLR /* IE: pfkey_msg->sadb_msg_type == SADB_FLUSH */)) {
		if((error = pfkey_sa_build(&extensions[SADB_EXT_SA],
					   SADB_EXT_SA,
					   htonl(spi), /* in network order */
					   replay_window,
					   SADB_SASTATE_MATURE,
					   authalg,
					   encryptalg,
					   0))) {
			fprintf(stderr, "%s: Trouble building sa extension, error=%d.\n",
				program_name, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if(debug) {
			fprintf(stdout, "%s: extensions[0]=0p%p previously set with msg_hdr.\n",
				program_name,
				extensions[0]);
		}
		if(debug) {
			fprintf(stdout, "%s: assembled SA extension, pfkey msg authalg=%d encalg=%d.\n",
				program_name,
				authalg,
				encryptalg);
		}
		
		if(debug) {
			int i,j;
			for(i = 0; i < life_maxsever; i++) {
				for(j = 0; j < life_maxtype; j++) {
					fprintf(stdout, "%s: i=%d, j=%d, life_opt[%d][%d]=0p%p, life[%d][%d]=%d\n",
						program_name,
						i, j, i, j, life_opt[i][j], i, j, life[i][j]);
				}
			}
		}
		if(life_opt[life_soft][life_alloc] != NULL ||
		   life_opt[life_soft][life_bytes] != NULL ||
		   life_opt[life_soft][life_addtime] != NULL ||
		   life_opt[life_soft][life_usetime] != NULL ||
		   life_opt[life_soft][life_packets] != NULL) {
			if((error = pfkey_lifetime_build(&extensions[SADB_EXT_LIFETIME_SOFT],
							 SADB_EXT_LIFETIME_SOFT,
							 life[life_soft][life_alloc],/*-1,*/		/*allocations*/
							 life[life_soft][life_bytes],/*-1,*/		/*bytes*/
							 life[life_soft][life_addtime],/*-1,*/		/*addtime*/
							 life[life_soft][life_usetime],/*-1,*/		/*usetime*/
							 life[life_soft][life_packets]/*-1*/))) {	/*packets*/
				fprintf(stderr, "%s: Trouble building lifetime_s extension, error=%d.\n",
					program_name, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: lifetime_s extension assembled.\n",
					program_name);
			}
		}

		if(life_opt[life_hard][life_alloc] != NULL ||
		   life_opt[life_hard][life_bytes] != NULL ||
		   life_opt[life_hard][life_addtime] != NULL ||
		   life_opt[life_hard][life_usetime] != NULL ||
		   life_opt[life_hard][life_packets] != NULL) {
			if((error = pfkey_lifetime_build(&extensions[SADB_EXT_LIFETIME_HARD],
							 SADB_EXT_LIFETIME_HARD,
							 life[life_hard][life_alloc],/*-1,*/		/*allocations*/
							 life[life_hard][life_bytes],/*-1,*/		/*bytes*/
							 life[life_hard][life_addtime],/*-1,*/		/*addtime*/
							 life[life_hard][life_usetime],/*-1,*/		/*usetime*/
							 life[life_hard][life_packets]/*-1*/))) {	/*packets*/
				fprintf(stderr, "%s: Trouble building lifetime_h extension, error=%d.\n",
					program_name, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: lifetime_h extension assembled.\n",
					program_name);
			}
		}
		
		if(debug) {
                	addrtot(&src, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stdout, "%s: assembling address_s extension (%s).\n",
				program_name, ipaddr_txt);
		}
	
		if((error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
						SADB_EXT_ADDRESS_SRC,
						0,
						0,
						sockaddrof(&src)))) {
                	addrtot(&src, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stderr, "%s: Trouble building address_s extension (%s), error=%d.\n",
				program_name, ipaddr_txt, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if(debug) {
			ip_address temp_addr;
			
			switch(address_family) {
				case AF_INET:
					initaddr((const unsigned char *)&(((struct sockaddr_in*)( ((struct sadb_address*)(extensions[SADB_EXT_ADDRESS_SRC])) + 1))->sin_addr),
						sockaddrlenof(&src), address_family, &temp_addr);
					break;
				case AF_INET6:
					initaddr((const unsigned char *)&(((struct sockaddr_in6*)( ((struct sadb_address*)(extensions[SADB_EXT_ADDRESS_SRC])) + 1))->sin6_addr),
						sockaddrlenof(&src), address_family, &temp_addr);
					break;
				default:
					fprintf(stdout, "%s: unknown address family (%d).\n",
						program_name, address_family);
					exit(1);
			}
                	addrtot(&temp_addr, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stdout, "%s: address_s extension assembled (%s).\n",
				program_name, ipaddr_txt);
		}
	
		if(debug) {
                	addrtot(&edst, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stdout, "%s: assembling address_d extension (%s).\n",
				program_name, ipaddr_txt);
		}
	
		if((error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST],
						SADB_EXT_ADDRESS_DST,
						0,
						0,
						sockaddrof(&edst)))) {
                	addrtot(&edst, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stderr, "%s: Trouble building address_d extension (%s), error=%d.\n",
				program_name, ipaddr_txt, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if(debug) {
			ip_address temp_addr;
			switch(address_family) {
				case AF_INET:
					initaddr((const unsigned char *)&(((struct sockaddr_in*)( ((struct sadb_address*)(extensions[SADB_EXT_ADDRESS_DST])) + 1))->sin_addr),
						4, address_family, &temp_addr);
					break;
				case AF_INET6:
					initaddr((const unsigned char *)&(((struct sockaddr_in6*)( ((struct sadb_address*)(extensions[SADB_EXT_ADDRESS_DST])) + 1))->sin6_addr),
						16, address_family, &temp_addr);
					break;
				default:
					fprintf(stdout, "%s: unknown address family (%d).\n",
						program_name, address_family);
					exit(1);
			}
                	addrtot(&temp_addr, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stdout, "%s: address_d extension assembled (%s).\n",
				program_name, ipaddr_txt);
		}

#if PFKEY_PROXY
		anyaddr(address_family, &pfkey_address_p_ska);
		if((error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_PROXY],
						SADB_EXT_ADDRESS_PROXY,
						0,
						0,
						sockaddrof(&pfkey_address_p_ska)))) {
			fprintf(stderr, "%s: Trouble building address_p extension, error=%d.\n",
				program_name, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if(debug) {
			fprintf(stdout, "%s: address_p extension assembled.\n", program_name);
		}
#endif /* PFKEY_PROXY */
		
		switch(alg) {
#ifndef NO_KERNEL_ALG
		/*	Allow no auth ... after all is local root decision 8)  */
		case XF_OTHER_ALG:
			if (!authalg)
				break;
#endif /* NO_KERNEL_ALG */
		case XF_AHHMACMD5:
		case XF_ESP3DESMD596:
		case XF_AHHMACSHA1:
		case XF_ESP3DESSHA196:
			if((error = pfkey_key_build(&extensions[SADB_EXT_KEY_AUTH],
						    SADB_EXT_KEY_AUTH,
						    authkeylen * 8,
						    authkey))) {
				fprintf(stderr, "%s: Trouble building key_a extension, error=%d.\n",
					program_name, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: key_a extension assembled.\n",
					program_name);
			}
			break;
		default:
			break;
		}
		
		switch(alg) {
		case XF_ESP3DES:
		case XF_ESP3DESMD596:
		case XF_ESP3DESSHA196:
#ifndef NO_KERNEL_ALG
		case XF_OTHER_ALG:
#endif /* NO_KERNEL_ALG */
			if((error = pfkey_key_build(&extensions[SADB_EXT_KEY_ENCRYPT],
						    SADB_EXT_KEY_ENCRYPT,
						    enckeylen * 8,
						    enckey))) {
				fprintf(stderr, "%s: Trouble building key_e extension, error=%d.\n",
					program_name, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			if(debug) {
				fprintf(stdout, "%s: key_e extension assembled.\n",
					program_name);
			}
			break;
		default:
			break;
		}
		
#ifdef PFKEY_IDENT /* GG: looks wierd, not touched */
		if((pfkey_ident_build(&extensions[SADB_EXT_IDENTITY_SRC],
				      SADB_EXT_IDENTITY_SRC,
				      SADB_IDENTTYPE_PREFIX,
				      0,
				      strlen(pfkey_ident_s_ska),
				      pfkey_ident_s_ska))) {
			fprintf(stderr, "%s: Trouble building ident_s extension, error=%d.\n",
				program_name, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if(subnettoa(addr, mask, format, pfkey_ident_s_ska,
			     sizeof(pfkey_ident_s_ska) ) !=
		   sizeof(pfkey_ident_s_ska) ) {
			exit (1);
		}
		
		if((error = pfkey_ident_build(&extensions[SADB_EXT_IDENTITY_DST],
					      SADB_EXT_IDENTITY_DST,
					      SADB_IDENTTYPE_PREFIX,
					      0,
					      strlen(pfkey_ident_d_ska),
					      pfkey_ident_d_ska))) {
			fprintf(stderr, "%s: Trouble building ident_d extension, error=%d.\n",
				program_name, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if(subnettoa(addr, mask, format, pfkey_ident_d_ska,
			     sizeof(pfkey_ident_d_ska) ) !=
		   sizeof(pfkey_ident_d_ska) ) {
			exit (1);
		}

		if(debug) {
			fprintf(stdout, "%s: ident extensions assembled.\n",
				program_name);
		}
#endif /* PFKEY_IDENT */
	}
	
	if(debug) {
		fprintf(stdout, "%s: assembling pfkey msg....\n",
			program_name);
	}
	if((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	if(debug) {
		fprintf(stdout, "%s: assembled.\n",
			program_name);
	}
	if(debug) {
		fprintf(stdout, "%s: writing pfkey msg.\n",
			program_name);
	}
	io_error = write(pfkey_sock,
			 pfkey_msg,
			 pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);
	if(io_error < 0) {
		fprintf(stderr, "%s: pfkey write failed (errno=%d): ",
			program_name, errno);
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
		case ESRCH:
			fprintf(stderr, "SA does not exist.  Cannot delete.\n");
			break;
		case ENOSPC:
			fprintf(stderr, "no room in kernel SAref table.  Cannot process request.\n");
			break;
		case ESPIPE:
			fprintf(stderr, "kernel SAref table internal error.  Cannot process request.\n");
			break;
		default:
			fprintf(stderr, "Unknown socket write error %d (%s).  Please report as much detail as possible to development team.\n",
				errno, strerror(errno));
		}
		exit(1);
	} else if (io_error != (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		fprintf(stderr, "%s: pfkey write truncated to %d bytes\n",
			program_name, (int)io_error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}

	if(debug) {
		fprintf(stdout, "%s: pfkey command written to socket.\n",
			program_name);
	}

	if(pfkey_msg) {
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
	}
	if(debug) {
		fprintf(stdout, "%s: pfkey message buffer freed.\n",
			program_name);
	}
	if(authkey) {
		memset((caddr_t)authkey, 0, authkeylen);
		free(authkey);
	}
	if(enckey) {
		memset((caddr_t)enckey, 0, enckeylen);
		free(enckey);
	}
	if(iv) {
		memset((caddr_t)iv, 0, ivlen);
		free(iv);
	}

	if(listenreply || saref) {
		ssize_t readlen;
		unsigned char pfkey_buf[PFKEYv2_MAX_MSGSIZE];
		
		while((readlen = read(pfkey_sock, pfkey_buf, sizeof(pfkey_buf))) > 0) {
			struct sadb_ext *extensions[SADB_EXT_MAX + 1];
			pfkey_extensions_init(extensions);
			pfkey_msg = (struct sadb_msg *)pfkey_buf;
			
			/* first, see if we got enough for an sadb_msg */
			if((size_t)readlen < sizeof(struct sadb_msg)) {
				if(debug) {
					printf("%s: runt packet of size: %ld (<%lu)\n",
					       program_name, (long)readlen, (unsigned long)sizeof(struct sadb_msg));
				}
				continue;
			}
			
			/* okay, we got enough for a message, print it out */
			if(debug) {
				printf("%s: pfkey v%d msg received. type=%d(%s) seq=%d len=%d pid=%d errno=%d satype=%d(%s)\n",
				       program_name,
				       pfkey_msg->sadb_msg_version,
				       pfkey_msg->sadb_msg_type,
				       pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type),
				       pfkey_msg->sadb_msg_seq,
				       pfkey_msg->sadb_msg_len,
				       pfkey_msg->sadb_msg_pid,
				       pfkey_msg->sadb_msg_errno,
				       pfkey_msg->sadb_msg_satype,
				       satype2name(pfkey_msg->sadb_msg_satype));
			}
			
			if(readlen != (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN))
			{
				if(debug) {
					printf("%s: packet size read from socket=%d doesn't equal sadb_msg_len %u * %u; message not decoded\n",
					       program_name,
					       (int)readlen, 
					       (unsigned)pfkey_msg->sadb_msg_len,
					       (unsigned)IPSEC_PFKEYv2_ALIGN);
				}
				continue;
			}
			
			if (pfkey_msg_parse(pfkey_msg, NULL, extensions, EXT_BITS_OUT)) {
				if(debug) {
					printf("%s: unparseable PF_KEY message.\n",
					       program_name);
				}
				continue;
			} else {
				if(debug) {
					printf("%s: parseable PF_KEY message.\n",
					       program_name);
				}
			}
			if((pid_t)pfkey_msg->sadb_msg_pid == mypid) {
				if(saref) {
					printf("%s: saref=%d\n",
					       program_name,
					       (extensions[SADB_EXT_SA] != NULL)
					       ? ((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_x_sa_ref
					       : IPSEC_SAREF_NULL);
				}
				break;
			}
		}
	}
	(void) close(pfkey_sock);  /* close the socket */
	if(debug || listenreply) {
		printf("%s: exited normally\n", program_name);
	}
	exit(0);
}
