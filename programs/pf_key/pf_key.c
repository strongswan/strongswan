/*
 * @(#) pfkey socket manipulator/observer
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
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
 * RCSID $Id: pf_key.c,v 1.2 2004/04/20 21:23:25 as Exp $
 *
 */

/* 
 * This program opens a pfkey socket and prints all messages that it sees.
 *
 * This can be used to diagnose problems.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>

#include <sys/socket.h>

#include <sys/types.h>
#include <stdint.h>
#include <freeswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

char *progname;
uint32_t pfkey_seq = 0;
int pfkey_sock;

static void
Usage(char *progname)
{
	fprintf(stderr, "%s: Usage: %s [--help]\n"
		"\tby default listens for AH, ESP, IPIP and IPCOMP\n"
		"\t--daemon <file>  fork before printing, stuffing the PID in the file\n"
		"\t--ah       listen for AH messages\n"
		"\t--esp      listen for ESP messages\n"
		"\t--ipip     listen for IPIP messages\n"
		"\t--ipcomp   listen for IPCOMP messages\n",
		progname, progname);
	exit(1);
}

void
pfkey_register(uint8_t satype) {
	/* for registering SA types that can be negotiated */
	int error = 0;
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;

	pfkey_extensions_init(extensions);
	if((error = pfkey_msg_hdr_build(&extensions[0],
					SADB_REGISTER,
					satype,
					0,
					++pfkey_seq,
					getpid()))) {
		fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}
	if((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	if(write(pfkey_sock, pfkey_msg,
		 pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN) !=
	   (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		/* cleanup code here */
		fprintf(stderr, "%s: Trouble writing to channel PF_KEY.\n", progname);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
}

int dienow;

void controlC(int foo)
{
	fflush(stdout);
	printf("%s: Exiting on signal 15\n", progname);
	fflush(stderr);
	exit(0);
}

int
main(int argc, char *argv[])
{
	int opt;
	ssize_t readlen;
	unsigned char pfkey_buf[256];
	struct sadb_msg *msg;
	int fork_after_register;
	char *pidfilename;

	static int ah_register;
	static int esp_register;
	static int ipip_register;
	static int ipcomp_register;

	static struct option long_options[] =
	{
		{"help",        no_argument, 0, 'h'},
		{"daemon",      required_argument, 0, 'f'},
		{"ah",          no_argument, &ah_register, 1},
		{"esp",         no_argument, &esp_register, 1},
		{"ipip",        no_argument, &ipip_register, 1},
		{"ipcomp",      no_argument, &ipcomp_register, 1},
	};

	ah_register   = 0;
	esp_register  = 0;
	ipip_register = 0;
	ipcomp_register=0;
	dienow = 0;
	fork_after_register=0;
	pidfilename=NULL;
	
	progname = argv[0];
	if(strrchr(progname, '/')) {
		progname=strrchr(progname, '/')+1;
	}
	
	while((opt = getopt_long(argc, argv, "hf:",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		case 'f':
			pidfilename=optarg;
			fork_after_register=1;
			break;
		case 'h':
			Usage(progname);
			break;
		case '0':
			/* it was a long option with a flag */
			break;
		}
	}
	
	if((pfkey_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
		fprintf(stderr, "%s: failed to open PF_KEY family socket: %s\n",
			progname, strerror(errno));
		exit(1);
	}

	if(ah_register == 0 &&
	   esp_register== 0 &&
	   ipip_register==0 &&
	   ipcomp_register==0) {
		ah_register=1;
		esp_register=1;
		ipip_register=1;
		ipcomp_register=1;
	}

	if(ah_register) {
		pfkey_register(SADB_SATYPE_AH);
	}
	if(esp_register) {
		pfkey_register(SADB_SATYPE_ESP);
	}
	if(ipip_register) {
		pfkey_register(SADB_X_SATYPE_IPIP);
	}
	if(ipcomp_register) {
		pfkey_register(SADB_X_SATYPE_COMP);
	}

	if(fork_after_register) {
		/*
		 * to aid in regression testing, we offer to register 
		 * everything first, and then we fork. As part of this
		 * we write the PID of the new process to a file
		 * provided.
		 */
		int pid;
		FILE *pidfile;
		
		fflush(stdout);
		fflush(stderr);

		pid=fork();
		if(pid!=0) {
			/* in parent! */
			exit(0);
		}
		
		if((pidfile=fopen(pidfilename, "w"))==NULL) {
			perror(pidfilename);
		} else {
			fprintf(pidfile, "%d", getpid());
			fclose(pidfile);
		}
	}
			
	signal(SIGINT,  controlC);
	signal(SIGTERM, controlC);

	while((readlen = read(pfkey_sock, pfkey_buf, sizeof(pfkey_buf))) > 0) {
		struct sadb_ext *extensions[SADB_EXT_MAX + 1];
		msg = (struct sadb_msg *)pfkey_buf;
		
		/* first, see if we got enough for an sadb_msg */
		if((size_t)readlen < sizeof(struct sadb_msg)) {
			printf("%s: runt packet of size: %d (<%lu)\n",
			       progname, (int)readlen, (unsigned long)sizeof(struct sadb_msg));
			continue;
		}
		
		/* okay, we got enough for a message, print it out */
		printf("\npfkey v%d msg. type=%d(%s) seq=%d len=%d pid=%d errno=%d satype=%d(%s)\n",
		       msg->sadb_msg_version,
		       msg->sadb_msg_type,
		       pfkey_v2_sadb_type_string(msg->sadb_msg_type),
		       msg->sadb_msg_seq,
		       msg->sadb_msg_len,
		       msg->sadb_msg_pid,
		       msg->sadb_msg_errno,
		       msg->sadb_msg_satype,
		       satype2name(msg->sadb_msg_satype));
		
		if((size_t)readlen != msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)
		{
			printf("%s: packet size read from socket=%d doesn't equal sadb_msg_len %d * %u; message not decoded\n",
			       progname,
			       (int)readlen,
			       msg->sadb_msg_len,
			       (int) IPSEC_PFKEYv2_ALIGN);
			continue;
		}
		
		pfkey_lib_debug = PF_KEY_DEBUG_PARSE_STRUCT;
		if (pfkey_msg_parse(msg, NULL, extensions, EXT_BITS_OUT)) {
			printf("%s: unparseable PF_KEY message.\n",
			       progname);
		} else {
			printf("%s: parseable PF_KEY message.\n",
			       progname);
		}
	}
	printf("%s: exited normally\n", progname);
	exit(0);
}
	
/*
 * $Log: pf_key.c,v $
 * Revision 1.2  2004/04/20 21:23:25  as
 * int cast fix for 64 bit platforms
 *
 * Revision 1.1  2004/03/15 20:35:28  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.15  2003/09/10 00:01:30  mcr
 * 	fixes for gcc 3.3 from Matthias Bethke <Matthias.Bethke@gmx.net>
 *
 * Revision 1.14  2002/10/09 03:12:05  dhr
 *
 * [kenb+dhr] 64-bit fixes
 *
 * Revision 1.13  2002/09/20 05:02:15  rgb
 * Cleaned up pfkey_lib_debug usage.
 *
 * Revision 1.12  2002/09/13 23:02:23  rgb
 * Type fiddling to tame ia64 compiler.
 * Added text labels to elucidate numeric values presented.
 *
 * Revision 1.11  2002/08/26 03:05:25  mcr
 * 	duh, pf_key much catch SIGTERM as well as SIGINT...
 *
 * Revision 1.10  2002/08/13 19:01:27  mcr
 * 	patches from kenb to permit compilation of FreeSWAN on ia64.
 * 	des library patched to use proper DES_LONG type for ia64.
 *
 * Revision 1.9  2002/07/16 02:53:42  mcr
 * 	added --daemon <pidfile> to "ipsec pf_key" command.
 * 	this is used in *-trap-* tests to avoid race conditions between
 * 	registration of PF_KEY listeners and arrival of first test packet.
 *
 * Revision 1.8  2002/06/17 04:32:55  mcr
 * 	exit nicely from pf_key when SIGINT (^C) is sent.
 * 	This is needed so that the stdout will flush properly.
 *
 * Revision 1.7  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.6  2002/04/24 07:35:39  mcr
 * Moved from ./klips/utils/pf_key.c,v
 *
 * Revision 1.5  2002/03/08 21:44:04  rgb
 * Update for all GNU-compliant --version strings.
 *
 * Revision 1.4  2001/11/27 05:19:06  mcr
 * 	added extra newline between packets.
 * 	set pfkey_lib_debug to enum rather than just to "1".
 *
 * Revision 1.3  2001/11/27 03:35:29  rgb
 * Added stdlib *again*.
 *
 * Revision 1.2  2001/11/23 07:23:14  mcr
 * 	pulled up klips2 Makefile and pf_key code.
 *
 * Revision 1.1.2.5  2001/10/23 18:49:12  mcr
 * 	renamed man page to section 8.
 * 	added --ah, --esp, --ipcomp and --ipip to control which
 * 	protocols are printed.
 * 	incomplete messages which include at least an sadb header are printed.
 *
 * Revision 1.1.2.4  2001/10/22 21:50:51  rgb
 * Added pfkey register for AH, ESP, IPIP and COMP.
 *
 * Revision 1.1.2.3  2001/10/21 21:51:06  rgb
 * Bug fixes to get working.
 *
 * Revision 1.1.2.2  2001/10/20 22:45:31  rgb
 * Added check for exact length and a call to message parser to get some
 * idea of the contents of each extension.
 *
 * Revision 1.1.2.1  2001/10/17 23:25:37  mcr
 * 	added "pk_key" program to dump raw kernel pf messages.
 * 	(program is still skeletal)
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
