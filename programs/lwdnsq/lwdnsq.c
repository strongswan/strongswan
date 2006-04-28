/*
 * DNS KEY lookup helper
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

char tncfg_c_version[] = "RCSID $Id: lwdnsq.c,v 1.1 2004/03/15 20:35:28 as Exp $";


#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h> 

#include <freeswan.h>

#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
#include <ctype.h>
#include <signal.h>

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

static void
usage(char *name)
{	
	fprintf(stdout,"%s --attach --virtual <virtual-device> --physical <physical-device>\n",
		name);
	exit(1);
}

static struct option const longopts[] =
{
	{"prompt", 0, 0, 'i'},
	{"serial", 0, 0, 's'},
	{"debug",  0, 0, 'g'},
	{"regress",0, 0, 'X'},
	{"ignoreeof",0, 0, 'Z'},
	{0, 0, 0, 0}
};

/* globals */
jmp_buf getMeOut;

void sig_handler(int sig)
{
  fprintf(stderr, "Caught signal %d, cleaning up and exiting\n", sig);
  longjmp(getMeOut, 1);
}

void cmdprompt(dnskey_glob *gs)
{
	if(gs->prompt) {
		printf("lwdnsq> ");
	}
	fflush(gs->cmdproto_out);
}

void quitprog(dnskey_glob *gs,
	      int argc,
	      char **argv)
{
	gs->done=1;
}

void setdebug(dnskey_glob *gs,
	      int argc,
	      char **argv)
{
	if(argc > 1) {
		gs->debug=strtoul(argv[1],NULL,0);
	}
	printf("0 DEBUG is %d\n",gs->debug);
}


int cmdparse(dnskey_glob *gs,
	     char *cmdline)
{
	char *argv[256];
	int   argc;
	char *arg;
	static const struct cmd_entry {
		const char *cmdname;
		void (*cmdfunc)(dnskey_glob *, int, char **);
	} cmds[]={
		{"key",       lookup_key},
		{"key4",      lookup_key4},
		{"key6",      lookup_key6},
		{"txt",       lookup_txt},
		{"txt4",      lookup_txt4},
		{"txt6",      lookup_txt6},
		{"ipseckey",  lookup_ipseckey},
		{"ipseckey4", lookup_ipseckey4},
		{"ipseckey6", lookup_ipseckey6},
		{"oe4",       lookup_oe4},
		{"oe6",       lookup_oe6},
		{"vpn4",      lookup_key4},
		{"vpn6",      lookup_key6},
		{"quit",      quitprog},
		{"a",         lookup_a},
		{"aaaa",      lookup_aaaa},
		{"debug",     setdebug},
		{NULL,        NULL}};
	const struct cmd_entry *ce = cmds;

	argc=0;
	
	/* skip initial spaces */
	while(cmdline && isspace(*cmdline)) {
		cmdline++;
	}

	while(cmdline && *cmdline!='\0' &&
	      (arg=strsep(&cmdline, " \t\n"))!=NULL) {
	  if (argc < sizeof(argv)/sizeof(*argv - 1)) {
	    /* ignore arguments that would overflow.
	     * XXX should generate a diagnostic.
	     */
	    argv[argc++]=arg;
	  }
	  while(cmdline && isspace(*cmdline)) {
	    cmdline++;
	  }
	}
	argv[argc]=NULL;

	if(argc==0 || argv[0][0]=='\0') {
	    /* ignore empty line */
	} else if(strcasecmp("help", argv[0]) == 0) {
	    fprintf(gs->cmdproto_out, "0 HELP\n");
	    for (; ce->cmdname != NULL; ce++)
		fprintf(gs->cmdproto_out, "0 HELP %s\n", ce->cmdname);
	} else {
	    for (;; ce++) {
		if (ce->cmdname == NULL) {
		    fprintf(gs->cmdproto_out, "0 FATAL unknown command \"%s\"\n", argv[0]);
		    break;
		}
		if(strcasecmp(ce->cmdname, argv[0])==0) {
		    (*ce->cmdfunc)(gs, argc, argv);
		    break;
		}
	    }
	}

	if (!gs->done)
	    cmdprompt(gs);
	return 0;
}

int cmdread(dnskey_glob *gs,
	    char  *buf,
	    int    len)
{
	unsigned char *nl;
	int   cmdlen;

	cmdlen=0;

	/* 
	 * have to handle partial reads and multiple commands
	 * per read, since this may in fact be a file or a pipe.
	 */
	if((gs->cmdloc + len + 1) > sizeof(gs->cmdbuf)) {
		fprintf(stderr, "command '%.*s...' is too long, discarding!\n",
			40, buf);
		fflush(stdout);
		
		gs->cmdloc=0;
		return 0;
	}
	memcpy(gs->cmdbuf+gs->cmdloc, buf, len);
	gs->cmdloc+=len;
	gs->cmdbuf[gs->cmdloc]='\0';

	while((nl = strchr(gs->cmdbuf, '\n')) != NULL) {
		/* found a newline, so turn it into a \0, and process the
		 * command, and then we will pull the rest of the buffer
		 * up.
		 */
		*nl='\0';
		cmdlen= nl - gs->cmdbuf +1;

		cmdparse(gs, gs->cmdbuf);

		gs->cmdloc -= cmdlen;
		memmove(gs->cmdbuf, gs->cmdbuf+cmdlen, gs->cmdloc);
	}
	return 1;
}

int
main(int argc, char *argv[])
{
	char *program_name;
	dnskey_glob gs;
	int c;
	static int ignoreeof=0;  /* static to avoid longjmp clobber */
	int ineof;

	memset(&gs, 0, sizeof(dnskey_glob));

#if 0
	printf("PID: %d\n", getpid());
	sleep(60);
#endif

	program_name = argv[0];
	gs.concurrent = 1;

	if(lwres_async_init(&gs.lwctx) != ERRSET_SUCCESS) {
		fprintf(stderr, "Can not initialize async context\n");
		exit(3);
	}

	if(isc_mem_create(0,0,&gs.iscmem) != ISC_R_SUCCESS) {
		fprintf(stderr, "Can not initialize isc memory allocator\n");
		exit(4);
	}

	if(isc_buffer_allocate(gs.iscmem, &gs.iscbuf, LWDNSQ_RESULT_LEN_MAX)) {
		fprintf(stderr, "Can not allocate a result buffer\n");
		exit(5);
	}

	while((c = getopt_long_only(argc, argv, "dgsiXZ", longopts, 0)) != EOF) {
		switch(c) {
		case 'd':
			gs.debug+=2;
			break;

		case 'g':
			gs.debug++;
			break;
		case 's':
			gs.concurrent=0;
			break;
		case 'i':
			gs.prompt=1;
			break;
		case 'X':
			gs.regress++;
			break;

		case 'Z':
			ignoreeof=1;
			break;

		default:
			usage(program_name);
			break;
		}
	}

	if(gs.debug && ignoreeof) {
		fprintf(stderr, "Ignoring end of file\n");
	}

	if(isatty(0)) {
		gs.prompt=1;
	}

	/* do various bits of setup */
	if(setjmp(getMeOut)!=0) {
		signal(SIGINT,  SIG_DFL);
		signal(SIGPIPE, SIG_IGN);
		
		/* cleanup_crap(); */
		
		exit(1);
	}
	
	if(signal(SIGINT, sig_handler) < 0)
		perror("Setting handler for SIGINT");
	
	if(signal(SIGPIPE, sig_handler) < 0)
		perror("Setting handler for SIGINT");
	
	cmdprompt(&gs);

	ineof = 0;
	gs.done = 0;
	gs.cmdproto_out = stdout;
	gs.l_fds[0].events = POLLIN|POLLHUP;
	gs.l_fds[0].fd=0;

	gs.l_fds[1].events = POLLIN|POLLHUP|POLLERR;
	gs.l_fds[1].fd = lwres_async_fd(gs.lwctx);

	gs.l_nfds= 2;

	while(!gs.done) 
	{
		int    timeout;
		char   buf[128];
		int    n;
		int    rlen;

		timeout=-1;

		gs.l_fds[0].revents = 0;

		gs.l_fds[1].events = POLLIN|POLLHUP|POLLERR;
		gs.l_fds[1].revents = 0;
		gs.l_fds[1].fd = lwres_async_fd(gs.lwctx);

		if(gs.debug > 1) {
			fprintf(stderr, "=== invoking poll(,%d,) with %s\n",
				gs.l_nfds,
				timeout>0 ? "waittime" : "no wait");
			for(n = 0; n < gs.l_nfds; n++) {
				fprintf(stderr, "=== waiting on fd#%d\n",
					gs.l_fds[n].fd);
			}
			fprintf(stderr, "=== inflight: %d\n", gs.dns_inflight);
		}

		n = poll(gs.l_fds, gs.l_nfds, timeout);

		if(n == 0) {
			/* timeout! */
		}

		if(n < 0) {
			perror("poll");
		}

		if(gs.debug > 1) {
			fprintf(stderr, "=== poll returned with %d\n", n);
		}
				
		while(n>0) {
			if((gs.l_fds[0].revents & POLLERR) == POLLERR ||
			   (gs.l_fds[1].revents & POLLERR) == POLLERR)
			{
				break;
			}

			/* see if there are DNS events coming back */
			if((gs.l_fds[1].revents & POLLIN) == POLLIN) {
				if(gs.debug > 1) {
					fprintf(stderr,
						"=== new responses from lwdnsd\n");
				}

				process_dns_reply(&gs);
				fflush(stdout);
				n--;
			}

			if(!ignoreeof &&
			   (gs.l_fds[0].revents & POLLHUP) == POLLHUP)
			{
				break;
			}

			if((gs.l_fds[0].revents & POLLIN) == POLLIN) {
				
				rlen=read(0, buf, sizeof(buf));

				if(gs.debug > 1) {
					if(rlen > 0) {
						buf[rlen]='\0';
					}
					fprintf(stderr,
						"=== new commands on fd 0: %d: %s\n",
						rlen, buf);
				}

				if(rlen > 0) {
					cmdread(&gs, buf, rlen);
				} else if(rlen == 0) {
					ineof = 1;
					if(!ignoreeof) {
						/* EOF, die */
						gs.done=1;
					}
				}
				n--;
			} 

		}

		if((gs.l_fds[0].revents & POLLHUP) == POLLHUP)
		{
			ineof = 1;
			if(!ignoreeof)
			{
				gs.done=1;
			}
		}

		if(ignoreeof) {
			/* if we have exhausted the input,
			 * and there are none in flight,
			 * then exit, finally.
			 */
			if(ineof) { 
				if(gs.dns_inflight == 0) {
					gs.done=1;
				}
			}
		}

		if(gs.debug) {
			fprintf(stderr, "=== ineof: %d inflight: %d\n",
				ineof, gs.dns_inflight);
		}

	}

	signal(SIGINT,  SIG_DFL);
	signal(SIGPIPE, SIG_IGN);
  
	exit(0);
}
	
/*
 * $Log: lwdnsq.c,v $
 * Revision 1.1  2004/03/15 20:35:28  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.12  2003/09/16 05:01:14  mcr
 * 	prefix all debugging with === so that it can be easily removed.
 *
 * Revision 1.11  2003/09/10 04:43:52  mcr
 * 	final fixes to lwdnsq to exit only when all requests are done,
 * 	and we have been told to wait, *OR* if there is an EOF in stdin.
 *
 * Revision 1.10  2003/09/03 01:13:24  mcr
 * 	first attempt at async capable lwdnsq.
 *
 * Revision 1.9  2003/04/02 07:37:57  dhr
 *
 * lwdnsq: fix non-deterministic bug in handling batched input
 *
 * Revision 1.8  2003/02/08 04:03:06  mcr
 * 	renamed --single to --serial.
 *
 * Revision 1.7  2003/01/14 03:01:14  dhr
 *
 * improve diagnostics; tidy
 *
 * Revision 1.6  2002/12/19 07:29:47  dhr
 *
 * - avoid (improbable) buffer overflow
 * - suppress prompt after "quit" command
 * - add space to prompt to match aesthetics and man page
 * - elminate a magic number
 *
 * Revision 1.5  2002/12/19 07:08:42  dhr
 *
 * continue renaming dnskey => lwdnsq
 *
 * Revision 1.4  2002/12/12 06:03:41  mcr
 * 	added --regress option to force times to be regular
 *
 * Revision 1.3  2002/11/25 18:37:48  mcr
 * 	make sure that we exit cleanly upon EOF.
 *
 * Revision 1.2  2002/11/16 02:53:53  mcr
 * 	lwdnsq - with new contract added.
 *
 * Revision 1.1  2002/10/30 02:25:31  mcr
 * 	renamed version of files from dnskey/
 *
 * Revision 1.3  2002/10/09 20:14:16  mcr
 * 	make sure to flush stdout at the right time - do it regardless
 * 	of whether or not we are printing prompts.
 *
 * Revision 1.2  2002/09/30 18:55:54  mcr
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
