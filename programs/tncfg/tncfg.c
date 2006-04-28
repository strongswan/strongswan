/*
 * IPSEC interface configuration
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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

char tncfg_c_version[] = "RCSID $Id: tncfg.c,v 1.1 2004/03/15 20:35:31 as Exp $";


#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* system(), strtoul() */
#include <unistd.h> /* getuid() */
#include <linux/types.h>
#include <sys/ioctl.h> /* ioctl() */

#include <freeswan.h>
#ifdef NET_21 /* from freeswan.h */
#include <linux/sockios.h>
#include <sys/socket.h>
#endif /* NET_21 */ /* from freeswan.h */

#if 0
#include <linux/if.h>
#else
#include <net/if.h>
#endif
#include <sys/types.h>
#include <errno.h>
#include <getopt.h>

#include "freeswan/ipsec_tunnel.h"

static void
usage(char *name)
{	
	fprintf(stdout,"%s --attach --virtual <virtual-device> --physical <physical-device>\n",
		name);
	fprintf(stdout,"%s --detach --virtual <virtual-device>\n",
		name);
	fprintf(stdout,"%s --clear\n",
		name);
	fprintf(stdout,"%s --help\n",
		name);
	fprintf(stdout,"%s --version\n",
		name);
	fprintf(stdout,"%s\n",
		name);
	fprintf(stdout, "        [ --debug ] is optional to any %s command.\n", name);
	fprintf(stdout, "        [ --label <label> ] is optional to any %s command.\n", name);
	exit(1);
}

static struct option const longopts[] =
{
	{"virtual", 1, 0, 'V'},
	{"physical", 1, 0, 'P'},
	{"attach", 0, 0, 'a'},
	{"detach", 0, 0, 'd'},
	{"clear", 0, 0, 'c'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"label", 1, 0, 'l'},
	{"optionsfrom", 1, 0, '+'},
	{"debug", 0, 0, 'g'},
	{0, 0, 0, 0}
};

int
main(int argc, char *argv[])
{
	struct ifreq ifr;
	struct ipsectunnelconf *shc=(struct ipsectunnelconf *)&ifr.ifr_data;
	int s;
	int c, previous = -1;
	char *program_name;
	int debug = 0;
	int argcount = argc;
     
	memset(&ifr, 0, sizeof(ifr));
	program_name = argv[0];

	while((c = getopt_long_only(argc, argv, ""/*"adchvV:P:l:+:"*/, longopts, 0)) != EOF) {
		switch(c) {
		case 'g':
			debug = 1;
			argcount--;
			break;
		case 'a':
			if(shc->cf_cmd) {
				fprintf(stderr, "%s: exactly one of '--attach', '--detach' or '--clear' options must be specified.\n",	program_name);
				exit(1);
			}
			shc->cf_cmd = IPSEC_SET_DEV;
			break;
		case 'd':
			if(shc->cf_cmd) {
				fprintf(stderr, "%s: exactly one of '--attach', '--detach' or '--clear' options must be specified.\n",	program_name);
				exit(1);
			}
			shc->cf_cmd = IPSEC_DEL_DEV;
			break;
		case 'c':
			if(shc->cf_cmd) {
				fprintf(stderr, "%s: exactly one of '--attach', '--detach' or '--clear' options must be specified.\n",	program_name);
				exit(1);
			}
			shc->cf_cmd = IPSEC_CLR_DEV;
			break;
		case 'h':
			usage(program_name);
			break;
		case 'v':
			if(optarg) {
				fprintf(stderr, "%s: warning; '-v' and '--version' options don't expect arguments, arg '%s' found, perhaps unintended.\n",
					program_name, optarg);
			}
			fprintf(stdout, "%s, %s\n", program_name, tncfg_c_version);
			exit(1);
			break;
		case 'V':
			strcpy(ifr.ifr_name, optarg);
			break;
		case 'P':
			strcpy(shc->cf_name, optarg);
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
		case '+': /* optionsfrom */
			optionsfrom(optarg, &argc, &argv, optind, stderr);
			/* no return on error */
			break;
		default:
			usage(program_name);
			break;
		}
		previous = c;
	}

	if(argcount == 1) {
		system("cat /proc/net/ipsec_tncfg");
		exit(0);
	}

	switch(shc->cf_cmd) {
	case IPSEC_SET_DEV:
		if(!shc->cf_name) {
			fprintf(stderr, "%s: physical I/F parameter missing.\n",
				program_name);
			exit(1);
		}
	case IPSEC_DEL_DEV:
		if(!ifr.ifr_name) {
			fprintf(stderr, "%s: virtual I/F parameter missing.\n",
				program_name);
			exit(1);
		}
		break;
	case IPSEC_CLR_DEV:
		strcpy(ifr.ifr_name, "ipsec0");
		break;
	default:
		fprintf(stderr, "%s: exactly one of '--attach', '--detach' or '--clear' options must be specified.\n"
			"Try %s --help' for usage information.\n",
			program_name, program_name);
		exit(1);
	}

	s=socket(AF_INET, SOCK_DGRAM,0);
	if(s==-1)
	{
		fprintf(stderr, "%s: Socket creation failed -- ", program_name);
		switch(errno)
		{
		case EACCES:
			if(getuid()==0)
				fprintf(stderr, "Root denied permission!?!\n");
			else
				fprintf(stderr, "Run as root user.\n");
			break;
		case EPROTONOSUPPORT:
			fprintf(stderr, "Internet Protocol not enabled");
			break;
		case EMFILE:
		case ENFILE:
		case ENOBUFS:
			fprintf(stderr, "Insufficient system resources.\n");
			break;
		case ENODEV:
			fprintf(stderr, "No such device.  Is the virtual device valid?  Is the ipsec module linked into the kernel or loaded as a module?\n");
			break;
		default:
			fprintf(stderr, "Unknown socket error %d.\n", errno);
		}
		exit(1);
	}
	if(ioctl(s, shc->cf_cmd, &ifr)==-1)
	{
		if(shc->cf_cmd == IPSEC_SET_DEV) {
			fprintf(stderr, "%s: Socket ioctl failed on attach -- ", program_name);
			switch(errno)
			{
			case EINVAL:
				fprintf(stderr, "Invalid argument, check kernel log messages for specifics.\n");
				break;
			case ENODEV:
				fprintf(stderr, "No such device.  Is the virtual device valid?  Is the ipsec module linked into the kernel or loaded as a module?\n");
				break;
			case ENXIO:
				fprintf(stderr, "No such device.  Is the physical device valid?\n");
				break;
			case EBUSY:
				fprintf(stderr, "Device busy.  Virtual device %s is already attached to a physical device -- Use detach first.\n",
				       ifr.ifr_name);
				break;
			default:
				fprintf(stderr, "Unknown socket error %d.\n", errno);
			}
			exit(1);
		}
		if(shc->cf_cmd == IPSEC_DEL_DEV) {
			fprintf(stderr, "%s: Socket ioctl failed on detach -- ", program_name);
			switch(errno)
			{
			case EINVAL:
				fprintf(stderr, "Invalid argument, check kernel log messages for specifics.\n");
				break;
			case ENODEV:
				fprintf(stderr, "No such device.  Is the virtual device valid?  The ipsec module may not be linked into the kernel or loaded as a module.\n");
				break;
			case ENXIO:
				fprintf(stderr, "Device requested is not linked to any physical device.\n");
				break;
			default:
				fprintf(stderr, "Unknown socket error %d.\n", errno);
			}
			exit(1);
		}
		if(shc->cf_cmd == IPSEC_CLR_DEV) {
			fprintf(stderr, "%s: Socket ioctl failed on clear -- ", program_name);
			switch(errno)
			{
			case EINVAL:
				fprintf(stderr, "Invalid argument, check kernel log messages for specifics.\n");
				break;
			case ENODEV:
				fprintf(stderr, "Failed.  Is the ipsec module linked into the kernel or loaded as a module?.\n");
				break;
			default:
				fprintf(stderr, "Unknown socket error %d.\n", errno);
			}
			exit(1);
		}
	}
	exit(0);
}
	
/*
 * $Log: tncfg.c,v $
 * Revision 1.1  2004/03/15 20:35:31  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.30  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.29  2002/04/24 07:35:41  mcr
 * Moved from ./klips/utils/tncfg.c,v
 *
 * Revision 1.28  2002/03/08 21:44:05  rgb
 * Update for all GNU-compliant --version strings.
 *
 * Revision 1.27  2001/06/14 19:35:15  rgb
 * Update copyright date.
 *
 * Revision 1.26  2001/05/21 02:02:55  rgb
 * Eliminate 1-letter options.
 *
 * Revision 1.25  2001/05/16 05:07:20  rgb
 * Fixed --label option in KLIPS manual utils to add the label to the
 * command name rather than replace it in error text.
 * Fix 'print table' non-option in KLIPS manual utils to deal with --label
 * and --debug options.
 *
 * Revision 1.24  2000/09/12 13:09:05  rgb
 * Fixed real/physical discrepancy between tncfg.8 and tncfg.c.
 *
 * Revision 1.23  2000/08/27 01:48:30  rgb
 * Update copyright.
 *
 * Revision 1.22  2000/07/26 03:41:46  rgb
 * Changed all printf's to fprintf's.  Fixed tncfg's usage to stderr.
 *
 * Revision 1.21  2000/06/21 16:51:27  rgb
 * Added no additional argument option to usage text.
 *
 * Revision 1.20  2000/01/21 06:26:31  rgb
 * Added --debug switch to command line.
 *
 * Revision 1.19  1999/12/08 20:32:41  rgb
 * Cleaned out unused cruft.
 * Changed include file, limiting scope, to avoid conflicts in 2.0.xx
 * kernels.
 *
 * Revision 1.18  1999/12/07 18:27:10  rgb
 * Added headers to silence fussy compilers.
 * Converted local functions to static to limit scope.
 *
 * Revision 1.17  1999/11/18 04:09:21  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.16  1999/05/25 01:45:36  rgb
 * Fix version macros for 2.0.x as a module.
 *
 * Revision 1.15  1999/05/05 22:02:34  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.14  1999/04/15 15:37:28  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.10.6.2  1999/04/13 20:58:10  rgb
 * Add argc==1 --> /proc/net/ipsec_*.
 *
 * Revision 1.10.6.1  1999/03/30 17:01:36  rgb
 * Make main() return type explicit.
 *
 * Revision 1.13  1999/04/11 00:12:09  henry
 * GPL boilerplate
 *
 * Revision 1.12  1999/04/06 04:54:39  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.11  1999/03/17 15:40:54  rgb
 * Make explicit main() return type of int.
 *
 * Revision 1.10  1998/11/12 21:08:04  rgb
 * Add --label option to identify caller from scripts.
 *
 * Revision 1.9  1998/10/09 18:47:30  rgb
 * Add 'optionfrom' to get more options from a named file.
 *
 * Revision 1.8  1998/10/09 04:36:55  rgb
 * Changed help output from stderr to stdout.
 * Deleted old commented out cruft.
 *
 * Revision 1.7  1998/08/28 03:15:14  rgb
 * Add some manual long options to the usage text.
 *
 * Revision 1.6  1998/08/05 22:29:00  rgb
 * Change includes to accomodate RH5.x.
 * Force long option names.
 * Add ENXIO error return code to narrow down error reporting.
 *
 * Revision 1.5  1998/07/29 21:45:28  rgb
 * Convert to long option names.
 *
 * Revision 1.4  1998/07/09 18:14:11  rgb
 * Added error checking to IP's and keys.
 * Made most error messages more specific rather than spamming usage text.
 * Added more descriptive kernel error return codes and messages.
 * Converted all spi translations to unsigned.
 * Removed all invocations of perror.
 *
 * Revision 1.3  1998/05/27 18:48:20  rgb
 * Adding --help and --version directives.
 *
 * Revision 1.2  1998/04/23 21:11:39  rgb
 * Fixed 0 argument usage case to prevent sigsegv.
 *
 * Revision 1.1.1.1  1998/04/08 05:35:09  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:31:55  ji
 * New file.
 *
 */
