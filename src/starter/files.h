/* strongSwan file locations
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: files.h,v 1.5 2006/02/04 18:52:58 as Exp $
 */

#ifndef _STARTER_FILES_H_
#define _STARTER_FILES_H_

#ifndef DEFAULT_CTLBASE
#define DEFAULT_CTLBASE "/var/run/pluto"
#endif
#define CTL_SUFFIX      ".ctl"
#define PID_SUFFIX      ".pid"

#define MY_PID_FILE     "/var/run/starter.pid"

#define DEV_RANDOM      "/dev/random"
#define DEV_URANDOM     "/dev/urandom"

#define PROC_NETKEY         "/proc/net/pfkey"
#define PROC_IPSECVERSION   "/proc/net/ipsec_version"
#define PROC_SYSFLAGS       "/proc/sys/net/ipsec"
#define PROC_MODULES        "/proc/modules"

#define CONFIG_FILE     IPSEC_CONFDIR"/ipsec.conf"
#define SECRETS_FILE	IPSEC_CONFDIR"/ipsec.secrets"

#define PLUTO_CMD       IPSEC_EXECDIR"/pluto"
#define PLUTO_CTL_FILE  DEFAULT_CTLBASE CTL_SUFFIX
#define PLUTO_PID_FILE  DEFAULT_CTLBASE PID_SUFFIX

#ifdef IKEV2
#define CHARON_CMD		IPSEC_EXECDIR"/charon"
#define CHARON_BASE		"/var/run/charon"
#define CHARON_CTL_FILE CHARON_BASE CTL_SUFFIX
#define CHARON_PID_FILE CHARON_BASE PID_SUFFIX
#endif /* IKEV2 */

#define DYNIP_DIR       "/var/run/dynip"
#define INFO_FILE       "/var/run/ipsec.info"

#endif /* _STARTER_FILES_H_ */

