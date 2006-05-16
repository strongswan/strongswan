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

#define STARTER_PID_FILE IPSEC_PIDDIR "/starter.pid"

#define DEV_RANDOM      "/dev/random"
#define DEV_URANDOM     "/dev/urandom"
#define PROC_NETKEY	"/proc/net/pfkey"
#define PROC_MODULES	"/proc/modules"

#define CONFIG_FILE     IPSEC_CONFDIR "/ipsec.conf"
#define SECRETS_FILE	IPSEC_CONFDIR "/ipsec.secrets"

#define PLUTO_CMD       IPSEC_DIR "/pluto"
#define PLUTO_CTL_FILE  IPSEC_PIDDIR "/pluto.ctl"
#define PLUTO_PID_FILE  IPSEC_PIDDIR "/pluto.pid"

#define CHARON_CMD	IPSEC_DIR "/charon"
#define CHARON_CTL_FILE IPSEC_PIDDIR "/charon.ctl"
#define CHARON_PID_FILE IPSEC_PIDDIR "/charon.pid"

#define DYNIP_DIR       IPSEC_PIDDIR "/dynip"
#define INFO_FILE       IPSEC_PIDDIR "/ipsec.info"

#endif /* _STARTER_FILES_H_ */

