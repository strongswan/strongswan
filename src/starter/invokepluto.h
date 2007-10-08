/* strongSwan pluto launcher
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
 * RCSID $Id$
 */

#ifndef _STARTER_PLUTO_H_
#define _STARTER_PLUTO_H_

#define PLUTO_RESTART_DELAY    5

extern void starter_pluto_sigchild (pid_t pid);
extern pid_t starter_pluto_pid (void);
extern int starter_stop_pluto (void);
extern int starter_start_pluto (struct starter_config *cfg, bool debug);

#endif /* _STARTER_PLUTO_H_ */

