/* timing machinery
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

extern time_t now(void);	/* careful version of time(2) */

struct state;	/* forward declaration */

struct event
{
    time_t          ev_time;
    int             ev_type;        /* Event type */
    struct state   *ev_state;       /* Pointer to relevant state (if any) */
    struct event   *ev_next;        /* Pointer to next event */
};

extern void event_schedule(enum event_type type, time_t tm, struct state *st);
extern void handle_timer_event(void);
extern long next_event(void);
extern void delete_event(struct state *st);
extern void delete_dpd_event(struct state *st);
extern void daily_log_event(void);
extern void free_events(void);
