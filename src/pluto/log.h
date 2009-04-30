/* logging definitions
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
 */

#include <freeswan.h>

#define LOG_WIDTH   1024    /* roof of number of chars in log line */

#ifndef PERPEERLOGDIR
#define PERPEERLOGDIR "/var/log/pluto/peer"
#endif

/* our versions of assert: log result */

#ifdef DEBUG

extern void passert_fail(const char *pred_str
	, const char *file_str, unsigned long line_no) NEVER_RETURNS;

extern void pexpect_log(const char *pred_str
						, const char *file_str, unsigned long line_no);

# define impossible() passert_fail("impossible", __FILE__, __LINE__)

extern void switch_fail(int n
	, const char *file_str, unsigned long line_no) NEVER_RETURNS;

# define bad_case(n) switch_fail((int) n, __FILE__, __LINE__)

# define passert(pred) { \
		if (!(pred)) \
			passert_fail(#pred, __FILE__, __LINE__); \
	}

# define pexpect(pred) { \
		if (!(pred)) \
			pexpect_log(#pred, __FILE__, __LINE__); \
	}

/* assert that an err_t is NULL; evaluate exactly once */
# define happy(x) { \
		err_t ugh = x; \
		if (ugh != NULL) \
			passert_fail(ugh, __FILE__, __LINE__); \
	}

#else /*!DEBUG*/

# define impossible() abort()
# define bad_case(n) abort()
# define passert(pred)  { }     /* do nothing */
# define happy(x)  { (void) x; }        /* evaluate non-judgementally */

#endif /*!DEBUG*/


extern bool
	log_to_stderr,      /* should log go to stderr? */
	log_to_syslog,      /* should log go to syslog? */
	log_to_perpeer;     /* should log go to per-IP file? */

extern const char *base_perpeer_logdir;

/* maximum number of files to keep open for per-peer log files */
#define MAX_PEERLOG_COUNT 16

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * All are to be left in RESET condition and will be checked.
 * There are several pairs of routines to set and reset them.
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
extern int whack_log_fd;        /* only set during whack_handle() */
extern struct state *cur_state; /* current state, for diagnostics */
extern struct connection *cur_connection;       /* current connection, for diagnostics */
extern const ip_address *cur_from;      /* source of current current message */
extern u_int16_t cur_from_port; /* host order */

#ifdef DEBUG

  extern lset_t cur_debugging;  /* current debugging level */

  extern void extra_debugging(const struct connection *c);

# define reset_debugging() { cur_debugging = base_debugging; }

# define GLOBALS_ARE_RESET() (whack_log_fd == NULL_FD \
	&& cur_state == NULL \
	&& cur_connection == NULL \
	&& cur_from == NULL \
	&& cur_debugging == base_debugging)

#else /*!DEBUG*/

# define extra_debugging(c)  { }

# define reset_debugging() { }

# define GLOBALS_ARE_RESET() (whack_log_fd == NULL_FD \
	&& cur_state == NULL \
	&& cur_connection == NULL \
	&& cur_from == NULL)

#endif /*!DEBUG*/

#define reset_globals() { \
	whack_log_fd = NULL_FD; \
	cur_state = NULL; \
	cur_from = NULL; \
	reset_cur_connection(); \
	}


#define set_cur_connection(c) { \
	cur_connection = (c); \
	extra_debugging(c); \
	}

#define reset_cur_connection() { \
	cur_connection = NULL; \
	reset_debugging(); \
	}


#define set_cur_state(s) { \
	cur_state = (s); \
	extra_debugging((s)->st_connection); \
	}

#define reset_cur_state() { \
	cur_state = NULL; \
	reset_debugging(); \
	}

extern void init_log(const char *program);
extern void close_log(void);
extern void plog(const char *message, ...) PRINTF_LIKE(1);
extern void exit_log(const char *message, ...) PRINTF_LIKE(1) NEVER_RETURNS;

/* close of all per-peer logging */
extern void close_peerlog(void);

/* free all per-peer log resources */
extern void perpeer_logfree(struct connection *c);



/* the following routines do a dance to capture errno before it is changed
 * A call must doubly parenthesize the argument list (no varargs macros).
 * The first argument must be "e", the local variable that captures errno.
 */
#define log_errno(a) { int e = errno; log_errno_routine a; }
extern void log_errno_routine(int e, const char *message, ...) PRINTF_LIKE(2);
#define exit_log_errno(a) { int e = errno; exit_log_errno_routine a; }
extern void exit_log_errno_routine(int e, const char *message, ...) PRINTF_LIKE(2) NEVER_RETURNS NEVER_RETURNS;

extern void whack_log(int mess_no, const char *message, ...) PRINTF_LIKE(2);

/* Log to both main log and whack log
 * Much like log, actually, except for specifying mess_no.
 */
extern void loglog(int mess_no, const char *message, ...) PRINTF_LIKE(2);

/* show status, usually on whack log */
extern void show_status(bool all, const char *name);

/* Build up a diagnostic in a static buffer.
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 */
extern char diag_space[LOG_WIDTH];      /* output buffer, but can be occupied at call */
extern err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);

#ifdef DEBUG

extern lset_t base_debugging;   /* bits selecting what to report */

#define DBGP(cond)         (cur_debugging & (cond))
#define DBG(cond, action)   { if (DBGP(cond)) { action ; } }

extern void DBG_log(const char *message, ...) PRINTF_LIKE(1);
extern void DBG_dump(const char *label, const void *p, size_t len);
#define DBG_dump_chunk(label, ch) DBG_dump(label, (ch).ptr, (ch).len)

#else /*!DEBUG*/

#define DBG(cond, action)       { }     /* do nothing */

#endif /*!DEBUG*/

#define DBG_cond_dump(cond, label, p, len) DBG(cond, DBG_dump(label, p, len))
#define DBG_cond_dump_chunk(cond, label, ch) DBG(cond, DBG_dump_chunk(label, ch))


/* ip_str: a simple to use variant of addrtot.
 * It stores its result in a static buffer.
 * This means that newer calls overwrite the storage of older calls.
 * Note: this is not used in any of the logging functions, so their
 * callers may use it.
 */
extern const char *ip_str(const ip_address *src);

/*
 * call this routine to reset daily items.
 */
extern void daily_log_reset(void);
extern void daily_log_event(void);

/*
 * some events are to be logged only occasionally.
 */
extern bool logged_txt_warning;
extern bool logged_myid_ip_txt_warning;
extern bool logged_myid_ip_key_warning;
extern bool logged_myid_fqdn_txt_warning;
extern bool logged_myid_fqdn_key_warning;
