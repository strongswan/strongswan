/* Pluto Asynchronous DNS Helper Program -- for internal use only!
 * Copyright (C) 2002  D. Hugh Redelmeier.
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

/* This program executes as multiple processes.  The Master process
 * receives queries (struct adns_query messages) from Pluto and distributes
 * them amongst Worker processes.  These Worker processes are created
 * by the Master whenever a query arrives and no existing Worker is free.
 * At most MAX_WORKERS will be created; after that, the Master will queue
 * queries until a Worker becomes free.  When a Worker has an answer from
 * the resolver, it sends the answer as a struct adns_answer message to the
 * Master.  The Master then forwards the answer to Pluto, noting that
 * the Worker is free to accept another query.
 *
 * The protocol is simple: Pluto sends a sequence of queries and receives
 * a sequence of answers.  select(2) is used by Pluto and by the Master
 * process to decide when to read, but writes are done without checking
 * for readiness.  Communications is via pipes.  Since only one process
 * can write to each pipe, messages will not be interleaved.  Fixed length
 * records are used for simplicity.
 *
 * Pluto needs a way to indicate to the Master when to shut down
 * and the Master needs to indicate this to each worker.  EOF on the pipe
 * signifies this.
 *
 * The interfaces between these components are considered private to
 * Pluto.  This allows us to get away with less checking.  This is a
 * reason to use pipes instead of TCP/IP.
 *
 * Although the code uses plain old UNIX processes, it could be modified
 * to use threads.  That might reduce resource requirements.  It would
 * preclude running on systems without thread-safe resolvers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>      /* ??? for h_errno */

#include <freeswan.h>

/* GCC magic! */
#ifdef GCC_LINT
# define UNUSED __attribute__ ((unused))
#else
# define UNUSED /* ignore */
#endif

#include "constants.h"
#include "adns.h"       /* needs <resolv.h> */

/* shared by all processes */

static const char *name;        /* program name, for messages */

static bool debug = FALSE;

/* Read a variable-length record from a pipe (and no more!).
 * First bytes must be a size_t containing the length.
 * HES_CONTINUE if record read
 * HES_OK if EOF
 * HES_IO_ERROR_IN if errno tells the tale.
 * Others are errors.
 */
static enum helper_exit_status
read_pipe(int fd, unsigned char *stuff, size_t minlen, size_t maxlen)
{
	size_t n = 0;
	size_t goal = minlen;

	do {
		ssize_t m = read(fd, stuff + n, goal - n);

		if (m == -1)
		{
			if (errno != EINTR)
			{
				syslog(LOG_ERR, "Input error on pipe: %s", strerror(errno));
				return HES_IO_ERROR_IN;
			}
		}
		else if (m == 0)
		{
			return HES_OK;      /* treat empty message as EOF */
		}
		else
		{
			n += m;
			if (n >= sizeof(size_t))
			{
				goal = *(size_t *)(void *)stuff;
				if (goal < minlen || maxlen < goal)
				{
					if (debug)
						fprintf(stderr, "%lu : [%lu, %lu]\n"
							, (unsigned long)goal
							, (unsigned long)minlen, (unsigned long)maxlen);
					return HES_BAD_LEN;
				}
			}
		}
	} while (n < goal);

	return HES_CONTINUE;
}

/* Write a variable-length record to a pipe.
 * First bytes must be a size_t containing the length.
 * HES_CONTINUE if record written
 * Others are errors.
 */
static enum helper_exit_status
write_pipe(int fd, const unsigned char *stuff)
{
	size_t len = *(const size_t *)(const void *)stuff;
	size_t n = 0;

	do {
		ssize_t m = write(fd, stuff + n, len - n);

		if (m == -1)
		{
			/* error, but ignore and retry if EINTR */
			if (errno != EINTR)
			{
				syslog(LOG_ERR, "Output error from master: %s", strerror(errno));
				return HES_IO_ERROR_OUT;
			}
		}
		else
		{
			n += m;
		}
	} while (n != len);
	return HES_CONTINUE;
}

/**************** worker process ****************/

/* The interface in RHL6.x and BIND distribution 8.2.2 are different,
 * so we build some of our own :-(
 */

/* Support deprecated interface to allow for older releases of the resolver.
 * Fake new interface!
 * See resolver(3) bind distribution (should be in RHL6.1, but isn't).
 * __RES was 19960801 in RHL6.2, an old resolver.
 */

#if (__RES) <= 19960801
# define OLD_RESOLVER   1
#endif

#ifdef OLD_RESOLVER

# define res_ninit(statp) res_init()
# define res_nquery(statp, dname, class, type, answer, anslen) \
	res_query(dname, class, type, answer, anslen)
# define res_nclose(statp) res_close()

static struct __res_state *statp = &_res;

#else /* !OLD_RESOLVER */

static struct __res_state my_res_state /* = { 0 } */;
static res_state statp = &my_res_state;

#endif /* !OLD_RESOLVER */

static int
worker(int qfd, int afd)
{
	{
		int r = res_ninit(statp);

		if (r != 0)
		{
			syslog(LOG_ERR, "cannot initialize resolver");
			return HES_RES_INIT;
		}
#ifndef OLD_RESOLVER
		statp->options |= RES_ROTATE;
#endif
		statp->options |= RES_DEBUG;
	}

	for (;;)
	{
		struct adns_query q;
		struct adns_answer a;

		enum helper_exit_status r = read_pipe(qfd, (unsigned char *)&q
			, sizeof(q), sizeof(q));

		if (r != HES_CONTINUE)
			return r;   /* some kind of exit */

		if (q.qmagic != ADNS_Q_MAGIC)
		{
			syslog(LOG_ERR, "error in input from master: bad magic");
			return HES_BAD_MAGIC;
		}

		a.amagic = ADNS_A_MAGIC;
		a.serial = q.serial;
		a.continuation = NULL;

		a.result = res_nquery(statp, q.name_buf, C_IN, q.type, a.ans, sizeof(a.ans));
		a.h_errno_val = h_errno;

		a.len = offsetof(struct adns_answer, ans) + (a.result < 0? 0 : a.result);

#ifdef DEBUG
		if (((q.debugging & IMPAIR_DELAY_ADNS_KEY_ANSWER) && q.type == T_KEY)
		|| ((q.debugging & IMPAIR_DELAY_ADNS_TXT_ANSWER) && q.type == T_TXT))
			sleep(30);  /* delay the answer */
#endif

		/* write answer, possibly a bit at a time */
		r = write_pipe(afd, (const unsigned char *)&a);

		if (r != HES_CONTINUE)
			return r;   /* some kind of exit */
	}
}

/**************** master process ****************/

bool eof_from_pluto = FALSE;
#define PLUTO_QFD       0       /* queries come on stdin */
#define PLUTO_AFD       1       /* answers go out on stdout */

#ifndef MAX_WORKERS
# define MAX_WORKERS 10 /* number of in-flight queries */
#endif

struct worker_info {
	int qfd;    /* query pipe's file descriptor */
	int afd;    /* answer pipe's file descriptor */
	pid_t pid;
	bool busy;
	void *continuation; /* of outstanding request */
};

static struct worker_info wi[MAX_WORKERS];
static struct worker_info *wi_roof = wi;

/* request FIFO */

struct query_list {
	struct query_list *next;
	struct adns_query aq;
};

static struct query_list *oldest_query = NULL;
static struct query_list *newest_query; /* undefined when oldest == NULL */
static struct query_list *free_queries = NULL;

static bool
spawn_worker(void)
{
	int qfds[2];
	int afds[2];
	pid_t p;

	if (pipe(qfds) != 0 || pipe(afds) != 0)
	{
		syslog(LOG_ERR, "pipe(2) failed: %s", strerror(errno));
		exit(HES_PIPE);
	}

	wi_roof->qfd = qfds[1];     /* write end of query pipe */
	wi_roof->afd = afds[0];     /* read end of answer pipe */

	p = fork();
	if (p == -1)
	{
		/* fork failed: ignore if at least one worker exists */
		if (wi_roof == wi)
		{
			syslog(LOG_ERR, "fork(2) error creating first worker: %s", strerror(errno));
			exit(HES_FORK);
		}
		close(qfds[0]);
		close(qfds[1]);
		close(afds[0]);
		close(afds[1]);
		return FALSE;
	}
	else if (p == 0)
	{
		/* child */
		struct worker_info *w;

		close(PLUTO_QFD);
		close(PLUTO_AFD);
		/* close all master pipes, including ours */
		for (w = wi; w <= wi_roof; w++)
		{
			close(w->qfd);
			close(w->afd);
		}
		exit(worker(qfds[0], afds[1]));
	}
	else
	{
		/* parent */
		struct worker_info *w = wi_roof++;

		w->pid = p;
		w->busy = FALSE;
		close(qfds[0]);
		close(afds[1]);
		return TRUE;
	}
}

static void
send_eof(struct worker_info *w)
{
	pid_t p;
	int status;

	close(w->qfd);
	w->qfd = NULL_FD;

	close(w->afd);
	w->afd = NULL_FD;

	/* reap child */
	p = waitpid(w->pid, &status, 0);
	/* ignore result -- what could we do with it? */
}

static void
forward_query(struct worker_info *w)
{
	struct query_list *q = oldest_query;

	if (q == NULL)
	{
		if (eof_from_pluto)
			send_eof(w);
	}
	else
	{
		enum helper_exit_status r
			= write_pipe(w->qfd, (const unsigned char *) &q->aq);

		if (r != HES_CONTINUE)
			exit(r);

		w->busy = TRUE;

		oldest_query = q->next;
		q->next = free_queries;
		free_queries = q;
	}
}

static void
query(void)
{
	struct query_list *q = free_queries;
	enum helper_exit_status r;

	/* find an unused queue entry */
	if (q == NULL)
	{
		q = malloc(sizeof(*q));
		if (q == NULL)
		{
			syslog(LOG_ERR, "malloc(3) failed");
			exit(HES_MALLOC);
		}
	}
	else
	{
		free_queries = q->next;
	}

	r = read_pipe(PLUTO_QFD, (unsigned char *)&q->aq
		, sizeof(q->aq), sizeof(q->aq));

	if (r == HES_OK)
	{
		/* EOF: we're done, except for unanswered queries */
		struct worker_info *w;

		eof_from_pluto = TRUE;
		q->next = free_queries;
		free_queries = q;

		/* Send bye-bye to unbusy processes.
		 * Note that if there are queued queries, there won't be
		 * any non-busy workers.
		 */
		for (w = wi; w != wi_roof; w++)
			if (!w->busy)
				send_eof(w);
	}
	else if (r != HES_CONTINUE)
	{
		exit(r);
	}
	else if (q->aq.qmagic != ADNS_Q_MAGIC)
	{
		syslog(LOG_ERR, "error in query from Pluto: bad magic");
		exit(HES_BAD_MAGIC);
	}
	else
	{
		struct worker_info *w;

		/* got a query */

		/* add it to FIFO */
		q->next = NULL;
		if (oldest_query == NULL)
			oldest_query = q;
		else
			newest_query->next = q;
		newest_query = q;

		/* See if any worker available */
		for (w = wi; ; w++)
		{
			if (w == wi_roof)
			{
				/* no free worker */
				if (w == wi + MAX_WORKERS)
					break;      /* no more to be created */
				/* make a new one */
				if (!spawn_worker())
					break;      /* cannot create one at this time */
			}
			if (!w->busy)
			{
				/* assign first to free worker */
				forward_query(w);
				break;
			}
		}
	}
	return;
}

static void
answer(struct worker_info *w)
{
	struct adns_answer a;
	enum helper_exit_status r = read_pipe(w->afd, (unsigned char *)&a
		, offsetof(struct adns_answer, ans), sizeof(a));

	if (r == HES_OK)
	{
		/* unexpected EOF */
		syslog(LOG_ERR, "unexpected EOF from worker");
		exit(HES_IO_ERROR_IN);
	}
	else if (r != HES_CONTINUE)
	{
		exit(r);
	}
	else if (a.amagic != ADNS_A_MAGIC)
	{
		syslog(LOG_ERR, "Input from worker error: bad magic");
		exit(HES_BAD_MAGIC);
	}
	else if (a.continuation != w->continuation)
	{
		/* answer doesn't match query */
		syslog(LOG_ERR, "Input from worker error: continuation mismatch");
		exit(HES_SYNC);
	}
	else
	{
		/* pass the answer on to Pluto */
		enum helper_exit_status r
			= write_pipe(PLUTO_AFD, (const unsigned char *) &a);

		if (r != HES_CONTINUE)
			exit(r);
		w->busy = FALSE;
		forward_query(w);
	}
}

/* assumption: input limited; accept blocking on output */
static int
master(void)
{
	for (;;)
	{
		fd_set readfds;
		int maxfd = PLUTO_QFD;          /* approximate lower bound */
		int ndes = 0;
		struct worker_info *w;

		FD_ZERO(&readfds);
		if (!eof_from_pluto)
		{
			FD_SET(PLUTO_QFD, &readfds);
			ndes++;
		}
		for (w = wi; w != wi_roof; w++)
		{
			if (w->busy)
			{
				FD_SET(w->afd, &readfds);
				ndes++;
				if (maxfd < w->afd)
					maxfd = w->afd;
			}
		}

		if (ndes == 0)
			return HES_OK;      /* done! */

		do {
			ndes = select(maxfd + 1, &readfds, NULL, NULL, NULL);
		} while (ndes == -1 && errno == EINTR);
		if (ndes == -1)
		{
			syslog(LOG_ERR, "select(2) error: %s", strerror(errno));
			exit(HES_IO_ERROR_SELECT);
		}
		else if (ndes > 0)
		{
			if (FD_ISSET(PLUTO_QFD, &readfds))
			{
				query();
				ndes--;
			}
			for (w = wi; ndes > 0 && w != wi_roof; w++)
			{
				if (w->busy && FD_ISSET(w->afd, &readfds))
				{
					answer(w);
					ndes--;
				}
			}
		}
	}
}

/* Not to be invoked by strangers -- user hostile.
 * Mandatory args: query-fd answer-fd
 * Optional arg: -d, signifying "debug".
 */

static void
adns_usage(const char *fmt, const char *arg)
{
	const char **sp = ipsec_copyright_notice();

	fprintf(stderr, "INTERNAL TO PLUTO: DO NOT EXECUTE\n");

	fprintf(stderr, fmt, arg);
	fprintf(stderr, "\nstrongSwan "VERSION"\n");

	for (; *sp != NULL; sp++)
		fprintf(stderr, "%s\n", *sp);

	syslog(LOG_ERR, fmt, arg);
	exit(HES_INVOCATION);
}

int
main(int argc UNUSED, char **argv)
{
	int i = 1;

	name = argv[0];

	while (i < argc)
	{
		if (streq(argv[i], "-d"))
		{
			i++;
			debug = TRUE;
		}
		else
		{
			adns_usage("unexpected argument \"%s\"", argv[i]);
			/*NOTREACHED*/
		}
	}

	return master();
}
