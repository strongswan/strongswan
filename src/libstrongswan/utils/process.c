/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "process.h"

#include <utils/debug.h>

#include <fcntl.h>

typedef struct private_process_t private_process_t;

/**
 * Ends of a pipe()
 */
enum {
	PIPE_READ = 0,
	PIPE_WRITE = 1,
	PIPE_ENDS,
};

#ifndef WIN32

#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

/**
 * Private data of an process_t object.
 */
struct private_process_t {

	/**
	 * Public process_t interface.
	 */
	process_t public;

	/**
	 * child stdin pipe
	 */
	int in[PIPE_ENDS];

	/**
	 * child stdout pipe
	 */
	int out[PIPE_ENDS];

	/**
	 * child stderr pipe
	 */
	int err[PIPE_ENDS];

	/**
	 * child process
	 */
	int pid;
};

/**
 * Close a file descriptor if it is not -1
 */
static void close_if(int *fd)
{
	if (*fd != -1)
	{
		close(*fd);
		*fd = -1;
	}
}

/**
 * Destroy a process structure, close all pipes
 */
static void process_destroy(private_process_t *this)
{
	close_if(&this->in[PIPE_READ]);
	close_if(&this->in[PIPE_WRITE]);
	close_if(&this->out[PIPE_READ]);
	close_if(&this->out[PIPE_WRITE]);
	close_if(&this->err[PIPE_READ]);
	close_if(&this->err[PIPE_WRITE]);
	free(this);
}

METHOD(process_t, wait_, bool,
	private_process_t *this, int *code)
{
	int status, ret;

	ret = waitpid(this->pid, &status, 0);
	process_destroy(this);
	if (ret == -1)
	{
		return FALSE;
	}
	if (!WIFEXITED(status))
	{
		return FALSE;
	}
	if (code)
	{
		*code = WEXITSTATUS(status);
	}
	return TRUE;
}

/**
 * See header
 */
process_t* process_start(char *const argv[], char *const envp[],
						 int *in, int *out, int *err, bool close_all)
{
	private_process_t *this;
	char *empty[] = { NULL };

	INIT(this,
		.public = {
			.wait = _wait_,
		},
		.in = { -1, -1 },
		.out = { -1, -1 },
		.err = { -1, -1 },
	);

	if (in && pipe(this->in) != 0)
	{
		DBG1(DBG_LIB, "creating stdin pipe failed: %s", strerror(errno));
		process_destroy(this);
		return NULL;
	}
	if (out && pipe(this->out) != 0)
	{
		DBG1(DBG_LIB, "creating stdout pipe failed: %s", strerror(errno));
		process_destroy(this);
		return NULL;
	}
	if (err && pipe(this->err) != 0)
	{
		DBG1(DBG_LIB, "creating stderr pipe failed: %s", strerror(errno));
		process_destroy(this);
		return NULL;
	}

	this->pid = fork();
	switch (this->pid)
	{
		case -1:
			DBG1(DBG_LIB, "forking process failed: %s", strerror(errno));
			process_destroy(this);
			return NULL;
		case 0:
			/* child */
			close_if(&this->in[PIPE_WRITE]);
			close_if(&this->out[PIPE_READ]);
			close_if(&this->err[PIPE_READ]);
			if (this->in[PIPE_READ] != -1)
			{
				if (dup2(this->in[PIPE_READ], 0) == -1)
				{
					raise(SIGKILL);
				}
			}
			if (this->out[PIPE_WRITE] != -1)
			{
				if (dup2(this->out[PIPE_WRITE], 1) == -1)
				{
					raise(SIGKILL);
				}
			}
			if (this->err[PIPE_WRITE] != -1)
			{
				if (dup2(this->err[PIPE_WRITE], 2) == -1)
				{
					raise(SIGKILL);
				}
			}
			if (close_all)
			{
				closefrom(3);
			}
			if (execve(argv[0], argv, envp ?: empty) == -1)
			{
				raise(SIGKILL);
			}
			/* not reached */
		default:
			/* parent */
			close_if(&this->in[PIPE_READ]);
			close_if(&this->out[PIPE_WRITE]);
			close_if(&this->err[PIPE_WRITE]);
			if (in)
			{
				*in = this->in[PIPE_WRITE];
				this->in[PIPE_WRITE] = -1;
			}
			if (out)
			{
				*out = this->out[PIPE_READ];
				this->out[PIPE_READ] = -1;
			}
			if (err)
			{
				*err = this->err[PIPE_READ];
				this->err[PIPE_READ] = -1;
			}
			return &this->public;
	}
}

#else /* WIN32 */

/**
 * See header
 */
process_t* process_start(char *const argv[], char *const envp[],
						 int *in, int *out, int *err, bool close_all)
{
	return NULL;
}

#endif /* WIN32 */
