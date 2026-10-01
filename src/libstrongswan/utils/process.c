/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2014 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

/* vasprintf() */
#define _GNU_SOURCE
#include "process.h"

#include <library.h>
#include <utils/debug.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>

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

/* use posix_spawn() if we can close all open fds > 2, either via the
 * proprietary glibc function or the proprietary macOS flag */
#if defined(HAVE_POSIX_SPAWN) && \
	(defined(HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP) || \
	 HAVE_DECL_POSIX_SPAWN_CLOEXEC_DEFAULT)
#define USE_POSIX_SPAWN 1
#endif

#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef USE_POSIX_SPAWN
#include <spawn.h>
#endif

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

#ifdef USE_POSIX_SPAWN
/**
 * Handles the two ends of a pipe appropriately, dup the one in "from" to "to"
 * and close both ends (unless there is an overlap).
 */
static inline int add_pipe_actions(posix_spawn_file_actions_t *actions,
								   int pipe[PIPE_ENDS], int from, int to)
{
	int other = (from == PIPE_READ) ? PIPE_WRITE : PIPE_READ, ret = 0;

	if (pipe[other] != -1)
	{
		ret = posix_spawn_file_actions_addclose(actions,
												pipe[other]);
	}
	if (!ret && pipe[from] != -1)
	{
		ret = posix_spawn_file_actions_adddup2(actions,
											   pipe[from], to);
		if (!ret && pipe[from] != to)
		{
			ret = posix_spawn_file_actions_addclose(actions,
													pipe[from]);
		}
	}
	return ret;
}

/**
 * Use posix_spawn() to start the process, which has the advantage of avoiding
 * several issues with fork(), in particular on macOS where atfork handlers in
 * system libraries use allocations that can interfere with e.g. ASan's wrappers
 * and the locks they use.
 */
static bool process_spawn(private_process_t *this, char *const argv[],
						  char *const envp[], bool close_all)
{
	posix_spawn_file_actions_t actions;
	posix_spawnattr_t attr;
	pid_t pid;
	int ret = 0;

	if (posix_spawn_file_actions_init(&actions) != 0)
	{
		return FALSE;
	}
	if (posix_spawnattr_init(&attr) != 0)
	{
		posix_spawn_file_actions_destroy(&actions);
		return FALSE;
	}
	if (!ret)
	{
		ret = add_pipe_actions(&actions, this->in, PIPE_READ, 0);
	}
	if (!ret)
	{
		ret = add_pipe_actions(&actions, this->out, PIPE_WRITE, 1);
	}
	if (!ret)
	{
		ret = add_pipe_actions(&actions, this->err, PIPE_WRITE, 2);
	}
	if (!ret && close_all)
	{
#ifdef HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP
		ret = posix_spawn_file_actions_addclosefrom_np(&actions, 3);
#elif HAVE_DECL_POSIX_SPAWN_CLOEXEC_DEFAULT
		ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
#ifdef HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDINHERIT_NP
		/* the above includes FDs 0-2 on macOS (but not on Android), so inherit
		 * them if they are not redirected to preserve the behavior seen on
		 * other platforms and with the fork fallback */
		if (!ret && this->in[PIPE_READ] == -1)
		{
			ret = posix_spawn_file_actions_addinherit_np(&actions, 0);
		}
		if (!ret && this->out[PIPE_WRITE] == -1)
		{
			ret = posix_spawn_file_actions_addinherit_np(&actions, 1);
		}
		if (!ret && this->err[PIPE_WRITE] == -1)
		{
			ret = posix_spawn_file_actions_addinherit_np(&actions, 2);
		}
#endif
#endif
	}
	if (!ret)
	{
		ret = posix_spawn(&pid, argv[0], &actions, &attr, argv, envp);
	}
	posix_spawn_file_actions_destroy(&actions);
	posix_spawnattr_destroy(&attr);
	if (ret)
	{
		DBG1(DBG_LIB, "spawning process failed: %s", strerror(ret));
		return FALSE;
	}
	this->pid = pid;
	return TRUE;
}
#endif

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

#ifdef USE_POSIX_SPAWN
	if (!process_spawn(this, argv, envp ?: empty, close_all))
	{
		process_destroy(this);
		return NULL;
	}
#else
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
				if (this->in[PIPE_READ] != 0)
				{
					close(this->in[PIPE_READ]);
				}
			}
			if (this->out[PIPE_WRITE] != -1)
			{
				if (dup2(this->out[PIPE_WRITE], 1) == -1)
				{
					raise(SIGKILL);
				}
				if (this->out[PIPE_WRITE] != 1)
				{
					close(this->out[PIPE_WRITE]);
				}
			}
			if (this->err[PIPE_WRITE] != -1)
			{
				if (dup2(this->err[PIPE_WRITE], 2) == -1)
				{
					raise(SIGKILL);
				}
				if (this->err[PIPE_WRITE] != 2)
				{
					close(this->err[PIPE_WRITE]);
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
			break;
	}
#endif

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

/**
 * See header
 */
process_t* process_start_shell(char *const envp[], int *in, int *out, int *err,
							   char *fmt, ...)
{
	char *argv[] = {
		"/bin/sh",
		"-c",
		NULL,
		NULL
	};
	process_t *process;
	va_list args;
	int len;

	va_start(args, fmt);
	len = vasprintf(&argv[2], fmt, args);
	va_end(args);
	if (len < 0)
	{
		return NULL;
	}

	process = process_start(argv, envp, in, out, err, TRUE);
	free(argv[2]);
	return process;
}

#else /* WIN32 */

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
	HANDLE in[PIPE_ENDS];

	/**
	 * child stdout pipe
	 */
	HANDLE out[PIPE_ENDS];

	/**
	 * child stderr pipe
	 */
	HANDLE err[PIPE_ENDS];

	/**
	 * child process information
	 */
	PROCESS_INFORMATION pi;
};

/**
 * Clean up state associated to child process
 */
static void process_destroy(private_process_t *this)
{
	if (this->in[PIPE_READ])
	{
		CloseHandle(this->in[PIPE_READ]);
	}
	if (this->in[PIPE_WRITE])
	{
		CloseHandle(this->in[PIPE_WRITE]);
	}
	if (this->out[PIPE_READ])
	{
		CloseHandle(this->out[PIPE_READ]);
	}
	if (this->out[PIPE_WRITE])
	{
		CloseHandle(this->out[PIPE_WRITE]);
	}
	if (this->err[PIPE_READ])
	{
		CloseHandle(this->err[PIPE_READ]);
	}
	if (this->err[PIPE_WRITE])
	{
		CloseHandle(this->err[PIPE_WRITE]);
	}
	if (this->pi.hProcess)
	{
		CloseHandle(this->pi.hProcess);
		CloseHandle(this->pi.hThread);
	}
	free(this);
}

METHOD(process_t, wait_, bool,
	private_process_t *this, int *code)
{
	DWORD ec;

	if (WaitForSingleObject(this->pi.hProcess, INFINITE) != WAIT_OBJECT_0)
	{
		DBG1(DBG_LIB, "waiting for child process failed: 0x%08x",
			 GetLastError());
		process_destroy(this);
		return FALSE;
	}
	if (code)
	{
		if (!GetExitCodeProcess(this->pi.hProcess, &ec))
		{
			DBG1(DBG_LIB, "getting child process exit code failed: 0x%08x",
				 GetLastError());
			process_destroy(this);
			return FALSE;
		}
		*code = ec;
	}
	process_destroy(this);
	return TRUE;
}

/**
 * Append a command line argument to buf, optionally quoted
 */
static void append_arg(char *buf, u_int len, char *arg, char *quote)
{
	char *space = "";
	int current;

	current = strlen(buf);
	if (current)
	{
		space = " ";
	}
	snprintf(buf + current, len - current, "%s%s%s%s", space, quote, arg, quote);
}

/**
 * Append a null-terminate env string to buf
 */
static void append_env(char *buf, u_int len, char *env)
{
	char *pos = buf;
	int current;

	while (TRUE)
	{
		pos += strlen(pos);
		if (!pos[1])
		{
			if (pos == buf)
			{
				current = 0;
			}
			else
			{
				current = pos - buf + 1;
			}
			snprintf(buf + current, len - current, "%s", env);
			break;
		}
		pos++;
	}
}

/**
 * See header
 */
process_t* process_start(char *const argv[], char *const envp[],
						 int *in, int *out, int *err, bool close_all)
{
	private_process_t *this;
	char arg[32768], env[32768];
	SECURITY_ATTRIBUTES sa = {
		.nLength = sizeof(SECURITY_ATTRIBUTES),
		.bInheritHandle = TRUE,
	};
	STARTUPINFO sui = {
		.cb = sizeof(STARTUPINFO),
	};
	int i;

	memset(arg, 0, sizeof(arg));
	memset(env, 0, sizeof(env));

	for (i = 0; argv[i]; i++)
	{
		if (!strchr(argv[i], ' '))
		{	/* no spaces, fine for appending */
			append_arg(arg, sizeof(arg) - 1, argv[i], "");
		}
		else if (argv[i][0] == '"' &&
				 argv[i][strlen(argv[i]) - 1] == '"' &&
				 strchr(argv[i] + 1, '"') == argv[i] + strlen(argv[i]) - 1)
		{	/* already properly quoted */
			append_arg(arg, sizeof(arg) - 1, argv[i], "");
		}
		else if (strchr(argv[i], ' ') && !strchr(argv[i], '"'))
		{	/* spaces, but no quotes; append quoted */
			append_arg(arg, sizeof(arg) - 1, argv[i], "\"");
		}
		else
		{
			DBG1(DBG_LIB, "invalid command line argument: %s", argv[i]);
			return NULL;
		}
	}
	if (envp)
	{
		for (i = 0; envp[i]; i++)
		{
			append_env(env, sizeof(env) - 1, envp[i]);
		}
	}

	INIT(this,
		.public = {
			.wait = _wait_,
		},
	);

	if (in)
	{
		sui.dwFlags = STARTF_USESTDHANDLES;
		if (!CreatePipe(&this->in[PIPE_READ], &this->in[PIPE_WRITE], &sa, 0))
		{
			process_destroy(this);
			return NULL;
		}
		if (!SetHandleInformation(this->in[PIPE_WRITE], HANDLE_FLAG_INHERIT, 0))
		{
			process_destroy(this);
			return NULL;
		}
		sui.hStdInput = this->in[PIPE_READ];
		*in = _open_osfhandle((uintptr_t)this->in[PIPE_WRITE], 0);
		if (*in == -1)
		{
			process_destroy(this);
			return NULL;
		}
	}
	if (out)
	{
		sui.dwFlags = STARTF_USESTDHANDLES;
		if (!CreatePipe(&this->out[PIPE_READ], &this->out[PIPE_WRITE], &sa, 0))
		{
			process_destroy(this);
			return NULL;
		}
		if (!SetHandleInformation(this->out[PIPE_READ], HANDLE_FLAG_INHERIT, 0))
		{
			process_destroy(this);
			return NULL;
		}
		sui.hStdOutput = this->out[PIPE_WRITE];
		*out = _open_osfhandle((uintptr_t)this->out[PIPE_READ], 0);
		if (*out == -1)
		{
			process_destroy(this);
			return NULL;
		}
	}
	if (err)
	{
		sui.dwFlags = STARTF_USESTDHANDLES;
		if (!CreatePipe(&this->err[PIPE_READ], &this->err[PIPE_WRITE], &sa, 0))
		{
			process_destroy(this);
			return NULL;
		}
		if (!SetHandleInformation(this->err[PIPE_READ], HANDLE_FLAG_INHERIT, 0))
		{
			process_destroy(this);
			return NULL;
		}
		sui.hStdError = this->err[PIPE_WRITE];
		*err = _open_osfhandle((uintptr_t)this->err[PIPE_READ], 0);
		if (*err == -1)
		{
			process_destroy(this);
			return NULL;
		}
	}

	if (!CreateProcess(argv[0], arg, NULL, NULL, TRUE,
					   NORMAL_PRIORITY_CLASS, env, NULL, &sui, &this->pi))
	{
		DBG1(DBG_LIB, "creating process '%s' failed: 0x%08x",
			 argv[0], GetLastError());
		process_destroy(this);
		return NULL;
	}

	/* close child process end of pipes */
	if (this->in[PIPE_READ])
	{
		CloseHandle(this->in[PIPE_READ]);
		this->in[PIPE_READ] = NULL;
	}
	if (this->out[PIPE_WRITE])
	{
		CloseHandle(this->out[PIPE_WRITE]);
		this->out[PIPE_WRITE] = NULL;
	}
	if (this->err[PIPE_WRITE])
	{
		CloseHandle(this->err[PIPE_WRITE]);
		this->err[PIPE_WRITE] = NULL;
	}
	/* our side gets closed over the osf_handle closed by caller */
	this->in[PIPE_WRITE] = NULL;
	this->out[PIPE_READ] = NULL;
	this->err[PIPE_READ] = NULL;
	return &this->public;
}

/**
 * See header
 */
process_t* process_start_shell(char *const envp[], int *in, int *out, int *err,
							   char *fmt, ...)
{
	char path[MAX_PATH], *exe = "system32\\cmd.exe";
	char *argv[] = {
		path,
		"/C",
		NULL,
		NULL
	};
	process_t *process;
	va_list args;
	int len;

	len = GetSystemWindowsDirectory(path, sizeof(path));
	if (len == 0 || len >= sizeof(path) - strlen(exe))
	{
		DBG1(DBG_LIB, "resolving Windows directory failed: 0x%08x",
			 GetLastError());
		return NULL;
	}
	if (path[len - 1] != '\\')
	{
		strncat(path, "\\", sizeof(path) - len++);
	}
	strncat(path, exe, sizeof(path) - len);

	va_start(args, fmt);
	len = vasprintf(&argv[2], fmt, args);
	va_end(args);
	if (len < 0)
	{
		return NULL;
	}

	process = process_start(argv, envp, in, out, err, TRUE);
	free(argv[2]);
	return process;
}

#endif /* WIN32 */
