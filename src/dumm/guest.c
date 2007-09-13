/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <termios.h>

#include <debug.h>
#include <utils/linked_list.h>

#include "dumm.h"
#include "guest.h"
#include "mconsole.h"
#include "cowfs.h"

#define PERME (S_IRWXU | S_IRWXG)
#define PERM (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define MASTER_DIR "master"
#define DIFF_DIR "diff"
#define UNION_DIR "union"
#define MEMORY_FILE "mem"
#define KERNEL_FILE "linux"
#define LOG_FILE "boot.log"
#define NOTIFY_FILE "notify"
#define PTYS 0

typedef struct private_guest_t private_guest_t;

struct private_guest_t {
	/** implemented public interface */
	guest_t public;
	/** name of the guest */
	char *name;
	/** directory of guest */
	int dir;
	/** directory name of guest */
	char *dirname;
	/** amount of memory for guest, in MB */
	int mem;
	/** pid of guest child process */
	int pid;
	/** state of guest */
	guest_state_t state;
	/** log file for console 0 */
	int bootlog;
	/** FUSE cowfs instance */
	cowfs_t *cowfs;
	/** mconsole to control running UML */
	mconsole_t *mconsole;
	/** list of interfaces attached to the guest */
	linked_list_t *ifaces;
};

ENUM(guest_state_names, GUEST_STOPPED, GUEST_STOPPING,
	"STOPPED",
	"STARTING",
	"RUNNING",
	"PAUSED",
	"STOPPING",
);

/**
 * Implementation of guest_t.get_name.
 */
static char* get_name(private_guest_t *this)
{
	return this->name;
}

/**
 * Implementation of guest_t.create_iface.
 */
static iface_t* create_iface(private_guest_t *this, char *name)
{
	iterator_t *iterator;
	iface_t *iface;
	
	if (this->state != GUEST_RUNNING)
	{
		DBG1("guest '%s' not running, unable to add interface", this->name);
		return NULL;
	}
	
	iterator = this->ifaces->create_iterator(this->ifaces, TRUE);
	while (iterator->iterate(iterator, (void**)&iface))
	{
		if (streq(name, iface->get_guestif(iface)))
		{
			DBG1("guest '%s' already has an interface '%s'", this->name, name);
			iterator->destroy(iterator);
			return NULL;
		}
	}
	iterator->destroy(iterator);

	iface = iface_create(this->name, name, this->mconsole);
	if (iface)
	{
		this->ifaces->insert_last(this->ifaces, iface);
	}
	return iface;
}

/**
 * Implementation of guest_t.create_iface_iterator.
 */
static iterator_t* create_iface_iterator(private_guest_t *this)
{
	return this->ifaces->create_iterator(this->ifaces, TRUE);
}
	
/**
 * Implementation of guest_t.get_state.
 */
static guest_state_t get_state(private_guest_t *this)
{
	return this->state;
}

/**
 * Implementation of guest_t.get_pid.
 */
static pid_t get_pid(private_guest_t *this)
{
	return this->pid;
}

/**
 * write format string to a buffer, and advance buffer position
 */
static char* write_arg(char **pos, size_t *left, char *format, ...)
{
	size_t len;
	char *res = NULL;
	va_list args;

	va_start(args, format);
	len = vsnprintf(*pos, *left, format, args);
	va_end(args);
	if (len < *left)
	{
		res = *pos;
		len++;
		*pos += len + 1;
		*left -= len + 1;
	}
	return res;
}

/**
 * Implementation of get_t.close_console.
 */
static char* get_console(private_guest_t *this, int console)
{
	if (this->state == GUEST_RUNNING)
	{
		return this->mconsole->get_console_pts(this->mconsole, console);
	}
	return NULL;
}

/**
 * Implementation of guest_t.stop.
 */
static void stop(private_guest_t *this)
{
	if (this->state != GUEST_STOPPED)
	{
		this->state = GUEST_STOPPING;
		this->ifaces->destroy_offset(this->ifaces, offsetof(iface_t, destroy));
		this->ifaces = linked_list_create();
		kill(this->pid, SIGINT);
		waitpid(this->pid, NULL, 0);
		this->state = GUEST_STOPPED;
	}
}

/**
 * Implementation of guest_t.start.
 */
static bool start(private_guest_t *this)
{
	char buf[2048];
	char *notify;
	char *pos = buf;
	char *args[16];
	int i = 0;
	size_t left = sizeof(buf);
	
	if (this->state != GUEST_STOPPED)
	{
		DBG1("unable to start guest in state %N", guest_state_names, this->state);
		return FALSE;
	}
	this->state = GUEST_STARTING;
	
	notify = write_arg(&pos, &left, "%s/%s", this->dirname, NOTIFY_FILE);
	
	args[i++] = write_arg(&pos, &left, "%s/%s", this->dirname, KERNEL_FILE);
	args[i++] = write_arg(&pos, &left, "root=/dev/root");
	args[i++] = write_arg(&pos, &left, "rootfstype=hostfs");
	args[i++] = write_arg(&pos, &left, "rootflags=%s/%s", this->dirname, UNION_DIR);
	args[i++] = write_arg(&pos, &left, "uml_dir=%s", this->dirname);
	args[i++] = write_arg(&pos, &left, "umid=%s", this->name);
	args[i++] = write_arg(&pos, &left, "mem=%dM", this->mem);
	args[i++] = write_arg(&pos, &left, "mconsole=notify:%s", notify);
	args[i++] = write_arg(&pos, &left, "con=pts");
	args[i++] = write_arg(&pos, &left, "con0=none,fd:%d", this->bootlog);
	args[i++] = NULL;
	  
	this->pid = fork();
	switch (this->pid)
	{
		case 0: /* child,  */
			dup2(open("/dev/null", 0), 0);
			dup2(this->bootlog, 1);
			dup2(this->bootlog, 2);
			execvp(args[0], args);
			DBG1("starting UML kernel '%s' failed: %m", args[0]);
			exit(1);
		case -1:
			this->state = GUEST_STOPPED;
			return FALSE;
		default:
			break;
	}
	/* open mconsole */
	this->mconsole = mconsole_create(notify);
	if (this->mconsole == NULL)
	{
		DBG1("opening mconsole at '%s' failed, stopping guest", buf);
		stop(this);
		return FALSE;
	}
	
	this->state = GUEST_RUNNING;
	return TRUE;
}	
	
/**
 * Implementation of guest_t.load_template.
 */
static bool load_template(private_guest_t *this, char *path)
{
	char dir[PATH_MAX];
	size_t len;
	
	if (path == NULL)
	{
		return this->cowfs->set_overlay(this->cowfs, NULL);	
	}
	
	len = snprintf(dir, sizeof(dir), "%s/%s", path, this->name);
	if (len < 0 || len >= sizeof(dir))
	{
		return FALSE;
	}
	if (access(dir, F_OK) != 0)
	{
		if (mkdir(dir, PERME) != 0)
		{
			DBG1("creating overlay for guest '%s' failed: %m", this->name);
			return FALSE;
		}
	}
	return this->cowfs->set_overlay(this->cowfs, dir);
}

/**
 * Implementation of guest_t.sigchild.
 */
static void sigchild(private_guest_t *this)
{
	if (this->state != GUEST_STOPPING)
	{	/* collect zombie if uml crashed */
		waitpid(this->pid, NULL, WNOHANG);
	}
	DESTROY_IF(this->mconsole);
	this->mconsole = NULL;
	this->state = GUEST_STOPPED;
}

/**
 * umount the union filesystem
 */
static bool umount_unionfs(private_guest_t *this)
{
	if (this->cowfs)
	{
		this->cowfs->destroy(this->cowfs);
		this->cowfs = NULL;
		return TRUE;
	}
	return FALSE;
}

/**
 * mount the union filesystem
 */
static bool mount_unionfs(private_guest_t *this)
{
	char master[PATH_MAX];
	char diff[PATH_MAX];
	char mount[PATH_MAX];

	if (this->cowfs == NULL)
	{
		snprintf(master, sizeof(master), "%s/%s", this->dirname, MASTER_DIR);
		snprintf(diff, sizeof(diff), "%s/%s", this->dirname, DIFF_DIR);
		snprintf(mount, sizeof(mount), "%s/%s", this->dirname, UNION_DIR);
		
		this->cowfs = cowfs_create(master, diff, mount);
		if (this->cowfs)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * open logfile for boot messages
 */
static int open_bootlog(private_guest_t *this)
{
	int fd;
	
	fd = openat(this->dir, LOG_FILE, O_WRONLY | O_CREAT, PERM);
	if (fd == -1)
	{
		DBG1("opening bootlog failed, using stdout");
		return 1;
	}
	return fd;
}

/**
 * load memory configuration from file
 */
int loadmem(private_guest_t *this)
{
	FILE *file;
	int mem = 0;
	
	file = fdopen(openat(this->dir, MEMORY_FILE, O_RDONLY, PERM), "r");
	if (file)
	{
		if (fscanf(file, "%d", &mem) <= 0)
		{
			mem = 0;
		}
		fclose(file);
	}
	return mem;
}

/**
 * save memory configuration to file
 */
bool savemem(private_guest_t *this, int mem)
{
	FILE *file;
	bool retval = FALSE;
	
	file = fdopen(openat(this->dir, MEMORY_FILE, O_RDWR | O_CREAT | O_TRUNC,
						 PERM), "w");
	if (file)
	{
		if (fprintf(file, "%d", mem) > 0)
		{
			retval = TRUE;
		}
		fclose(file);
	}
	return retval;
}

/**
 * Implementation of guest_t.destroy.
 */
static void destroy(private_guest_t *this)
{
	stop(this);
	umount_unionfs(this);
	if (this->bootlog > 1)
	{
		close(this->bootlog);
	}
	if (this->dir > 0)
	{
		close(this->dir);
	}
	free(this->dirname);
	free(this->name);
	free(this);
}

/**
 * generic guest constructor
 */
static private_guest_t *guest_create_generic(char *parent, char *name,
											 bool create)
{
	char cwd[PATH_MAX];
	private_guest_t *this = malloc_thing(private_guest_t);
	
	this->public.get_name = (void*)get_name;
	this->public.get_pid = (pid_t(*)(guest_t*))get_pid;
	this->public.get_state = (guest_state_t(*)(guest_t*))get_state;
	this->public.create_iface = (iface_t*(*)(guest_t*,char*))create_iface;
	this->public.create_iface_iterator = (iterator_t*(*)(guest_t*))create_iface_iterator;
	this->public.start = (void*)start;
	this->public.stop = (void*)stop;
	this->public.get_console = (char*(*)(guest_t*,int))get_console;
	this->public.load_template = (bool(*)(guest_t*, char *path))load_template;
	this->public.sigchild = (void(*)(guest_t*))sigchild;
	this->public.destroy = (void*)destroy;
		
	if (*parent == '/' || getcwd(cwd, sizeof(cwd)) == NULL)
	{
		asprintf(&this->dirname, "%s/%s", parent, name);
	}
	else
	{
		asprintf(&this->dirname, "%s/%s/%s", cwd, parent, name);
	}
	if (create)
	{
		mkdir(this->dirname, PERME);
	}
	this->dir = open(this->dirname, O_DIRECTORY, PERME);
	if (this->dir < 0)
	{
		DBG1("opening guest directory '%s' failed: %m", this->dirname);
		free(this->dirname);
		free(this);
		return NULL;
	}
	
	this->pid = 0;
	this->state = GUEST_STOPPED;
	this->mconsole = NULL;
	this->ifaces = linked_list_create();
	this->mem = 0;
	this->bootlog = open_bootlog(this);
	this->name = strdup(name);
	this->cowfs = NULL;
	
	return this;
}

/**
 * create a symlink to old called new in our working dir
 */
static bool make_symlink(private_guest_t *this, char *old, char *new)
{
	char cwd[PATH_MAX];
	char buf[PATH_MAX];
	
	if (*old == '/' || getcwd(cwd, sizeof(cwd)) == NULL)
	{
		snprintf(buf, sizeof(buf), "%s", old);
	}
	else
	{
		snprintf(buf, sizeof(buf), "%s/%s", cwd, old);
	}
	return symlinkat(buf, this->dir, new) == 0;
}


/**
 * create the guest instance, including required dirs and mounts 
 */
guest_t *guest_create(char *parent, char *name, char *kernel,
					  char *master, int mem)
{
	private_guest_t *this = guest_create_generic(parent, name, TRUE);
	
	if (this == NULL)
	{
		return NULL;
	}
	
	if (!make_symlink(this, master, MASTER_DIR) ||
		!make_symlink(this, kernel, KERNEL_FILE))
	{
		DBG1("creating master/kernel symlink failed: %m");
		destroy(this);
		return NULL;
	}
	
	if (mkdirat(this->dir, UNION_DIR, PERME) != 0 || 
		mkdirat(this->dir, DIFF_DIR, PERME) != 0)
	{
		DBG1("unable to create directories for '%s': %m", name);
		destroy(this);
		return NULL;
	}
	
	this->mem = mem;
	if (!savemem(this, mem))
	{
		destroy(this);
		return NULL;
	}
	
	if (!mount_unionfs(this))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

/**
 * load an already created guest
 */
guest_t *guest_load(char *parent, char *name)
{
	private_guest_t *this = guest_create_generic(parent, name, FALSE);
	
	if (this == NULL)
	{
		return NULL;
	}
	
	this->mem = loadmem(this);
	if (this->mem == 0)
	{
		DBG1("unable to open memory configuration file: %m", name);
		destroy(this);
		return NULL;
	}
	
	if (!mount_unionfs(this))
	{
		destroy(this);
		return NULL;
	}
	
	return &this->public;
}

