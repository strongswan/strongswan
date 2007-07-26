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
#include <unistd.h>
#include <stdio.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

#include <debug.h>
#include <utils/linked_list.h>

#include "dumm.h"
#include "guest.h"
#include "mconsole.h"

typedef struct private_guest_t private_guest_t;

struct private_guest_t {
	/** implemented public interface */
	guest_t public;
	/** name of the guest */
	char *name;
	/** read only master filesystem guest uses */
	char *master;
	/** amount of memory for guest, in MB */
	int mem;
	/** pid of guest child process */
	int pid;
	/** state of guest */
	guest_state_t state;
	/** log file for console 0 */
	int bootlog;
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
	
	if (this->pid == 0)
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
 * Implementation of guest_t.start.
 */
static bool start(private_guest_t *this, char *kernel)
{
	char buf[1024];
	char cwd[512];
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
	
	notify = write_arg(&pos, &left, "%s/%s/notify", RUN_DIR, this->name);
	
	args[i++] = kernel;
	args[i++] = write_arg(&pos, &left, "root=/dev/root");
	args[i++] = write_arg(&pos, &left, "rootfstype=hostfs");
	args[i++] = write_arg(&pos, &left, "rootflags=%s/%s/%s",
						  getcwd(cwd, sizeof(cwd)), MOUNT_DIR, this->name);
	args[i++] = write_arg(&pos, &left, "uml_dir=%s/%s", RUN_DIR, this->name);
	args[i++] = write_arg(&pos, &left, "umid=%s", this->name);
	args[i++] = write_arg(&pos, &left, "mem=%dM", this->mem);
	args[i++] = write_arg(&pos, &left, "mconsole=notify:%s", notify);
	/*args[i++] = write_arg(&pos, &left, "con=pts");*/
	args[i++] = write_arg(&pos, &left, "con0=null,fd:%d", this->bootlog);
	/*args[i++] = write_arg(&pos, &left, "con1=fd:0,fd:1");*/
	args[i++] = write_arg(&pos, &left, "con2=null,null");
	args[i++] = write_arg(&pos, &left, "con3=null,null");
	args[i++] = write_arg(&pos, &left, "con4=null,null");
	args[i++] = write_arg(&pos, &left, "con5=null,null");
	args[i++] = write_arg(&pos, &left, "con6=null,null");
	args[i++] = NULL;
	  
	this->pid = fork();
	switch (this->pid)
	{
		case 0: /* child,  */
			dup2(open("/dev/null", 0), 0);
			dup2(open("/dev/null", 0), 1);
			dup2(open("/dev/null", 0), 2);
			execvp(args[0], args);
			DBG1("starting UML kernel '%s' failed", args[0]);
			exit(1);
		case -1:
			this->pid = 0;
			return FALSE;
		default:
			break;
	}
	/* open mconsole */
	this->mconsole = mconsole_create(notify);
	if (this->mconsole == NULL)
	{
		DBG1("opening mconsole at '%s' failed, stopping guest", buf);
		kill(this->pid, SIGINT);
		this->pid = 0;
		return FALSE;
	}
	this->state = GUEST_RUNNING;
	return TRUE;
}

/**
 * Implementation of guest_t.stop.
 */
static void stop(private_guest_t *this)
{
	if (this->pid)
	{
		kill(this->pid, SIGINT);
		this->pid = 0;
	}
}

/**
 * Check if directory exists, create otherwise
 */
static bool makedir(char *dir, char *name)
{
	struct stat st;
	char buf[256];
	size_t len;
	
	len = snprintf(buf, sizeof(buf), "%s/%s", dir, name);
	if (len < 0 || len >= sizeof(buf))
	{
		return FALSE;
	}
	if (stat(buf, &st) != 0)
	{
		return mkdir(buf, S_IRWXU) == 0;
	}
	return S_ISDIR(st.st_mode);
}

/**
 * umount the union filesystem
 */
static bool umount_unionfs(char *name)
{
	char cmd[128];
	size_t len;
	
	len = snprintf(cmd, sizeof(cmd), "fusermount -u %s/%s", MOUNT_DIR, name);
	if (len < 0 || len >= sizeof(cmd))
	{
		return FALSE;
	}
	if (system(cmd) != 0)
	{
		DBG1("unmounting guest unionfs for %s failed", name);
		return FALSE;
	}
	return TRUE;
}

/**
 * mount the union filesystem
 */
static bool mount_unionfs(char *name, char *master)
{
	char cmd[256];
	size_t len;
	
	len = snprintf(cmd, sizeof(cmd), "unionfs %s/%s:%s %s/%s",
				   HOST_DIR, name, master, MOUNT_DIR, name);
	if (len < 0 || len >= sizeof(cmd))
	{
		return FALSE;
	}
	if (system(cmd) != 0)
	{
		DBG1("mounting guest unionfs for %s using '%s' failed", name, cmd);
		return FALSE;
	}
	return TRUE;
}

/**
 * open logfile for boot messages
 */
static int open_bootlog(char *name)
{
	char blg[256];
	size_t len;
	int fd;
	
	len = snprintf(blg, sizeof(blg), "%s/%s/boot.log", RUN_DIR, name);
	if (len < 0 || len >= sizeof(blg))
	{
		return 1;
	}
	fd = open(blg, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		DBG1("opening bootlog '%s' for %s failed, using stdout", blg, name);
		return 1;
	}
	return fd;
}

/**
 * Implementation of guest_t.destroy.
 */
static void destroy(private_guest_t *this)
{
	stop(this);
	umount_unionfs(this->name);
	this->ifaces->destroy_offset(this->ifaces, offsetof(iface_t, destroy));
	DESTROY_IF(this->mconsole);
	free(this->name);
	free(this->master);
	free(this);
}

/**
 * create the guest instance, including required dirs and mounts 
 */
guest_t *guest_create(char *name, char *master, int mem)
{
	private_guest_t *this = malloc_thing(private_guest_t);
	
	this->public.get_name = (void*)get_name;
	this->public.get_pid = (pid_t(*)(guest_t*))get_pid;
	this->public.get_state = (guest_state_t(*)(guest_t*))get_state;
	this->public.create_iface = (iface_t*(*)(guest_t*,char*))create_iface;
	this->public.create_iface_iterator = (iterator_t*(*)(guest_t*))create_iface_iterator;
	this->public.start = (void*)start;
	this->public.stop = (void*)stop;
	this->public.destroy = (void*)destroy;
	
	if (!makedir(HOST_DIR, name) || !makedir(MOUNT_DIR, name) ||
		!makedir(RUN_DIR, name) || !mount_unionfs(name, master))
	{
		free(this);
		return NULL;
	}
	
	this->name = strdup(name);
	this->master = strdup(master);
	this->mem = mem;
	this->pid = 0;
	this->state = GUEST_STOPPED;
	this->bootlog = open_bootlog(name);
	this->mconsole = NULL;
	this->ifaces = linked_list_create();

	return &this->public;
}

