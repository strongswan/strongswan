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

#include "dumm.h"
#include "guest.h"

typedef struct private_guest_t private_guest_t;

struct private_guest_t {
	guest_t public;
	char *name;
	char *kernel;
	char *master;
	int mem;
	int pid;
	int bootlog;
};

static char* get_name(private_guest_t *this)
{
	return this->name;
}

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

static bool start(private_guest_t *this)
{
	char buf[1024];
	char cwd[512];
	char *pos = buf;
	char *args[16];
	int i = 0;
	size_t left = sizeof(buf);

	args[i++] = this->kernel;
	args[i++] = write_arg(&pos, &left, "root=/dev/root");
	args[i++] = write_arg(&pos, &left, "rootfstype=hostfs");
	args[i++] = write_arg(&pos, &left, "rootflags=%s/%s/%s",
						  getcwd(cwd, sizeof(cwd)), MOUNT_DIR, this->name);
	args[i++] = write_arg(&pos, &left, "uml_dir=%s/%s", RUN_DIR, this->name);
	args[i++] = write_arg(&pos, &left, "umid=%s", this->name);
	args[i++] = write_arg(&pos, &left, "mem=%dM", this->mem);
	//args[i++] = write_arg(&pos, &left, "con=pts");
	args[i++] = write_arg(&pos, &left, "con0=null,fd:%d", this->bootlog);
	args[i++] = write_arg(&pos, &left, "con1=fd:0,fd:1");
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
			exit(1);
		case -1:
			this->pid = 0;
			return FALSE;
		default:
			return TRUE;
	}
}

static void stop(private_guest_t *this)
{
	if (this->pid)
	{
		kill(this->pid, SIGINT);
		this->pid = 0;
	}
}

/**
 * create a directory
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
	
	/* mount unionfs */
	len = snprintf(cmd, sizeof(cmd), "unionfs %s/%s:%s %s/%s",
				   HOST_DIR, name, master, MOUNT_DIR, name);
	if (len < 0 || len >= sizeof(cmd))
	{
		return FALSE;
	}
	if (system(cmd) != 0)
	{
		DBG1("mounting unionfs using '%s' failed.", cmd);
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
		return 1;
	}
	return fd;
}

/**
 * stop guest, unmount mounts
 */
static void destroy(private_guest_t *this)
{
	stop(this);
	umount_unionfs(this->name);
	free(this->name);
	free(this->kernel);
	free(this->master);
	free(this);
}

/**
 * create the guest instance, including required dirs and mounts 
 */
guest_t *guest_create(char *name, char *kernel, char *master, int mem)
{
	private_guest_t *this = malloc_thing(private_guest_t);
	
	this->public.get_name = (void*)get_name;
	this->public.start = (void*)start;
	this->public.stop = (void*)stop;
	this->public.destroy = (void*)destroy;
	
	if (!makedir(HOST_DIR, name) || !makedir(MOUNT_DIR, name) ||
		!makedir(RUN_DIR, name))
	{
		DBG1("creating guest directories for %s failed failed.", name);
		free(this);
		return NULL;
	}
	
	if (!mount_unionfs(name, master))
	{
		DBG1("mounting guest unionfs for %s failed.", name);
		free(this);
		return NULL;
	}
	
	this->name = strdup(name);
	this->kernel = strdup(kernel);
	this->master = strdup(master);
	this->mem = mem;
	this->pid = 0;
	this->bootlog = open_bootlog(name);

	return &this->public;
}

