/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2001-2007 Miklos Szeredi
 *
 * Based on example shipped with FUSE.
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


#define FUSE_USE_VERSION 26
#define _GNU_SOURCE

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>

#include "cowfs.h"

#include <library.h>
#include <debug.h>

/** define _XOPEN_SOURCE 500 fails when using libstrongswan, define popen */
extern ssize_t pread(int fd, void *buf, size_t count, off_t offset);
extern ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);

typedef struct private_cowfs_t private_cowfs_t;

struct private_cowfs_t {
	/** public cowfs interface */
	cowfs_t public;
	/** fuse channel to mountpoint */
	struct fuse_chan *chan;
	/** fuse handle */
	struct fuse *fuse;
	/** mountpoint of cowfs FUSE */
	char *mount;
	/** master filesystem path */
	char *master;
	/** host filesystem path */
	char *host;
	/** overlay filesystem path */
	char *over;
	/** fd of read only master filesystem */
	int master_fd;
	/** copy on write overlay to master */
	int host_fd;
	/** optional COW overlay */
	int over_fd;
	/** thread processing FUSE */
	pthread_t thread;
};

/**
 * get this pointer stored in fuse context
 */
static private_cowfs_t *get_this()
{
	return (fuse_get_context())->private_data;
}

/**
 * make a path relative
 */
static void rel(const char **path)
{
	if (**path == '/')
	{
		(*path)++;
	}
	if (**path == '\0')
	{
		*path = ".";
	}
}

/**
 * get the highest overlay in which path exists
 */
static int get_rd(const char *path)
{
	private_cowfs_t *this = get_this();

	if (this->over_fd > 0 && faccessat(this->over_fd, path, F_OK, 0) == 0)
	{
		return this->over_fd;
	}
	if (faccessat(this->host_fd, path, F_OK, 0) == 0)
	{
		return this->host_fd;
	}
	return this->master_fd;
}

/**
 * get the highest overlay available, to write something
 */
static int get_wr(const char *path)
{
	private_cowfs_t *this = get_this();
	if (this->over_fd > 0)
	{
		return this->over_fd;
	}
	return this->host_fd;
}

/**
 * create full "path" at "wr" the same way they exist at "rd"
 */
static bool clone_path(int rd, int wr, const char *path)
{
	char *pos, *full;
	struct stat st;
	full = strdupa(path);
	pos = full;
	
	while ((pos = strchr(pos, '/')))
	{
		*pos = '\0';
		if (fstatat(wr, full, &st, 0) < 0)
		{
			/* TODO: handle symlinks!? */
			if (fstatat(rd, full, &st, 0) < 0)
			{
				return FALSE;
			}
			if (mkdirat(wr, full, st.st_mode) < 0)
			{
				return FALSE;
			}
		}
		*pos = '/';
		pos++;
	}
	return TRUE;
}

/**
 * copy a (special) file from a readonly to a read-write overlay
 */
static int copy(const char *path)
{
	char *buf[4096];
	int len;
	int rd, wr;
	int from, to;
	struct stat st;
	
	rd = get_rd(path);
	wr = get_wr(path);
	
	if (rd == wr)
	{
		/* already writeable */
		return wr;
	}
	if (fstatat(rd, path, &st, 0) < 0)
	{
		return -1;
	}
	if (!clone_path(rd, wr, path))
	{
		return -1;
	}
	if (mknodat(wr, path, st.st_mode, st.st_rdev) < 0)
	{
		return -1;
	}
	/* copy if no special file */
	if (st.st_size)
	{
		from = openat(rd, path, O_RDONLY, st.st_mode);
		if (from < 0)
		{
			return -1;
		}
		to = openat(wr, path, O_WRONLY , st.st_mode);
		if (to < 0)
		{
			close(from);
			return -1;
		}
		while ((len = read(from, buf, sizeof(buf))) > 0)
		{
			if (write(to, buf, len) < len)
			{
				/* TODO: only on len < 0 ? */
				close(from);
				close(to);
				return -1;
			}
		}
		close(from);
		close(to);
		if (len < 0)
		{
			return -1;
		}
	}
	return wr;
}

/**
 * FUSE getattr method
 */
static int cowfs_getattr(const char *path, struct stat *stbuf)
{
	rel(&path);

	if (fstatat(get_rd(path), path, stbuf, AT_SYMLINK_NOFOLLOW) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE access method
 */
static int cowfs_access(const char *path, int mask)
{
	rel(&path);
	
	if (faccessat(get_rd(path), path, mask, 0) < 0)
	{
		return -errno;
	}
    return 0;
}

/**
 * FUSE readlink method
 */
static int cowfs_readlink(const char *path, char *buf, size_t size)
{
	int res;

	rel(&path);
	
	res = readlinkat(get_rd(path), path, buf, size - 1);
    if (res < 0)
    {
        return -errno;
	}
    buf[res] = '\0';
    return 0;
}

/**
 * get a directory stream of two concatenated paths
 */
static DIR* get_dir(char *dir, const char *subdir)
{
	char *full;
	
	if (dir == NULL)
	{
		return NULL;
	}
	
	full = alloca(strlen(dir) + strlen(subdir) + 1);
	strcpy(full, dir);
	strcat(full, subdir);
	
	return opendir(full);
}

/**
 * check if a directory stream contains a directory
 */
static bool contains_dir(DIR *d, char *dirname)
{
	if (d)
	{
		struct dirent *ent;
		
		rewinddir(d);
		while ((ent = readdir(d)))
		{
			if (streq(ent->d_name, dirname))
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * FUSE readdir method
 */
static int cowfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
						 off_t offset, struct fuse_file_info *fi)
{
	private_cowfs_t *this = get_this();
	DIR *d1, *d2, *d3;
	struct stat st;
	struct dirent *ent;
	
	memset(&st, 0, sizeof(st));
	
	d1 = get_dir(this->master, path);
	d2 = get_dir(this->host, path);
	d3 = get_dir(this->over, path);
	
	if (d1)
	{
		while ((ent = readdir(d1)))
		{
			if (!contains_dir(d2, ent->d_name) &&
				!contains_dir(d3, ent->d_name))
			{
				st.st_ino = ent->d_ino;
				st.st_mode = ent->d_type << 12;
	        	filler(buf, ent->d_name, &st, 0);
			}
		}
		closedir(d1);
	}
	if (d2)
	{
		rewinddir(d2);
		while ((ent = readdir(d2)))
		{
			if (!contains_dir(d3, ent->d_name))
			{
				st.st_ino = ent->d_ino;
				st.st_mode = ent->d_type << 12;
	        	filler(buf, ent->d_name, &st, 0);
			}
		}
		closedir(d2);
	}
	if (d3)
	{
		rewinddir(d3);
		while ((ent = readdir(d3)))
		{
			st.st_ino = ent->d_ino;
			st.st_mode = ent->d_type << 12;
        	filler(buf, ent->d_name, &st, 0);
		}
		closedir(d3);
	}
    return 0;
}

/**
 * FUSE mknod method
 */
static int cowfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int fd;
	rel(&path);

	fd = get_wr(path);
	if (!clone_path(get_rd(path), fd, path))
	{
		return -errno;
	}

	if (mknodat(fd, path, mode, rdev) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE mkdir method
 */
static int cowfs_mkdir(const char *path, mode_t mode)
{
	int fd;
	rel(&path);

	fd = get_wr(path);
	if (!clone_path(get_rd(path), fd, path))
	{
		return -errno;
	}
	if (mkdirat(fd, path, mode) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE unlink method
 */
static int cowfs_unlink(const char *path)
{
	rel(&path);
	
	/* TODO: whiteout master */
	if (unlinkat(get_wr(path), path, 0) < 0)
	{
		return -errno;
	}
    return 0;
}

/**
 * FUSE rmdir method
 */
static int cowfs_rmdir(const char *path)
{
	rel(&path);
	
	/* TODO: whiteout master */
	if (unlinkat(get_wr(path), path, AT_REMOVEDIR) < 0)
	{
		return -errno;
	}
    return 0;
}

/**
 * FUSE symlink method
 */
static int cowfs_symlink(const char *from, const char *to)
{
	int fd;
	const char *fromrel = from;

	rel(&to);
	rel(&fromrel);

	fd = get_wr(to);
	if (!clone_path(get_rd(fromrel), fd, fromrel))
	{
		return -errno;
	}
	if (symlinkat(from, fd, to) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE rename method
 */
static int cowfs_rename(const char *from, const char *to)
{
	int fd;
	private_cowfs_t *this = get_this();

	rel(&from);
	rel(&to);

	fd = get_rd(from);
	if (fd == this->master_fd)
	{
		fd = copy(from);
		if (fd < 0)
		{
			return -errno;
		}
	}
	
	if (renameat(fd, from, get_wr(to), to) < 0)
	{
	    return -errno;
	}
	return 0;
}

/**
 * FUSE link method
 */
static int cowfs_link(const char *from, const char *to)
{
	int rd, wr;

	rel(&from);
	rel(&to);
	
	rd = get_rd(from);
	wr = get_wr(to);
	
	if (!clone_path(rd, wr, to))
	{
		DBG1("cloning path '%s' failed", to);
		return -errno;
	}
    if (linkat(rd, from, wr, to, 0) < 0)
    {
		DBG1("linking '%s' to '%s' failed", from, to);
    	return -errno;
	}
    return 0;
}

/**
 * FUSE chmod method
 */
static int cowfs_chmod(const char *path, mode_t mode)
{
	int fd;
	struct stat st;
	private_cowfs_t *this = get_this();
	
	rel(&path);
	fd = get_rd(path);
	if (fd == this->master_fd)
	{
		if (fstatat(fd, path, &st, 0) < 0)
		{
			return -errno;
		}
		if (st.st_mode == mode)
		{
			return 0;
		}
		fd = copy(path);
		if (fd < 0)
		{
			return -errno;
		}
	}
	if (fchmodat(fd, path, mode, 0) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE chown method
 */
static int cowfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int fd;
	struct stat st;
	private_cowfs_t *this = get_this();
	
	rel(&path);
	fd = get_rd(path);
	if (fd == this->master_fd)
	{
		if (fstatat(fd, path, &st, 0) < 0)
		{
			return -errno;
		}
		if (st.st_uid == uid && st.st_gid == gid)
		{
			return 0;
		}
		fd = copy(path);
		if (fd < 0)
		{
			return -errno;
		}
	}
	if (fchownat(fd, path, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE truncate method
 */
static int cowfs_truncate(const char *path, off_t size)
{
	int fd;
	struct stat st;
	
	private_cowfs_t *this = get_this();

	rel(&path);
	fd = get_rd(path);
	if (fd == this->master_fd)
	{
		if (fstatat(fd, path, &st, 0) < 0)
		{
			return -errno;
		}
		if (st.st_size == size)
		{
			return 0;
		}
		fd = copy(path);
		if (fd < 0)
		{
			return -errno;
		}
	}
	fd = openat(fd, path, O_WRONLY);
	if (fd < 0)
	{
		return -errno;
	}
	if (ftruncate(fd, size) < 0)
	{
		close(fd);
		return -errno;
	}
	close(fd);
	return 0;
}

/**
 * FUSE utimens method
 */
static int cowfs_utimens(const char *path, const struct timespec ts[2])
{
	struct timeval tv[2];
	int fd;
	private_cowfs_t *this = get_this();

	rel(&path);
	fd = get_rd(path);
	if (fd == this->master_fd)
	{
		fd = copy(path);
		if (fd < 0)
		{
			return -errno;
		}
	}

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	if (futimesat(fd, path, tv) < 0)
	{
		return -errno;
	}
	return 0;
}

/**
 * FUSE open method
 */
static int cowfs_open(const char *path, struct fuse_file_info *fi)
{
	int fd;

	rel(&path);
	fd = get_rd(path);

	fd = openat(fd, path, fi->flags);
	if (fd < 0)
	{
		return -errno;
	}
	close(fd);
	return 0;
}

/**
 * FUSE read method
 */
static int cowfs_read(const char *path, char *buf, size_t size, off_t offset,
					  struct fuse_file_info *fi)
{
	int file, fd, res;

	rel(&path);

	fd = get_rd(path);

	file = openat(fd, path, O_RDONLY);
	if (file < 0)
	{
		return -errno;
	}
	
	res = pread(file, buf, size, offset);
	if (res < 0)
	{
		res = -errno;
	}
	close(file);
	return res;
}

/**
 * FUSE write method
 */
static int cowfs_write(const char *path, const char *buf, size_t size,
					   off_t offset, struct fuse_file_info *fi)
{
	private_cowfs_t *this = get_this();
	int file, fd, res;

	rel(&path);

	fd = get_rd(path);
	if (fd == this->master_fd)
	{
		fd = copy(path);
		if (fd < 0)
		{
			return -errno;
		}
	}
	file = openat(fd, path, O_WRONLY);
	if (file < 0)
	{
		return -errno;
	}
	res = pwrite(file, buf, size, offset);
	if (res < 0)
	{
		res = -errno;
	}
	close(file);
	return res;
}

/**
 * FUSE statfs method
 */
static int cowfs_statfs(const char *path, struct statvfs *stbuf)
{
	private_cowfs_t *this = get_this();
	int fd;
	
	fd = this->host_fd;
	if (this->over_fd > 0)
	{
		fd = this->over_fd;
	}

	if (fstatvfs(fd, stbuf) < 0)
	{
		return -errno;
	}
	
    return 0;
}

/** 
 * FUSE init method
 */
static void *cowfs_init(struct fuse_conn_info *conn)
{
	struct fuse_context *ctx;
	
	ctx = fuse_get_context();
	
	return ctx->private_data;
}

/**
 * FUSE method vectors
 */
static struct fuse_operations cowfs_operations = {
    .getattr	= cowfs_getattr,
    .access		= cowfs_access,
    .readlink	= cowfs_readlink,
    .readdir	= cowfs_readdir,
    .mknod		= cowfs_mknod,
    .mkdir		= cowfs_mkdir,
    .symlink	= cowfs_symlink,
    .unlink		= cowfs_unlink,
    .rmdir		= cowfs_rmdir,
    .rename		= cowfs_rename,
    .link		= cowfs_link,
    .chmod		= cowfs_chmod,
    .chown		= cowfs_chown,
    .truncate	= cowfs_truncate,
    .utimens	= cowfs_utimens,
    .open		= cowfs_open,
    .read		= cowfs_read,
    .write		= cowfs_write,
    .statfs		= cowfs_statfs,
    .init		= cowfs_init,
};

/**
 * Implementation of cowfs_t.set_overlay.
 */
static bool set_overlay(private_cowfs_t *this, char *path)
{
	if (this->over)
	{
		free(this->over);
		this->over = NULL;
	}
	if (this->over_fd > 0)
	{
		close(this->over_fd);
		this->over_fd = -1;
	}
	if (path)
	{
		this->over_fd = open(path, O_RDONLY | O_DIRECTORY);
		if (this->over_fd < 0)
		{
			DBG1("failed to open overlay directory '%s': %m", path);
			return FALSE;
		}
		this->over = strdup(path);
	}
	return TRUE;
}

/**
 * stop, umount and destroy a cowfs FUSE filesystem
 */
static void destroy(private_cowfs_t *this)
{
	fuse_exit(this->fuse);
	fuse_unmount(this->mount, this->chan);
	pthread_join(this->thread, NULL);
	fuse_destroy(this->fuse);
	free(this->mount);
	free(this->master);
	free(this->host);
	free(this->over);
	close(this->master_fd);
	close(this->host_fd);
	if (this->over_fd > 0)
	{
		close(this->over_fd);
	}
	free(this);
}

/**
 * creates a new cowfs fuse instance
 */
cowfs_t *cowfs_create(char *master, char *host, char *mount)
{
	struct fuse_args args = {0, NULL, 0};
	private_cowfs_t *this = malloc_thing(private_cowfs_t);
	
	this->public.set_overlay = (bool(*)(cowfs_t*, char *path))set_overlay;
	this->public.destroy = (void(*)(cowfs_t*))destroy;
	
    this->master_fd = open(master, O_RDONLY | O_DIRECTORY);
    if (this->master_fd < 0)
    {
    	DBG1("failed to open master filesystem '%s'", master);
    	free(this);
    	return NULL;
    }
    this->host_fd = open(host, O_RDONLY | O_DIRECTORY);
	if (this->host_fd < 0)
    {
    	DBG1("failed to open host filesystem '%s'", host);
    	close(this->master_fd);
    	free(this);
    	return NULL;
    }
	this->over_fd = -1;
	
    this->chan = fuse_mount(mount, &args);
    if (this->chan == NULL)
    {
    	DBG1("mounting cowfs FUSE on '%s' failed", mount);
    	close(this->master_fd);
    	close(this->host_fd);
    	free(this);
    	return NULL;
    }
    
    this->fuse = fuse_new(this->chan, &args, &cowfs_operations,
    					  sizeof(cowfs_operations), this);
    if (this->fuse == NULL)
    {
    	DBG1("creating cowfs FUSE handle failed");
    	close(this->master_fd);
    	close(this->host_fd);
    	fuse_unmount(mount, this->chan);
    	free(this);
    	return NULL;
    }
    
    this->mount = strdup(mount);
    this->master = strdup(master);
    this->host = strdup(host);
    this->over = NULL;
	
	if (pthread_create(&this->thread, NULL, (void*)fuse_loop, this->fuse) != 0)
	{
    	DBG1("creating thread to handle FUSE failed");
    	fuse_unmount(mount, this->chan);
    	free(this->mount);
    	free(this->master);
    	free(this->host);
    	close(this->master_fd);
    	close(this->host_fd);
    	free(this);
    	return NULL;
	}
    
    return &this->public;
}

