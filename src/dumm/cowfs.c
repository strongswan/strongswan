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
	/** read only master filesystem */
	char *master;
	/** copy on write overlay to master */
	char *host;
	/** optional scenario COW overlay */
	char *scenario;
	/** thread processing FUSE */
	pthread_t thread;
};


static int cowfs_getattr(const char *path, struct stat *stbuf)
{
    int res;

    res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_access(const char *path, int mask)
{
    int res;

    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int cowfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;

    dp = opendir(path);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int cowfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_unlink(const char *path)
{
    int res;

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_truncate(const char *path, off_t size)
{
    int res;

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(path, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int cowfs_open(const char *path, struct fuse_file_info *fi)
{
    int res;

    res = open(path, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int cowfs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;
    fd = open(path, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int cowfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;
    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int cowfs_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static void *cowfs_init(struct fuse_conn_info *conn)
{
	struct fuse_context *ctx;
	
	ctx = fuse_get_context();
	
	return ctx->private_data;
}

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
 * Implementation of cowfs_t.set_scenario.
 */
static void set_scenario(private_cowfs_t *this, char *path)
{
	free(this->scenario);
	this->scenario = path ? strdup(path) : NULL;
}

/**
 * stop, umount and destroy a cowfs FUSE filesystem
 */
static void destroy(private_cowfs_t *this)
{
	fuse_exit(this->fuse);
	pthread_join(this->thread, NULL);
	fuse_unmount(this->mount, this->chan);
	fuse_destroy(this->fuse);
	free(this->mount);
	free(this->master);
	free(this->host);
	free(this->scenario);
	free(this);
}

/**
 * creates a new cowfs fuse instance
 */
cowfs_t *cowfs_create(char *master, char *host, char *mount)
{
	struct fuse_args args = {0, NULL, 0};
	private_cowfs_t *this = malloc_thing(private_cowfs_t);
	
	this->public.set_scenario = (void(*)(cowfs_t*, char *path))set_scenario;
	this->public.destroy = (void(*)(cowfs_t*))destroy;
	
    this->chan = fuse_mount(mount, &args);
    if (this->chan == NULL)
    {
    	DBG1("mounting cowfs FUSE on '%s' failed", mount);
    	free(this);
    	return NULL;
    }
    
    this->fuse = fuse_new(this->chan, &args, &cowfs_operations,
    					  sizeof(cowfs_operations), this);
    if (this->fuse == NULL)
    {
    	DBG1("creating cowfs FUSE handle failed");
    	fuse_unmount(mount, this->chan);
    	free(this);
    	return NULL;
    }
    
    this->mount = strdup(mount);
    this->master = strdup(master);
    this->host = strdup(host);
	this->scenario = NULL;
	
	if (pthread_create(&this->thread, NULL, (void*)fuse_loop_mt, this->fuse) != 0)
	{
    	DBG1("creating thread to handle FUSE failed");
    	fuse_unmount(mount, this->chan);
    	free(this->mount);
    	free(this->master);
    	free(this->host);
    	free(this);
    	return NULL;
	}
    
    return &this->public;
}

