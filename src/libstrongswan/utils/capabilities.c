/*
 * Copyright (C) 2012 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "capabilities.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#ifdef HAVE_PRCTL
# include <sys/prctl.h>
#endif /* HAVE_PRCTL */

#include <debug.h>

#if !defined(HAVE_GETPWNAM_R) || !defined(HAVE_GETGRNAM_R)
# include <threading/mutex.h>
# define EMULATE_R_FUNCS
#endif

typedef struct private_capabilities_t private_capabilities_t;

/**
 * Private data of an capabilities_t object.
 */
struct private_capabilities_t {

	/**
	 * Public capabilities_t interface.
	 */
	capabilities_t public;

	/**
	 * user ID to switch during rights dropping
	 */
	uid_t uid;

	/**
	 * group ID to switch during rights dropping
	 */
	gid_t gid;

	/**
	 * capabilities to keep
	 */
#ifdef CAPABILITIES_LIBCAP
	cap_t caps;
#endif /* CAPABILITIES_LIBCAP */
#ifdef CAPABILITIES_NATIVE
	struct __user_cap_data_struct caps[2];
#endif /* CAPABILITIES_NATIVE */

#ifdef EMULATE_R_FUNCS
	/**
	 * mutex to emulate get(pw|gr)nam_r functions
	 */
	mutex_t *mutex;
#endif
};

METHOD(capabilities_t, keep, void,
	private_capabilities_t *this, u_int cap)
{
#ifdef CAPABILITIES_LIBCAP
	cap_set_flag(this->caps, CAP_EFFECTIVE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_PERMITTED, 1, &cap, CAP_SET);
#endif /* CAPABILITIES_LIBCAP */
#ifdef CAPABILITIES_NATIVE
	int i = 0;

	if (cap >= 32)
	{
		i++;
		cap -= 32;
	}
	this->caps[i].effective |= 1 << cap;
	this->caps[i].permitted |= 1 << cap;
	this->caps[i].inheritable |= 1 << cap;
#endif /* CAPABILITIES_NATIVE */
}

METHOD(capabilities_t, get_uid, uid_t,
	private_capabilities_t *this)
{
	return this->uid;
}

METHOD(capabilities_t, get_gid, gid_t,
	private_capabilities_t *this)
{
	return this->gid;
}

METHOD(capabilities_t, set_uid, void,
	private_capabilities_t *this, uid_t uid)
{
	this->uid = uid;
}

METHOD(capabilities_t, set_gid, void,
	private_capabilities_t *this, gid_t gid)
{
	this->gid = gid;
}

METHOD(capabilities_t, resolve_uid, bool,
	private_capabilities_t *this, char *username)
{
	struct passwd *pwp;
	int err;

#ifdef HAVE_GETPWNAM_R
	struct passwd passwd;
	char buf[1024];

	err = getpwnam_r(username, &passwd, buf, sizeof(buf), &pwp);
	if (pwp)
	{
		this->uid = pwp->pw_uid;
	}
#else /* HAVE GETPWNAM_R */
	this->mutex->lock(this->mutex);
	pwp = getpwnam(username);
	if (pwp)
	{
		this->uid = pwp->pw_uid;
	}
	err = errno;
	this->mutex->unlock(this->mutex);
#endif /* HAVE GETPWNAM_R */
	if (pwp)
	{
		return TRUE;
	}
	DBG1(DBG_LIB, "resolving user '%s' failed: %s", username,
		 err ? strerror(err) : "user not found");
	return FALSE;
}

METHOD(capabilities_t, resolve_gid, bool,
	private_capabilities_t *this, char *groupname)
{
	struct group *grp;
	int err;

#ifdef HAVE_GETGRNAM_R
	struct group group;
	char buf[1024];

	err = getgrnam_r(groupname, &group, buf, sizeof(buf), &grp);
	if (grp)
	{
		this->gid = grp->gr_gid;
	}
#else /* HAVE_GETGRNAM_R */
	this->mutex->lock(this->mutex);
	grp = getgrnam(groupname);
	if (grp)
	{
		this->gid = grp->gr_gid;
	}
	err = errno;
	this->mutex->unlock(this->mutex);
#endif /* HAVE_GETGRNAM_R */
	if (grp)
	{
		return TRUE;
	}
	DBG1(DBG_LIB, "resolving user '%s' failed: %s", groupname,
		 err ? strerror(err) : "group not found");
	return FALSE;
}

METHOD(capabilities_t, drop, bool,
	private_capabilities_t *this)
{
#ifdef HAVE_PRCTL
	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
#endif

	if (this->gid && setgid(this->gid) != 0)
	{
		DBG1(DBG_LIB, "change to unprivileged group %u failed: %s",
			 this->gid, strerror(errno));
		return FALSE;
	}
	if (this->uid && setuid(this->uid) != 0)
	{
		DBG1(DBG_LIB, "change to unprivileged user %u failed: %s",
			 this->uid, strerror(errno));
		return FALSE;
	}

#ifdef CAPABILITIES_LIBCAP
	if (cap_set_proc(this->caps) != 0)
	{
		DBG1(DBG_LIB, "dropping capabilities failed: %s", strerror(errno));
		return FALSE;
	}
#endif /* CAPABILITIES_LIBCAP */
#ifdef CAPABILITIES_NATIVE
	struct __user_cap_header_struct header = {
#if defined(_LINUX_CAPABILITY_VERSION_3)
		.version = _LINUX_CAPABILITY_VERSION_3,
#elif defined(_LINUX_CAPABILITY_VERSION_2)
		.version = _LINUX_CAPABILITY_VERSION_2,
#elif defined(_LINUX_CAPABILITY_VERSION_1)
		.version = _LINUX_CAPABILITY_VERSION_1,
#else
		.version = _LINUX_CAPABILITY_VERSION,
#endif
	};
	if (capset(&header, this->caps) != 0)
	{
		DBG1(DBG_LIB, "dropping capabilities failed: %s", strerror(errno));
		return FALSE;
	}
#endif /* CAPABILITIES_NATIVE */
#ifdef CAPABILITIES
	DBG1(DBG_LIB, "dropped capabilities, running as uid %u, gid %u",
		 this->uid, this->gid);
#endif /* CAPABILITIES */
	return TRUE;
}

METHOD(capabilities_t, destroy, void,
	private_capabilities_t *this)
{
#ifdef EMULATE_R_FUNCS
	this->mutex->destroy(this->mutex);
#endif /* EMULATE_R_FUNCS */
#ifdef CAPABILITIES_LIBCAP
	cap_free(this->caps);
#endif /* CAPABILITIES_LIBCAP */
	free(this);
}

/**
 * See header
 */
capabilities_t *capabilities_create()
{
	private_capabilities_t *this;

	INIT(this,
		.public = {
			.keep = _keep,
			.get_uid = _get_uid,
			.get_gid = _get_gid,
			.set_uid = _set_uid,
			.set_gid = _set_gid,
			.resolve_uid = _resolve_uid,
			.resolve_gid = _resolve_gid,
			.drop = _drop,
			.destroy = _destroy,
		},
	);

#ifdef CAPABILITIES
#ifdef CAPABILITIES_LIBCAP
	this->caps = cap_init();
#endif /* CAPABILITIES_LIBCAP */
	if (lib->leak_detective)
	{
		keep(this, CAP_SYS_NICE);
	}
#endif /* CAPABILITIES */

#ifdef EMULATE_R_FUNCS
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
#endif /* EMULATE_R_FUNCS */

	return &this->public;
}
