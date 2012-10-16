/*
 * Copyright (C) 2012 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "os_info.h"

#include <sys/utsname.h>
#include <stdio.h>

#include <collections/linked_list.h>
#include <utils/debug.h>

typedef struct private_os_info_t private_os_info_t;

ENUM(os_fwd_status_names, OS_FWD_DISABLED, OS_FWD_UNKNOWN,
	"disabled",
	"enabled",
	"unknown"
);

/**
 * Private data of an os_info_t object.
 *
 */
struct private_os_info_t {

	/**
	 * Public os_info_t interface.
	 */
	os_info_t public;

	/**
	 * OS name
	 */
	chunk_t name;

	/**
	 * OS version
	 */
	chunk_t version;

};

METHOD(os_info_t, get_name, chunk_t,
	private_os_info_t *this)
{
	return this->name;
}

METHOD(os_info_t, get_numeric_version, void,
	private_os_info_t *this, u_int32_t *major, u_int32_t *minor)
{
	u_char *pos;

	if (major)
	{
		*major = atol(this->version.ptr);
	}
	pos = memchr(this->version.ptr, '.', this->version.len);
	if (minor)
	{
		*minor = pos ? atol(pos + 1) : 0;
	}
}

METHOD(os_info_t, get_version, chunk_t,
	private_os_info_t *this)
{
	return this->version;
}

METHOD(os_info_t, get_fwd_status, os_fwd_status_t,
	private_os_info_t *this)
{
	const char ip_forward[] = "/proc/sys/net/ipv4/ip_forward";
	char buf[2];
	FILE *file;

	os_fwd_status_t fwd_status = OS_FWD_UNKNOWN;

	file = fopen(ip_forward, "r");
	if (file)
	{
		if (fread(buf, 1, 1, file) == 1)
		{
			switch (buf[0])
			{
				case '0':
					fwd_status = OS_FWD_DISABLED;
					break;
				case '1':
					fwd_status = OS_FWD_ENABLED;
					break;
				default:
					DBG1(DBG_IMC, "\"%s\" returns invalid value ", ip_forward);
					break;
			}
		}
		else
		{
			DBG1(DBG_IMC, "could not read from \"%s\"", ip_forward);
		}
		fclose(file);
	}
	else
	{
		DBG1(DBG_IMC, "failed to open \"%s\"", ip_forward);
	}

	return fwd_status;
}

METHOD(os_info_t, get_uptime, time_t,
	private_os_info_t *this)
{
	const char proc_uptime[] = "/proc/uptime";
	FILE *file;
	time_t uptime;

	file = fopen(proc_uptime, "r");
	if (!file)
	{
		DBG1(DBG_IMC, "failed to open \"%s\"", proc_uptime);
		return 0;
	}
	if (fscanf(file, "%u", &uptime) != 1)
	{
		DBG1(DBG_IMC, "failed to read file \"%s\"", proc_uptime);
		uptime = 0;
	}
	fclose(file);

	return uptime;
}

METHOD(os_info_t, create_package_enumerator, enumerator_t*,
	private_os_info_t *this)
{
	/* TODO */

	return NULL;
}


METHOD(os_info_t, destroy, void,
	private_os_info_t *this)
{
	free(this->name.ptr);
	free(this->version.ptr);
	free(this);
}

#define RELEASE_LSB		0
#define RELEASE_DEBIAN	1

/**
 * Determine Linux distribution version and hardware platform
 */
static bool extract_platform_info(chunk_t *name, chunk_t *version)
{
	FILE *file;
	u_char buf[BUF_LEN], *pos = buf;
	int len = BUF_LEN - 1;
	chunk_t os_name = chunk_empty;
	chunk_t os_version = chunk_empty;
	struct utsname uninfo;
	int i;

	/* Linux/Unix distribution release info (from http://linuxmafia.com) */
	const char* releases[] = {
		"/etc/lsb-release",           "/etc/debian_version",
		"/etc/SuSE-release",          "/etc/novell-release",
		"/etc/sles-release",          "/etc/redhat-release",
		"/etc/fedora-release",        "/etc/gentoo-release",
		"/etc/slackware-version",     "/etc/annvix-release",
		"/etc/arch-release",          "/etc/arklinux-release",
		"/etc/aurox-release",         "/etc/blackcat-release",
		"/etc/cobalt-release",        "/etc/conectiva-release",
		"/etc/debian_release",        "/etc/immunix-release",
		"/etc/lfs-release",           "/etc/linuxppc-release",
		"/etc/mandrake-release",      "/etc/mandriva-release",
		"/etc/mandrakelinux-release", "/etc/mklinux-release",
		"/etc/pld-release",           "/etc/redhat_version",
		"/etc/slackware-release",     "/etc/e-smith-release",
		"/etc/release",               "/etc/sun-release",
		"/etc/tinysofa-release",      "/etc/turbolinux-release",
		"/etc/ultrapenguin-release",  "/etc/UnitedLinux-release",
		"/etc/va-release",            "/etc/yellowdog-release"
	};

	const char lsb_distrib_id[]      = "DISTRIB_ID=";
	const char lsb_distrib_release[] = "DISTRIB_RELEASE=";

	for (i = 0; i < countof(releases); i++)
	{
		file = fopen(releases[i], "r");
		if (!file)
		{
			continue;
		}

		/* read release file into buffer */
		fseek(file, 0, SEEK_END);
		len = min(ftell(file), len);
		rewind(file);
		buf[len] = '\0';
		if (fread(buf, 1, len, file) != len)
		{
			DBG1(DBG_IMC, "failed to read file \"%s\"", releases[i]);
			fclose(file);
			return FALSE;
		}
		fclose(file);

		DBG1(DBG_IMC, "processing \"%s\" file", releases[i]);

		switch (i)
		{
			case RELEASE_LSB:
			{
				/* Determine Distribution ID */
				pos = strstr(buf, lsb_distrib_id);
				if (!pos)
				{
					DBG1(DBG_IMC, "failed to find begin of DISTRIB_ID field");
					return FALSE;
				}
				pos += strlen(lsb_distrib_id);

				os_name.ptr = pos;

				pos = strchr(pos, '\n');
				if (!pos)
				{
					DBG1(DBG_IMC, "failed to find end of DISTRIB_ID field");
					return FALSE;
			 	}

				os_name.len = pos - os_name.ptr;

				/* Determine Distribution Release */
				pos = strstr(buf, lsb_distrib_release);
				if (!pos)
				{
					DBG1(DBG_IMC, "failed to find begin of DISTRIB_RELEASE field");
					return FALSE;
				}
				pos += strlen(lsb_distrib_release);

				os_version.ptr = pos;

				pos = strchr(pos, '\n');
				if (!pos)
				{
					DBG1(DBG_IMC, "failed to find end of DISTRIB_RELEASE field");
					return FALSE;
			 	}

				os_version.len = pos - os_version.ptr;

				break;
			}
			case RELEASE_DEBIAN:
			{
				char str_debian[] = "Debian";

				os_name = chunk_create(str_debian, strlen(str_debian));
				os_version.ptr = buf;

				pos = strchr(buf, '\n');
				if (!pos)
				{
					DBG1(DBG_PTS, "failed to find end of release string");
					return FALSE;
				}

				os_version.len = pos - os_version.ptr;

				break;
			}
			default:
			{
				const char str_release[] = " release ";

				os_name.ptr = buf;

				pos = strstr(buf, str_release);
				if (!pos)
				{
					DBG1(DBG_IMC, "failed to find release keyword");
					return FALSE;
				}

				os_name.len = pos - os_name.ptr;
				pos += strlen(str_release);
				os_version.ptr = pos;

				pos = strchr(pos, '\n');
				if (!pos)
				{
					DBG1(DBG_IMC, "failed to find end of release string");
					return FALSE;
			 	}

				os_version.len = pos - os_version.ptr;

				break;
			}
		}
		break;
	}

	if (!os_name.ptr)
	{
		DBG1(DBG_IMC, "no distribution release file found");
		return FALSE;
	}

	if (uname(&uninfo) < 0)
	{
		DBG1(DBG_IMC, "could not retrieve machine architecture");
		return FALSE;
	}

	/* copy OS name */
	*name = chunk_clone(os_name);

	/* copy OS version and machine architecture */
	*version = chunk_alloc(os_version.len + 1 + strlen(uninfo.machine));
	pos = version->ptr;
	memcpy(pos, os_version.ptr, os_version.len);
	pos += os_version.len;
	*pos++ = ' ';
	memcpy(pos, uninfo.machine, strlen(uninfo.machine));

	return TRUE;
}

/**
 * See header
 */
os_info_t *os_info_create(void)
{
	private_os_info_t *this;
	chunk_t name, version;

	/* As an opton OS name and OS version can be configured manually */
	name.ptr = lib->settings->get_str(lib->settings,
									  "libimcv.os_info.name", NULL);
	version.ptr = lib->settings->get_str(lib->settings,
									  "libimcv.os_info.version", NULL);
	if (name.ptr && version.ptr)
	{
		name.len = strlen(name.ptr);
		name = chunk_clone(name);

		version.len = strlen(version.ptr);
		version = chunk_clone(version);
	}
	else
	{
		if (!extract_platform_info(&name, &version))
		{
			return NULL;
		}
	}
	DBG1(DBG_IMC, "operating system name is '%.*s'",
				   name.len, name.ptr);
	DBG1(DBG_IMC, "operating system version is '%.*s'",
				   version.len, version.ptr);

	INIT(this,
		.public = {
			.get_name = _get_name,
			.get_numeric_version = _get_numeric_version,
			.get_version = _get_version,
			.get_fwd_status = _get_fwd_status,
			.get_uptime = _get_uptime,
			.create_package_enumerator = _create_package_enumerator,
			.destroy = _destroy,
		},
		.name = name,
		.version = version,
	);

	return &this->public;
}
