/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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

#define _GNU_SOURCE /* for memrchr */
#include <utils/utils.h>
#include <utils/debug.h>
#include <utils/chunk.h>

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>


/**
 * Described in header.
 */
bool path_is_dirsep(int c)
{
#ifdef WIN32
	if (c == '/' )
	{
		/* also correct on Win32 */
		return TRUE;
	}
#endif
	return (c == DIRECTORY_SEPARATOR[0]);
}


/**
 * Described in header.
 */
char *path_first_dirsep(const char *path, int len)
{
	if (len < 0)
		len = (int)strlen(path);

	while (len)
	{
		if (path_is_dirsep(*path))
		{
			return (char *)path;
		}
		path++;
		len--;
	}
	return NULL;
}


/**
 * Described in header.
 */
char *path_last_dirsep(const char *path, int len)
{
	if (len < 0)
		len = (int)strlen(path);

	while (len)
	{
		if (path_is_dirsep(path[--len]))
		{
			return (char *)path + len;
		}
	}
	return NULL;
}


/**
 * Described in header.
 */
char* path_dirname(const char *path)
{
	char *pos;

	pos = path ? path_last_dirsep(path, -1) : NULL;

	if (pos && !pos[1])
	{	/* if path ends with slashes we have to look beyond them */
		while (pos > path && path_is_dirsep(*pos))
		{	/* skip trailing slashes */
			pos--;
		}
		pos = path_last_dirsep(path, pos - path + 1);
	}
	if (!pos)
	{
#ifdef WIN32
		if (path && strlen(path))
		{
			if ((isalpha(path[0]) && path[1] == ':'))
			{	/* if just a drive letter given, return that as dirname */
				return chunk_clone(chunk_from_chars(path[0], ':', 0)).ptr;
			}
		}
#endif
		return strdup(".");
	}
	while (pos > path && path_is_dirsep(*pos))
	{	/* skip superfluous slashes */
		pos--;
	}
	return strndup(path, pos - path + 1);
}

/**
 * Described in header.
 */
char* path_basename(const char *path)
{
	char *pos, *trail = NULL;

	if (!path || !*path)
	{
		return strdup(".");
	}
	pos = path_last_dirsep(path, -1);
	if (pos && !pos[1])
	{	/* if path ends with slashes we have to look beyond them */
		while (pos > path && path_is_dirsep(*pos))
		{	/* skip trailing slashes */
			pos--;
		}
		if (pos == path && path_is_dirsep(*pos))
		{	/* contains only slashes */
			return strndup(pos, 1);
		}
		trail = pos + 1;
		pos = path_last_dirsep(path, trail - path);
	}
	pos = pos ? pos + 1 : (char*)path;
	return trail ? strndup(pos, trail - pos) : strdup(pos);
}

/**
 * Described in header.
 */
bool path_absolute(const char *path)
{
	if (!path)
	{
		return FALSE;
	}
#ifdef WIN32
	if (strpfx(path, "\\\\"))
	{	/* UNC */
		return TRUE;
	}
	if (strlen(path) && isalpha(path[0]) && path[1] == ':')
	{	/* drive letter */
		return TRUE;
	}
#endif /* !WIN32 */

	if (path_is_dirsep(path[0]))
	{
		return TRUE;
	}

	return FALSE;
}

/**
 * Described in header.
 */
bool mkdir_p(const char *path, mode_t mode)
{
	int len;
	char *pos, full[PATH_MAX];
	pos = full;
	if (!path || *path == '\0')
	{
		return TRUE;
	}
	len = snprintf(full, sizeof(full)-1, "%s", path);
	if (len < 0 || len >= sizeof(full)-1)
	{
		DBG1(DBG_LIB, "path string %s too long", path);
		return FALSE;
	}
	/* ensure that the path ends with a '/' */
	if (!path_is_dirsep(full[len-1]))
	{
		full[len++] = '/';
		full[len] = '\0';
	}
	/* skip '/' at the beginning */
	while (path_is_dirsep(*pos))
	{
		pos++;
	}
	while ((pos = path_first_dirsep(pos, -1)))
	{
		char old = *pos;
		*pos = '\0';
		if (access(full, F_OK) < 0)
		{
#ifdef WIN32
			if (_mkdir(full) < 0)
#else
			if (mkdir(full, mode) < 0)
#endif
			{
				DBG1(DBG_LIB, "failed to create directory %s", full);
				return FALSE;
			}
		}
		*pos = old;
		pos++;
	}
	return TRUE;
}
