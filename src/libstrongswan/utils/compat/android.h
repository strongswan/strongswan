/*
 * Copyright (C) 2010-2015 Tobias Brunner
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

/**
 * @defgroup android android
 * @{ @ingroup compat
 */

#ifndef ANDROID_H_
#define ANDROID_H_

#include <android/api-level.h>

/* stuff defined in AndroidConfig.h, which is included using the -include
 * command-line option, thus cannot be undefined using -U CFLAGS options.
 * the reason we have to undefine these flags in the first place, is that
 * AndroidConfig.h defines them as 0, which in turn means that they are
 * actually defined. */
#undef HAVE_BACKTRACE

/* sigwaitinfo() is not defined up to this API level, provide a fallback */
#if __ANDROID_API__ <= 21
#include <errno.h>
#include <signal.h>

static inline int sigwaitinfo(const sigset_t *set, void *info)
{
	int sig, err;

	if (info)
	{	/* we don't replicate siginfo_t, which we don't use */
		errno = EINVAL;
		return -1;
	}
	err = sigwait(set, &sig);
	if (err != 0)
	{
		errno = err;
		sig = -1;
	}
	return sig;
}
#else
#error Check availability of sigwaitinfo() in this API level
#endif

#endif /** ANDROID_H_ @}*/
