/*
 * Copyright (C) 2020 Tobias Brunner
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

/**
 * @defgroup android_scheduler android_scheduler
 * @{ @ingroup android_backend
 */

#ifndef ANDROID_SCHEDULER_H_
#define ANDROID_SCHEDULER_H_

#include <jni.h>

#include <processing/scheduler.h>

/**
 * Create an Android-specific scheduler_t implementation.
 *
 * The given scheduler is used for short-term events. We can't destroy it anyway
 * because of the scheduler job operating on it, and this way we can use it to
 * avoid the overhead of broadcasts for some events.
 *
 * @param context	Context object
 * @param scheduler	the default scheduler used as fallback
 * @return			scheduler_t instance
 */
scheduler_t *android_scheduler_create(jobject context, scheduler_t *scheduler);

#endif /** ANDROID_SCHEDULER_H_ @}*/
