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
 * @param context	Context object
 * @return			scheduler_t instance
 */
scheduler_t *android_scheduler_create(jobject context);

#endif /** ANDROID_SCHEDULER_H_ @}*/
