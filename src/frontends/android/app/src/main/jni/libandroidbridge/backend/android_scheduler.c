/*
 * Copyright (C) 2020 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.  *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/time.h>

#include "android_scheduler.h"
#include "../android_jni.h"

#include <collections/hashtable.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>

/**
 * Threshold in milliseconds up to which the default scheduler is used.
 * This includes the roaming events (100 ms) and initial retransmits.
 */
#define DEFAULT_SCHEDULER_THRESHOLD 3000

typedef struct private_scheduler_t private_scheduler_t;

/**
 * Private data.
 */
struct private_scheduler_t {

	/**
	 * Public interface.
	 */
	scheduler_t public;

	/**
	 * Reference to Scheduler object.
	 */
	jobject obj;

	/**
	 * Java class for Scheduler.
	 */
	jclass cls;

	/**
	 * Hashtable that stores scheduled jobs (entry_t*).
	 */
	hashtable_t *jobs;

	/**
	 * Mutex to safely access the scheduled jobs.
	 */
	mutex_t *mutex;

	/**
	 * Default scheduler used for short-term events.
	 */
	scheduler_t *default_scheduler;
};

/**
 * Data for scheduled jobs.
 */
typedef struct {

	/**
	 * Random identifier as string.
	 */
	char *id;

	/**
	 * The scheduled job.
	 */
	job_t *job;

} entry_t;

CALLBACK(destroy_entry, void,
	entry_t *this, const void *key)
{
	DESTROY_IF(this->job);
	free(this->id);
	free(this);
}

JNI_METHOD(Scheduler, executeJob, void,
	jstring jid)
{
	private_scheduler_t *sched;
	entry_t *entry;
	char *id;

	sched = (private_scheduler_t*)lib->scheduler;
	id = androidjni_convert_jstring(env, jid);
	sched->mutex->lock(sched->mutex);
	entry = sched->jobs->remove(sched->jobs, id);
	sched->mutex->unlock(sched->mutex);
	free(id);

	if (entry)
	{
		lib->processor->queue_job(lib->processor, entry->job);
		entry->job = NULL;
		destroy_entry(entry, NULL);
	}
}

METHOD(scheduler_t, get_job_load, u_int,
	private_scheduler_t *this)
{
	u_int count;

	this->mutex->lock(this->mutex);
	count = this->jobs->get_count(this->jobs);
	this->mutex->unlock(this->mutex);
	return count;
}

/**
 * Allocate an ID for a new job. We do this via JNI so we don't have to rely
 * on RNGs being available when we replace the default scheduler.
 */
static jstring allocate_id(private_scheduler_t *this, JNIEnv *env)
{
	jmethodID method_id;

	method_id = (*env)->GetMethodID(env, this->cls, "allocateId",
									"()Ljava/lang/String;");
	if (!method_id)
	{
		return NULL;
	}
	return (*env)->CallObjectMethod(env, this->obj, method_id);
}

METHOD(scheduler_t, schedule_job_ms, void,
	private_scheduler_t *this, job_t *job, uint32_t ms)
{
	JNIEnv *env;
	jmethodID method_id;
	entry_t *entry = NULL;
	jstring jid;

	/* use the default scheduler for short-term events */
	if (ms <= DEFAULT_SCHEDULER_THRESHOLD)
	{
		this->default_scheduler->schedule_job_ms(this->default_scheduler,
												 job, ms);
		return;
	}

	androidjni_attach_thread(&env);
	jid = allocate_id(this, env);
	if (!jid)
	{
		goto failed;
	}
	method_id = (*env)->GetMethodID(env, this->cls, "scheduleJob",
									"(Ljava/lang/String;J)V");
	if (!method_id)
	{
		goto failed;
	}

	this->mutex->lock(this->mutex);
	INIT(entry,
		.id = androidjni_convert_jstring(env, jid),
		.job = job,
	);
	job->status = JOB_STATUS_QUEUED;
	this->jobs->put(this->jobs, entry->id, entry);
	this->mutex->unlock(this->mutex);

	(*env)->CallVoidMethod(env, this->obj, method_id, jid, (jlong)ms);
	if (androidjni_exception_occurred(env))
	{
		goto failed;
	}
	androidjni_detach_thread();
	return;

failed:
	DBG1(DBG_JOB, "unable to schedule job for execution in %u ms", ms);
	if (entry)
	{
		this->mutex->lock(this->mutex);
		this->jobs->remove(this->jobs, entry->id);
		this->mutex->unlock(this->mutex);
		destroy_entry(entry, NULL);
	}
	else
	{
		job->destroy(job);
	}
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
}

METHOD(scheduler_t, schedule_job_tv, void,
	private_scheduler_t *this, job_t *job, timeval_t tv)
{
	timeval_t now;

	time_monotonic(&now);

	if (!timercmp(&now, &tv, <))
	{
		/* already expired, just send it to the processor */
		lib->processor->queue_job(lib->processor, job);
		return;
	}
	timersub(&tv, &now, &now);
	schedule_job_ms(this, job, now.tv_sec * 1000 + now.tv_usec / 1000);
}

METHOD(scheduler_t, schedule_job, void,
	private_scheduler_t *this, job_t *job, uint32_t s)
{
	schedule_job_ms(this, job, s * 1000);
}

METHOD(scheduler_t, flush, void,
	private_scheduler_t *this)
{
	JNIEnv *env;
	jmethodID method_id;

	this->default_scheduler->flush(this->default_scheduler);

	this->mutex->lock(this->mutex);
	this->jobs->destroy_function(this->jobs, destroy_entry);
	this->jobs = hashtable_create(hashtable_hash_str, hashtable_equals_str, 16);
	this->mutex->unlock(this->mutex);

	androidjni_attach_thread(&env);
	method_id = (*env)->GetMethodID(env, this->cls, "Terminate", "()V");
	if (!method_id)
	{
		androidjni_exception_occurred(env);
	}
	else
	{
		(*env)->CallVoidMethod(env, this->obj, method_id);
		androidjni_exception_occurred(env);
	}
	androidjni_detach_thread();
}

METHOD(scheduler_t, destroy, void,
	private_scheduler_t *this)
{
	JNIEnv *env;

	androidjni_attach_thread(&env);
	if (this->obj)
	{
		(*env)->DeleteGlobalRef(env, this->obj);
	}
	if (this->cls)
	{
		(*env)->DeleteGlobalRef(env, this->cls);
	}
	androidjni_detach_thread();
	this->default_scheduler->destroy(this->default_scheduler);
	this->mutex->destroy(this->mutex);
	this->jobs->destroy(this->jobs);
	free(this);
}

/*
 * Described in header
 */
scheduler_t *android_scheduler_create(jobject context, scheduler_t *scheduler)
{
	private_scheduler_t *this;
	JNIEnv *env;
	jmethodID method_id;
	jobject obj;
	jclass cls;

	INIT(this,
		.public = {
			.get_job_load = _get_job_load,
			.schedule_job = _schedule_job,
			.schedule_job_ms = _schedule_job_ms,
			.schedule_job_tv = _schedule_job_tv,
			.flush = _flush,
			.destroy = _destroy,
		},
		.default_scheduler = scheduler,
		.jobs = hashtable_create(hashtable_hash_str, hashtable_equals_str, 16),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	androidjni_attach_thread(&env);
	cls = (*env)->FindClass(env, JNI_PACKAGE_STRING "/Scheduler");
	if (!cls)
	{
		goto failed;
	}
	this->cls = (*env)->NewGlobalRef(env, cls);
	method_id = (*env)->GetMethodID(env, cls, "<init>",
									"(Landroid/content/Context;)V");
	if (!method_id)
	{
		goto failed;
	}
	obj = (*env)->NewObject(env, cls, method_id, context);
	if (!obj)
	{
		goto failed;
	}
	this->obj = (*env)->NewGlobalRef(env, obj);
	androidjni_detach_thread();
	return &this->public;

failed:
	DBG1(DBG_JOB, "failed to create Scheduler object");
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	destroy(this);
	return NULL;
}
