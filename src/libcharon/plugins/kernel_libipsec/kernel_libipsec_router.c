/*
 * Copyright (C) 2013 Tobias Brunner
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

#include <unistd.h>
#include <fcntl.h>

#ifdef WIN32
#include <signal.h>
#endif

#include "kernel_libipsec_router.h"

#include <daemon.h>
#include <ipsec.h>
#include <collections/hashtable.h>
#include <networking/tun_device.h>
#include <threading/rwlock.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

typedef struct private_kernel_libipsec_router_t private_kernel_libipsec_router_t;

/**
 * Entry in the TUN device map
 */
typedef struct {
	/** virtual IP (points to internal data of tun) */
	host_t *addr;
	/** underlying TUN file descriptor (cached from tun) */
#ifdef WIN32
        HANDLE *handle;
#else
	int fd;
#endif /* WIN32 */
	/** TUN device */
	tun_device_t *tun;
} tun_entry_t;

#ifdef WIN32
typedef struct {
    HANDLE *fileHandle;
    OVERLAPPED *overlapped;
    chunk_t *buffer;
} handle_overlapped_buffer_t;
#endif
/**
 * Single instance of the router
 */
kernel_libipsec_router_t *router;

/**
 * Private data
 */
struct private_kernel_libipsec_router_t {

	/**
	 * Public interface
	 */
	kernel_libipsec_router_t public;

	/**
	 * Default TUN device if kernel interface does not require separate TUN
	 * devices per VIP or for tunnels without VIP.
	 */
	tun_entry_t tun;

        /**
	 * Hashtable that maps virtual IPs to TUN devices (tun_entry_t).
	 */
	hashtable_t *tuns;

	/**
	 * Lock for TUN device map
	 */
	rwlock_t *lock;
#ifdef WIN32
        /**
         * Event we use to signal handle_plain() about changes regarding tun devices
         */
        HANDLE event;
#else
	/**
	 * Pipe to signal handle_plain() about changes regarding TUN devices
	 */
	int notify[2];
#endif
};

/**
 * Hash function for TUN device map
 */
static u_int tun_entry_hash(tun_entry_t *entry)
{
	return chunk_hash(entry->addr->get_address(entry->addr));
}

/**
 * Comparison function for TUN device map
 */
static bool tun_entry_equals(tun_entry_t *a, tun_entry_t *b)
{
	return a->addr->ip_equals(a->addr, b->addr);
}

/**
 * Outbound callback
 */
static void send_esp(void *data, esp_packet_t *packet)
{
	charon->sender->send_no_marker(charon->sender, (packet_t*)packet);
}

/**
 * Receiver callback
 */
static void receiver_esp_cb(void *data, packet_t *packet)
{
	ipsec->processor->queue_inbound(ipsec->processor,
									esp_packet_create_from_packet(packet));
}

/**
 * Inbound callback
 */
static void deliver_plain(private_kernel_libipsec_router_t *this,
						  ip_packet_t *packet)
{
	tun_device_t *tun;
	tun_entry_t *entry, lookup = {
		.addr = packet->get_destination(packet),
	};

	this->lock->read_lock(this->lock);
	entry = this->tuns->get(this->tuns, &lookup);
	tun = entry ? entry->tun : this->tun.tun;
	tun->write_packet(tun, packet->get_encoding(packet));
	this->lock->unlock(this->lock);
	packet->destroy(packet);
}

/**
 * Read and process outbound plaintext packet for the given TUN device
 */
#if !defined(WIN32)
static void process_plain(tun_device_t *tun)
{
	chunk_t raw;

	if (tun->read_packet(tun, &raw))
	{
		ip_packet_t *packet;

		packet = ip_packet_create(raw);
		if (packet)
		{
			ipsec->processor->queue_outbound(ipsec->processor, packet);
		}
		else
		{
			DBG1(DBG_KNL, "invalid IP packet read from TUN device");
		}
	}
}

/**
 * Find flagged revents in a pollfd set by fd
 */
static int find_revents(struct pollfd *pfd, int count, int fd)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (pfd[i].fd == fd)
		{
			return pfd[i].revents;
		}
	}
	return 0;
}
#endif /* WIN32 */

/**
 * Job handling outbound plaintext packets
 */
static job_requeue_t handle_plain(private_kernel_libipsec_router_t *this)
{
#ifdef WIN32

        void **key = NULL;
        bool oldstate, status;
        uint32_t length, event_status = 0, i = 0, j = 0;
        handle_overlapped_buffer_t *bundle_array = NULL, dummy, tun_device_handle_overlapped_buffer, *structures = NULL;
        OVERLAPPED *overlapped = NULL;
        HANDLE *event_array = NULL, tun_device_event;
        tun_device_t *tun_device = this->tun.tun;
        enumerator_t *tuns_enumerator;

        /* Reset synchronisation event */
        ResetEvent(this->event);

        length = this->tuns->get_count(this->tuns);

        this->lock->read_lock(this->lock);

        /* Allocate variable number of objects on thread. Valid in some implementations? */
        overlapped = alloca((length+2)*sizeof(OVERLAPPED));
        event_array = alloca((length+2)*sizeof(HANDLE));
        bundle_array = alloca((length+2)*sizeof(handle_overlapped_buffer_t));
        structures = alloca((length+2)*sizeof(handle_overlapped_buffer_t));
        tun_device_event = OpenEvent(SYNCHRONIZE|EVENT_MODIFY_STATE, FALSE, "WIN32-libipsec-tun0");

        /* These are the arrays we're going to work with */

        tuns_enumerator = this->tuns->create_enumerator(this->tuns);
        /* first position is the event we use for synchronisation  */
        /* second position is this->tun */

        event_array[i] = this->event;
        bundle_array[i] = dummy;
        /* insert event object for this->tun device */
        i++;
        DBG1(DBG_LIB, "i: %d", i);
        event_array[i] = tun_device_event;

        /* dummy object for the notification handle */

        tun_device_handle_overlapped_buffer.buffer = alloca(sizeof(chunk_t));
        (*tun_device_handle_overlapped_buffer.buffer) = chunk_alloca(tun_device->get_mtu(tun_device));
        DBG1(DBG_LIB, "Allocated buffer.");
        tun_device_handle_overlapped_buffer.fileHandle = tun_device->get_handle(tun_device);
        DBG1(DBG_LIB, "Allocated file handle.");
        tun_device_handle_overlapped_buffer.overlapped = overlapped;
        DBG1(DBG_LIB, "Allocated overlapped..");
        memset(&tun_device_handle_overlapped_buffer.overlapped, 0, sizeof(OVERLAPPED));

        bundle_array[i] = tun_device_handle_overlapped_buffer;

        i++;

        /* Start ReadFile for this->tun.handle and this->event */
        /* pad bundle_array with two empty structures */
        /* iterate over all our tun devices, create event handles, reset them, queue read operations on all handles */

        while(tuns_enumerator->enumerate(tuns_enumerator, key, &tun_device))
        {
            char name[80];

            /* Allocate structure and buffer */

            structures[j].buffer = alloca(sizeof(chunk_t));
            (*structures[j].buffer) = chunk_alloca(tun_device->get_mtu(tun_device));

            structures[j].fileHandle = tun_device->get_handle(tun_device);
            /* Allocate and initialise OVERLAPPED structure */
            structures[j].overlapped = alloca(sizeof(OVERLAPPED));
            (*structures[j].overlapped) = overlapped[j];
            memset(&structures[j].overlapped, 0, sizeof(OVERLAPPED));
            /* Create unique name for that event. */
            snprintf(name, 80, "WIN32-libipsec-device-%d", i);
            /* Create unique event for read accesses on that device
             * No security attributes, no manual reset, initial state is unsignaled,
             * name is the special name we created
             */
            structures[j].overlapped->hEvent = CreateEvent(NULL, FALSE, FALSE, name);
            event_array[i] = structures[j].overlapped->hEvent;
            bundle_array[i] = structures[j];
            i++;

            /* Initialise read with the allocate overwrite structure */
            status = ReadFile(structures[j].fileHandle, structures[j].buffer->ptr,
                    structures[j].buffer->len, NULL, structures[j].overlapped);
            if (status)
            {
                /* Read returned immediately */
                /* We need to signal the event ourselves */
                SetEvent(event_array[i]);
                continue;
            }
            else
            {
                DWORD error = GetLastError();
                switch(error)
                {
                    case ERROR_IO_PENDING:
                        /* IO enqueud. Everything's fine. */
                        break;
                    case ERROR_INVALID_USER_BUFFER:
                    case ERROR_NOT_ENOUGH_MEMORY:
                        /* too many outstanding I/O requests
                         * We can't fix that and need to stop the process
                         */
                        DBG1(DBG_LIB, "the operating system did not allow us to enqueue more asynchronous operations");
                        this->lock->unlock(this->lock);
                        raise(SIGTERM);
                        /* fatal error */
                        break;
                    case ERROR_NOT_ENOUGH_QUOTA:
                        /* unable to page lock calling process's buffer */
                        DBG1(DBG_LIB, "the operating system could not lock the buffer");
                        this->lock->unlock(this->lock);
                        /* fatal error */
                        raise(SIGTERM);
                        break;
                    default:
                        DBG1(DBG_LIB, "Unknown error %d occured", error);
                        /* Some error we don't know */
                        /* exit */
                        /* TODO: Translate error number to human readable*/
                        /* fatal error */
                        raise(SIGTERM);
                        break;
                }
            }
            j++;
        }
        tuns_enumerator->destroy(tuns_enumerator);

        this->lock->unlock(this->lock);

        while(TRUE)
        {
            /* Wait for a handle to be signaled */
            /* In the mingw64 sources, MAXIMUM_WAIT_OBJECTS is defined as 64. That means we can wait for a maximum of 64 event handles.
             * This translates to 63 tun devices. I think this is sufficiently high to not have to implement a mechanism for waiting for more
             * events /support more TUN devices */
            oldstate = thread_cancelability(FALSE);
            event_status = WaitForMultipleObjects(i, event_array, FALSE, INFINITE);
            thread_cancelability(oldstate);
            /* A handle was signaled. Find the tun handle whose read was successful */

            /* We can only use the event_status of indication for the first completed IO operation.
             * After the event was signaled, we need to test the OVERLAPPED structure in the other array
             * to find out what event was signaled.
             */

            if ((WAIT_OBJECT_0 < event_status) < ((WAIT_OBJECT_0 + length - 1)))
            {
                /* the event at event_array[event_status - WAIT_OBJECT_0] has been signaled */
                /* It is possible that more than one event was signalled. In that case, (event_status - WAIT_OBJECT_0)
                 * is the index with the lowest event that was signalled. More signalled events can be found higher
                 */
                DWORD offset = event_status - WAIT_OBJECT_0;
                if (offset == 0)
                {
                    /* Notification about changes regarding the tun devices.
                     * We need to rebuild the array. So exit and rebuild. */

                    /* Cleanup*/
                    for(uint32_t k=0;k<i;k++)
                    {
                        /* stop all asynchronous IO */
                        CancelIo((*bundle_array[k].fileHandle));

                        ResetEvent(event_array[k]);
                    }
                    /* exit */
                    return JOB_REQUEUE_FAIR;
                }
                for(uint32_t k=1;k<i; k++)
                {
                    /* Is the object signaled? */
                    if (WaitForSingleObject(event_array[k], 0) == WAIT_OBJECT_0)
                    {
                        /* The arrays have the same length and the same positioning of the elements.
                         * Therefore, if event_array[k] is signaled, the read on bundle_array[i].fileHandle has succeeded
                         * and bundle_array[k].buffer has our data now. */

                        /* Do we need to copy the chunk before we enqueue it? */
                        ip_packet_t *packet;

                        packet = ip_packet_create((*bundle_array[k].buffer));
                        if (packet)
                        {
                                ipsec->processor->queue_outbound(ipsec->processor, packet);
                        }
                        else
                        {
                                DBG1(DBG_KNL, "invalid IP packet read from TUN device");
                        }
                        /* Reset the overlapped structure, event and buffer */
                        memset(&bundle_array[k].overlapped, 0, sizeof(OVERLAPPED));
                        /* Don't leak packets */
                        memset(bundle_array[k].buffer->ptr, 0, bundle_array[k].buffer->len);

                        bundle_array[k].overlapped->hEvent = event_array[k];
                        ResetEvent(event_array[k]);

                    }
                }

            }
            /* Function failed */
            else
            {
                DBG1(DBG_LIB, "waiting for events on the tun device reads failed.");
                /* cleanup, exit, retry */
            }
        }

        return JOB_REQUEUE_DIRECT;
#else
	enumerator_t *enumerator;
	tun_entry_t *entry;
	bool oldstate;
	int count = 0;
	char buf[1];
	struct pollfd *pfd;

	this->lock->read_lock(this->lock);

	pfd = alloca(sizeof(*pfd) * (this->tuns->get_count(this->tuns) + 2));
	pfd[count].fd = this->notify[0];
	pfd[count].events = POLLIN;
	count++;
	pfd[count].fd = this->tun.fd;
	pfd[count].events = POLLIN;
	count++;

	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		pfd[count].fd = entry->fd;
		pfd[count].events = POLLIN;
		count++;
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	oldstate = thread_cancelability(TRUE);
	if (poll(pfd, count, -1) <= 0)
	{
		thread_cancelability(oldstate);
		return JOB_REQUEUE_FAIR;
	}
	thread_cancelability(oldstate);

	if (pfd[0].revents & POLLIN)
	{
		/* list of TUN devices changed, read notification data, rebuild FDs */
		while (read(this->notify[0], &buf, sizeof(buf)) == sizeof(buf))
		{
			/* nop */
		}
		return JOB_REQUEUE_DIRECT;
	}

	if (pfd[1].revents & POLLIN)
	{
		process_plain(this->tun.tun);
	}

	this->lock->read_lock(this->lock);
	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		if (find_revents(pfd, count, entry->fd) & POLLIN)
		{
			process_plain(entry->tun);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	return JOB_REQUEUE_DIRECT;
#endif /* WIN32 */
}


METHOD(kernel_listener_t, tun, bool,
	private_kernel_libipsec_router_t *this, tun_device_t *tun, bool created)
{
	tun_entry_t *entry, lookup;
#if !defined(WIN32)
	char buf[] = {0x01};
#endif

	this->lock->write_lock(this->lock);
	if (created)
	{
		INIT(entry,
			.addr = tun->get_address(tun, NULL),
#ifdef WIN32
                        .handle = tun->get_handle(tun),
#else
			.fd = tun->get_fd(tun),
#endif /* WIN32 */
			.tun = tun,
		);
		this->tuns->put(this->tuns, entry, entry);
	}
	else
	{
		lookup.addr = tun->get_address(tun, NULL);
		entry = this->tuns->remove(this->tuns, &lookup);
		free(entry);
	}

#ifdef WIN32
        SetEvent(this->event);
#else
	/* notify handler thread to recreate FD set */
	ignore_result(write(this->notify[1], buf, sizeof(buf)));
#endif
	this->lock->unlock(this->lock);
	return TRUE;
}

METHOD(kernel_libipsec_router_t, get_tun_name, char*,
	private_kernel_libipsec_router_t *this, host_t *vip)
{
	tun_entry_t *entry, lookup = {
		.addr = vip,
	};
	tun_device_t *tun;
	char *name;

	if (!vip)
	{
		return strdup(this->tun.tun->get_name(this->tun.tun));
	}
	this->lock->read_lock(this->lock);
	entry = this->tuns->get(this->tuns, &lookup);
	tun = entry ? entry->tun : this->tun.tun;
	name = strdup(tun->get_name(tun));
	this->lock->unlock(this->lock);
	return name;
}

METHOD(kernel_libipsec_router_t, destroy, void,
	private_kernel_libipsec_router_t *this)
{
        DBG1(DBG_LIB, "Destroy on kernel_libipsec_router called");
	charon->receiver->del_esp_cb(charon->receiver,
							 (receiver_esp_cb_t)receiver_esp_cb);
	ipsec->processor->unregister_outbound(ipsec->processor,
										 (ipsec_outbound_cb_t)send_esp);
	ipsec->processor->unregister_inbound(ipsec->processor,
										 (ipsec_inbound_cb_t)deliver_plain);
	charon->kernel->remove_listener(charon->kernel, &this->public.listener);
	this->lock->destroy(this->lock);
	this->tuns->destroy(this->tuns);
#ifdef WIN32
        DBG1(DBG_LIB, "Setting event.");
        SetEvent(this->event);
        CloseHandle(this->tun.handle);
        CloseHandle(this->event);
        DBG1(DBG_LIB, "Handles closed");
        /* Remove all other handles we might have */
        /* TODO: Create enumerator, enumerate over tuns, close all those handles */
#else
	close(this->notify[0]);
	close(this->notify[1]);
#endif
	router = NULL;
	free(this);
        DBG1(DBG_LIB, "Destroy end.");
}

/**
 * Set O_NONBLOCK on the given socket.
 */
#if !defined(WIN32)
static bool set_nonblock(int socket)
{
	int flags = fcntl(socket, F_GETFL);
	return flags != -1 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) != -1;
}
#endif
/*
 * See header file
 */
kernel_libipsec_router_t *kernel_libipsec_router_create()
{
	private_kernel_libipsec_router_t *this;

	INIT(this,
		.public = {
			.listener = {
				.tun = _tun,
			},
			.get_tun_name = _get_tun_name,
			.destroy = _destroy,
		},
		.tun = {
			.tun = lib->get(lib, "kernel-libipsec-tun"),
		}
	);
#ifdef WIN32
	this->tun.handle = this->tun.tun->get_handle(this->tun.tun);
        this->event = CreateEvent(NULL, FALSE, FALSE, "WIN32-libipsec-tun0");
#else
	if (pipe(this->notify) != 0 ||
		!set_nonblock(this->notify[0]) || !set_nonblock(this->notify[1]))
	{
		DBG1(DBG_KNL, "creating notify pipe for kernel-libipsec router failed");
		free(this);
		return NULL;
	}

	this->tun.fd = this->tun.tun->get_fd(this->tun.tun);
#endif /* WIN32 */

	this->tuns = hashtable_create((hashtable_hash_t)tun_entry_hash,
								  (hashtable_equals_t)tun_entry_equals, 4);
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	charon->kernel->add_listener(charon->kernel, &this->public.listener);
	ipsec->processor->register_outbound(ipsec->processor, send_esp, NULL);
	ipsec->processor->register_inbound(ipsec->processor,
									(ipsec_inbound_cb_t)deliver_plain, this);
	charon->receiver->add_esp_cb(charon->receiver,
									(receiver_esp_cb_t)receiver_esp_cb, NULL);
	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)handle_plain, this,
									NULL, (callback_job_cancel_t)return_false));

	router = &this->public;
	return &this->public;
}
