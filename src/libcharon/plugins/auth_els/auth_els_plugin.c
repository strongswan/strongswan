/*
 * Copyright (C) 2019-2020 Marvell 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <linux/netlink.h>
#include <scsi/scsi_netlink_fc.h>
#include <scsi/scsi_netlink.h>
#include <pthread.h>

#include <collections/linked_list.h>

#include <processing/jobs/callback_job.h>
#include <credentials/credential_set.h>
#include <credentials/keys/shared_key.h>
#include <utils/identification.h>
#include <utils/backtrace.h>
#include <threading/thread.h>
#include <daemon.h>

#include "auth_els_utils.h"
#include "auth_els_plugin.h"
#include "auth_els_ike.h"
#include "auth_els_socket.h"
#include "auth_els_kernel_fc_sp.h"
#include "auth_els_configs.h"

/**
 * private data of auth_els plugin
 */
struct private_auth_els_plugin_t {

	auth_els_plugin_t public;

	auth_els_ike_t *ike;
	backend_t* backend;
	credential_set_t *creds;
	
	int apidev_fd;
	auth_els_configs_t *configs;
};
typedef struct private_auth_els_plugin_t private_auth_els_plugin_t;

// This plugin reference is being used for handling of signals because retreiving
// a context is too complicated.  Use with caution otherwise.
private_auth_els_plugin_t *plugin_ref;


static void handle_system_fault(int sig_type, siginfo_t* si, void* arg)
{
	DBG_STD ("thread %u received %x", thread_current_id(), sig_type);
	
	backtrace_t *backtrace;

	backtrace = backtrace_create(2);
	backtrace->log(backtrace, NULL, TRUE);
	backtrace->log(backtrace, stderr, TRUE);
	backtrace->destroy(backtrace);
	
	DBG_STD ("killing ourself, received critical signal");
	abort();
}

static void setup_signal_handlers (private_auth_els_plugin_t *plugin)
{
    struct sigaction sa;
	
	// fault handler
    memset (&sa, 0, sizeof (struct sigaction));  // struct
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handle_system_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);

}

/**
 * Initialize plugin
 */
static bool initialize_plugin(private_auth_els_plugin_t *this)
{
	if (this->configs->reload_config(this->configs) == FALSE)
	{
		return FALSE;
	}

	this->ike = auth_els_ike_create(&this->public);
	
	setup_signal_handlers (this);
	
	return TRUE;
}

/**
 * Initialize plugin and register listener
 */
static bool plugin_cb(private_auth_els_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		DBG_STD ("before socket_register");

		lib->credmgr->add_set(lib->credmgr, this->creds);
	}

	if (reg)
	{
		if (!initialize_plugin(this))
		{
			return FALSE;
		}
		charon->bus->add_listener(charon->bus, &this->ike->listener);
		charon->backends->add_backend(charon->backends, this->backend);
	}
	else
	{
		lib->credmgr->remove_set(lib->credmgr, this->creds);
	}
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	private_auth_els_plugin_t *this)
{
	return "auth-els";
}

METHOD(plugin_t, get_features, int,
	private_auth_els_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_fc_sp_register, auth_els_kernel_fc_sp_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK(socket_register, auth_els_socket_create),
			PLUGIN_PROVIDE(CUSTOM, "socket"),
				PLUGIN_DEPENDS(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "auth_els"),
	};
	*features = f;
	
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_auth_els_plugin_t *this)
{
	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_auth_els_plugin_t *this)
{
	DESTROY_IF(this->ike);
	
	free(this);
	
	DBG_STD ("Plugin destroy complete");
}

/**
 * Plugin constructor
 */
plugin_t *auth_els_plugin_create()
{
	private_auth_els_plugin_t *this;

	if (!lib->caps->keep(lib->caps, CAP_CHOWN))
	{
		DBG_FATAL ("creation failed");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.apidev_fd = -1,
		.configs = NULL,
	);
	
	 this->configs = auth_els_configs_create ();

	this->backend = this->configs->get_backend(this->configs);
	this->creds = this->configs->get_creds(this->configs);
	
	char auth_els_plugin_version[AUTH_MAX_STRING_VERSION_LEN + 1];

	sprintf(auth_els_plugin_version, "%d.%02d.%04d%s",
		AUTH_MAJOR_VERSION, AUTH_MINOR_VERSION, AUTH_BUILD_VERSION, AUTH_STRING_SUFFIX_VERSION);
	DBG1(DBG_CFG, "auth_els version is %s.", 
					auth_els_plugin_version);
	
	return &this->public.plugin;
}
