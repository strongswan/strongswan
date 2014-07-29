#include "external_authorization_listener.h"

#include <stdlib.h>
#include <daemon.h>
#include <printf.h>
#include <sys/wait.h>

typedef struct private_external_authorization_listener_t private_external_authorization_listener_t;

/**
 * Private data of an external_authorization_listener_t object.
 */
struct private_external_authorization_listener_t {

	/**
	 * Public external_authorization_listener_listener_t interface.
	 */
	external_authorization_listener_t public;

	/**
	 * Path to authorization program
	 */
	char *path;
};

METHOD(listener_t, authorize, bool,
	private_external_authorization_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	int authorized = 0;

	if (final)
	{
		identification_t *peer_id;
		identification_t *my_id;
		my_id = ike_sa->get_my_id(ike_sa);
		peer_id = ike_sa->get_other_id(ike_sa);
		if (peer_id && my_id && peer_id->equals(peer_id, my_id))
		{
			DBG2(DBG_CFG, "called for my_id: '%Y'", my_id);
			*success = TRUE;
			return TRUE;
		}
		if (peer_id)
		{
			DBG2(DBG_CFG, "peer identity received: '%Y'", peer_id);
			char buf[255];
			snprintf(buf, 255, "%Y", peer_id);
			setenv("IPSEC_IDENTITY", (char*)buf, 1);
			DBG2(DBG_CFG, "calling script: %s", this->path);
			authorized = WEXITSTATUS(system(this->path));
			DBG2(DBG_CFG, "script returned: %d", authorized);
		}
		if (authorized == 0)
		{
			DBG2(DBG_CFG, "peer identity '%Y' authorized", peer_id);
			*success = TRUE;
		}
		else
		{
			DBG1(DBG_CFG, "peer identity '%Y' not authorized externally", peer_id);
			*success = FALSE;
		}
	}
	return TRUE;
}

METHOD(external_authorization_listener_t, set_path, void,
	private_external_authorization_listener_t *this, char* path)
{
	DBG1(DBG_CFG, "New authorization script: %s", path);
	this->path = path;
}


/**
 * See header
 */
external_authorization_listener_t *external_authorization_listener_create(char* program_path)
{
	private_external_authorization_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.authorize = _authorize,
			},
		},
		.path = program_path,
	);

	return &this->public;
}
