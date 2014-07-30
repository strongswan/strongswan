/*
Copyright (c) 2014 Vyronas Tsingaras (vtsingaras@it.auth.gr)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


#include "external_authorization_listener.h"

#include <stdlib.h>
#include <daemon.h>
#include <printf.h>
#include <stdio.h>
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
		identification_t *my_id = NULL;
		identification_t *peer_id = NULL;
		identification_t *eap_peer_id = NULL;
		my_id = ike_sa->get_my_id(ike_sa);
		peer_id = ike_sa->get_other_id(ike_sa);
		eap_peer_id = ike_sa->get_other_eap_id(ike_sa);
		if( peer_id == NULL || eap_peer_id == NULL )
		{
			DBG1(DBG_CFG, "Fatal Error!, empty identities");
			*success = FALSE;
			return FALSE;
		}
		if ( (peer_id && my_id && peer_id->equals(peer_id, my_id)) || 
			(eap_peer_id && my_id && eap_peer_id->equals(eap_peer_id, my_id)) )
		{
			DBG2(DBG_CFG, "called for my_id: '%Y'", my_id);
			*success = TRUE;
			return TRUE;
		}
		/*if eap_peer_id doesn't equal peer_id then we are called after an EAP round, else generic XAuth*/
		{
			char id_buf[512];
			char cmd_buf[2048];
			char prog_out[1024];
			FILE* fp = NULL;
			identification_t* generic_id = 
				(!eap_peer_id->equals(eap_peer_id, peer_id)) ? eap_peer_id : peer_id;
			memset(id_buf, 0, sizeof(id_buf));
			memset(cmd_buf, 0, sizeof(cmd_buf));
			memset(cmd_buf, 0, sizeof(prog_out));
			DBG2(DBG_CFG, "peer identity received: '%Y'", generic_id);
			snprintf(id_buf, sizeof(id_buf) - 1, "%Y", generic_id);
			DBG2(DBG_CFG, "calling program: %s", this->path);
			snprintf(cmd_buf, sizeof(cmd_buf) - 1, "\"%s\" %s \"%s\"", this->path,
				(!eap_peer_id->equals(eap_peer_id, peer_id)) ? "eap" : "ike", (char*)id_buf);
			fp = popen(cmd_buf, "r");
			if ( fp == NULL )
			{
				*success = FALSE;
				DBG1(DBG_CFG, "Fatal Error!, could not execute program (check permissions?)");
				return FALSE;
			}
			setvbuf(fp, NULL, _IONBF, 0);
			while (fgets(prog_out, sizeof(prog_out), fp) != NULL)
			{
				DBG2(DBG_CFG, prog_out);
			}
			authorized = WEXITSTATUS(pclose(fp));
			DBG2(DBG_CFG, "script returned: %d", authorized);
		}
		if (authorized == 0)
		{
			DBG2(DBG_CFG, "peer identity '%Y' authorized", 
				(!eap_peer_id->equals(eap_peer_id, peer_id)) ? eap_peer_id : peer_id);
			*success = TRUE;
		}
		else
		{
			DBG1(DBG_CFG, "peer identity '%Y' not authorized",
				 (!eap_peer_id->equals(eap_peer_id, peer_id)) ? eap_peer_id : peer_id);
			*success = FALSE;
		}
	}
	return TRUE;
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
