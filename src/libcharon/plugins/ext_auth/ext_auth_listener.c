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


#include "ext_auth_listener.h"

#include <stdlib.h>
#include <daemon.h>
#include <printf.h>
#include <stdio.h>
#include <sys/wait.h>

typedef struct private_ext_auth_listener_t private_ext_auth_listener_t;

/**
 * Private data of an ext_auth_listener_t object.
 */
struct private_ext_auth_listener_t {

	/**
	 * Public ext_auth_listener_listener_t interface.
	 */
	ext_auth_listener_t public;

	/**
	 * Path to authorization program
	 */
	char *path;
};

METHOD(listener_t, authorize, bool,
	private_ext_auth_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	int authorized = 0;

	if (final)
	{
		identification_t *my_id;
		identification_t *peer_id;
		identification_t *eap_peer_id;
		my_id = ike_sa->get_my_id(ike_sa);
		peer_id = ike_sa->get_other_id(ike_sa);
		eap_peer_id = ike_sa->get_other_eap_id(ike_sa);
		if( peer_id == NULL || eap_peer_id == NULL )
		{
			DBG1(DBG_CFG, "Fatal Error!, empty identities");
			*success = FALSE;
			return FALSE;
		}

		/*if eap_peer_id doesn't equal peer_id then we are called after an EAP round, else generic XAuth*/
		{
			char cmd_buf[2048];
			FILE* shell;

			DBG2(DBG_CFG, "peer identity received: '%Y'", eap_peer_id);
			DBG2(DBG_CFG, "calling program: %s", this->path);
			snprintf(cmd_buf, sizeof(cmd_buf), "IKE_REMOTE_ID='%Y' \"%s\" %s",eap_peer_id, this->path,
				(!eap_peer_id->equals(eap_peer_id, peer_id)) ? "eap" : "ike");
			shell = popen(cmd_buf, "r");
			if ( shell == NULL )
			{
				*success = FALSE;
				DBG1(DBG_CFG, "Fatal Error!, could not execute program (check permissions?)");
				return FALSE;
			}
			/*reused from updown*/
			while (TRUE)
			{
				char resp[512];

				if (fgets(resp, sizeof(resp), shell) == NULL)
				{
					if (ferror(shell))
					{
						DBG1(DBG_CHD, "error reading output from ext-auth program");
					}
					break;
				}
				else
				{
					char *e = resp + strlen(resp);
					if (e > resp && e[-1] == '\n')
					{	/* trim trailing '\n' */
						e[-1] = '\0';
					}
					DBG1(DBG_CHD, "ext-auth: %s", resp);
				}
			}
			authorized = WEXITSTATUS(pclose(shell));
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
ext_auth_listener_t *ext_auth_listener_create(char* program_path)
{
	private_ext_auth_listener_t *this;

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
