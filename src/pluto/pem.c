/* Loading of PEM encoded files with optional encryption
 * Copyright (C) 2001-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

/* decrypt a PEM encoded data block using DES-EDE3-CBC
 * see RFC 1423 PEM: Algorithms, Modes and Identifiers
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <freeswan.h>

#include <library.h>
#include <asn1/pem.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"
#include "pem.h"

/**
 *  Converts a PEM encoded file into its binary form
 *  RFC 1421 Privacy Enhancement for Electronic Mail, February 1993
 *  RFC 934 Message Encapsulation, January 1985
 */
err_t pemtobin(chunk_t *blob, prompt_pass_t *pass, const char* label, bool *pgp)
{
	chunk_t password = chunk_empty;

	/* do we prompt for the passphrase? */
	if (pass && pass->prompt && pass->fd != NULL_FD)
	{
		int i;
		chunk_t blob_copy;
		err_t ugh = "invalid passphrase, too many trials";
		status_t status;

		whack_log(RC_ENTERSECRET, "need passphrase for '%s'", label);

		for (i = 0; i < MAX_PROMPT_PASS_TRIALS; i++)
		{
			int n;

			if (i > 0)
			{
				whack_log(RC_ENTERSECRET, "invalid passphrase, please try again");
			}
			n = read(pass->fd, pass->secret, PROMPT_PASS_LEN);

			if (n == -1)
			{
				err_t ugh = "read(whackfd) failed";

				whack_log(RC_LOG_SERIOUS,ugh);
				return ugh;
			}

			pass->secret[n-1] = '\0';
			
			if (strlen(pass->secret) == 0)
			{
				err_t ugh = "no passphrase entered, aborted";

				whack_log(RC_LOG_SERIOUS, ugh);
				return ugh;
			}

			blob_copy = chunk_clone(*blob);
			password = chunk_create(pass->secret, strlen(pass->secret));

			status = pem_to_bin(blob, password, pgp);
			if (status != INVALID_ARG)
			{
				if (status == SUCCESS)
				{
					whack_log(RC_SUCCESS, "valid passphrase");
				}
				else
				{
					whack_log(RC_LOG_SERIOUS, "%N, aborted", status_names, status);
				}
				free(blob_copy.ptr);
				return NULL;
			}
			
			/* blob is useless after wrong decryption, restore the original */
			free(blob->ptr);
			*blob = blob_copy;
		}
		whack_log(RC_LOG_SERIOUS, ugh);
		return ugh;
	}
	else
	{
		if (pass)
		{
			password = chunk_create(pass->secret, strlen(pass->secret));
		}
		if (pem_to_bin(blob, password, pgp) == SUCCESS)
		{
			return NULL;
		}
		else
		{
			return "pem to bin conversion failed";
		}
	}	
}
