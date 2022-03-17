/*
 * Copyright (C) 2020 Noel Kuntze for Contauro AG
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

#include "command.h"

#include <errno.h>
#include <unistd.h>

struct vici_prompt_t {
    command_format_options_t format;
    vici_conn_t *conn;
};

typedef struct vici_prompt_t vici_prompt_t;

CALLBACK(prompt_cb, void,
	vici_prompt_t *this, char *name, vici_res_t *msg)
{
            char *a, *our_identity, *their_identity, *secret_type, *peer_message, txt[256];
        command_format_options_t format = this->format;
	vici_req_t *req;
	vici_res_t *res;
        
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(msg, "prompt-request", format & COMMAND_FORMAT_PRETTY, stdout);
	}

        /** print identities and type */
        secret_type=vici_find_str(msg, "UNKNOWN", "secret-type");
        our_identity=vici_find_str(msg, "UNKNOWN", "local-identity");
        their_identity=vici_find_str(msg, "UNKNOWN", "remote-identity");
        peer_message=vici_find_str(msg, "", "peer-message");
        vici_find_str(msg, "UNKNOWN", "secret-type");
        printf("Secret Type: %s\n", secret_type);
        printf("Their identity: %s\n", their_identity);
        printf("Our identity: %s\n", our_identity);
        snprintf(txt, sizeof(txt), "Peer message: %s. Please enter the password.", peer_message);
        /** Read credentials; One line (password or pin) */
        a = getpass(txt);
        /** ? Need to convert from wide characters (UTF-16) to UTF-8 ? */
        // a = fgets(buf, sizeof(buf), stdin);
        req = vici_begin("prompt-reply");
        vici_add_key_valuef(req, "secret-type",  secret_type);
        vici_add_key_valuef(req, "local-identity",  our_identity);
        vici_add_key_valuef(req, "remote-identity",  their_identity);        
        if (!a)
        {
            printf("Empty data or error occured\n");
            vici_add_key_valuef(req, "success", "no");
            vici_add_key_valuef(req, "errmsg", "User entered no data or an error occured");
        } else {
            vici_add_key_valuef(req, "success", "yes");
            chunk_t data = chunk_clone(chunk_from_str(a));
            vici_add_key_value(req, "secret", data.ptr, data.len);
            /* vici_add_key_value(req, "secret", a, strlen(a)+1); */
        }
        res = vici_submit(req, this->conn);
        printf("Secret sent\n");
        if (!res)
        {
            fprintf(stderr, "prompt-reply request failed: %s", strerror(errno));
            return;
        }
	if (this->format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "prompt-reply reply", this->format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else if (!streq(vici_find_str(res, "no", "success"), "yes"))
	{
		fprintf(stderr, "storing reply failed: %s\n",
				vici_find_str(res, "", "errmsg"));
	}
	else
	{
		printf("stored reply for identities %s == %s type %s\n", our_identity, their_identity, secret_type);
	}
	vici_free_res(res);
	return; 
}

static int promptcmd(vici_conn_t *conn)
{
	command_format_options_t format = COMMAND_FORMAT_NONE;
        vici_prompt_t *this;
        
        INIT(this,
            .format = format,
            .conn = conn
        );
        
	char *arg;
	int ret;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'P':
				format |= COMMAND_FORMAT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= COMMAND_FORMAT_RAW;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --prompt option");
		}
		break;
	}
        
	if (vici_register(conn, "prompt-request", prompt_cb, this) != 0)
	{
                free(this);
		ret = errno;
		fprintf(stderr, "registering for prompt-request failed: %s\n", strerror(errno));
		return ret;
	}
        
        printf("Ready; Waiting for message from daemon\n");
	wait_sigint();

	fprintf(stderr, "disconnecting...\n");
                
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		promptcmd, 'F', "prompt", "supply shared credentials",
		{"[--raw|--pretty]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
		}
	});
}
