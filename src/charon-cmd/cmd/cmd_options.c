/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "cmd_options.h"

#include <getopt.h>

/**
 * See header.
 */
cmd_option_t cmd_options[CMD_OPT_COUNT] = {
	{ CMD_OPT_HELP, "help", no_argument, "",
	  "print this usage information and exit" },
	{ CMD_OPT_VERSION, "version", no_argument, "",
	  "show version information and exit" },
	{ CMD_OPT_HOST, "host", required_argument, "hostname",
	  "DNS name or address to connect to" },
	{ CMD_OPT_IDENTITY, "identity", required_argument, "identity",
	  "identity the client uses for the IKE exchange" },
	{ CMD_OPT_REMOTE_IDENTITY, "remote-identity", required_argument, "identity",
	  "server identity to expect, defaults to host" },
	{ CMD_OPT_CERT, "cert", required_argument, "path",
	  "trusted certificate, for authentication or trust chain validation" },
	{ CMD_OPT_RSA, "rsa", required_argument, "path",
	  "RSA private key to use for authentication" },
	{ CMD_OPT_AGENT, "agent", no_argument, "",
	  "use SSH agent for authentication"},
	{ CMD_OPT_LOCAL_TS, "local-ts", required_argument, "subnet",
	  "additional traffic selector to propose for our side" },
	{ CMD_OPT_REMOTE_TS, "remote-ts", required_argument, "subnet",
	  "remote traffic selector to propose for remote side" },
	{ CMD_OPT_PROFILE, "profile", required_argument, "name",
	  "authentication profile to use, where name is one of:", {
		"ikev2-pub:       IKEv2 with public key client authentication",
		"ikev2-eap:       IKEv2 with client EAP",
		"ikev2-pub-eap:   IKEv2 with public key client authentication + client EAP",
		"ikev1-pub:       IKEv1 public key authentication",
		"ikev1-xauth:     IKEv1 public key authentication + initiator XAuth",
		"ikev1-xauth-psk: IKEv1 PSK authentication + initiator XAuth (INSECURE!)",
		"ikev1-hybrid:    IKEv1 public key responder only + initiator XAuth",
	}},
};
