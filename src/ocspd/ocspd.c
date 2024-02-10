/*
 * Copyright (C) 2024 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <library.h>
#include <utils/debug.h>
#include <utils/lexparser.h>
#include <networking/host.h>
#include <credentials/sets/mem_cred.h>

/**
 * Print usage information
 */
static void usage(FILE *out, char *cmd)
{
	fprintf(out, "usage:\n");
	fprintf(out, "  %s --ipv4 <address>|--ipv6 <address> [--port <port>]\n", cmd);
	fprintf(out, "\n");
	fprintf(out, "options:\n");
	fprintf(out, "  --help                   print help and exit\n");
	fprintf(out, "  --ipv4 <address>         specify IPv4 address to use \n");
	fprintf(out, "  --ipv6 <address>         specify IPv6 address to use\n");
	fprintf(out, "  --port <port>            specify the port to use\n");
	fprintf(out, "  --threads <number>       specify the number of threads to spawn\n");
	fprintf(out, "  --debug <debug level>    set debug level, default is 1\n");
}

/**
 * In-Memory credential set
 */
static mem_cred_t *creds;

/**
 * IPv4/IPv6 sockets
 */
static int ipv4_socket, ipv6_socket;

/**
 * Signing key
 */
private_key_t *key = NULL;

/**
 * TLS debug level
 */
static level_t debug_level = 1;

static void dbg_ocspd(debug_t group, level_t level, char *fmt, ...)
{
	if (level <= debug_level)
	{
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Cleanup
 */
static void cleanup()
{
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	library_deinit();
}

/**
 * Initialize library
 */
static void init()
{
	library_init(NULL, "ocspd");
	dbg = dbg_ocspd;

	/* load ocspd plugins */
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "%s.load", PLUGINS, lib->ns)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);

	atexit(cleanup);
}

/**
 * Open IPv4 or IPv6 TCP socket
 */
static int open_tcp_socket(int family, uint16_t port)
{
	int on = TRUE;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int skt;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = family;

	/* precalculate constants depending on address family */
	switch (family)
	{
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)&addr;

			htoun32(&sin->sin_addr.s_addr, INADDR_ANY);
			htoun16(&sin->sin_port, port);
			addrlen = sizeof(struct sockaddr_in);
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;

			memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			htoun16(&sin6->sin6_port, port);
			addrlen = sizeof(struct sockaddr_in6);
			break;
		}
		default:
			return 0;
	}

	/* open the socket */
	skt = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (skt < 0)
	{
		DBG1(DBG_CFG, "opening TCP socket failed: %s", strerror(errno));
		return 0;
	}
	if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) < 0)
	{
		DBG1(DBG_CFG, "unable to set SO_REUSEADDR on socket: %s",
					   strerror(errno));
		close(skt);
		return 0;
	}
	if (family == AF_INET6)
	{
	if (setsockopt(skt, IPPROTO_IPV6, IPV6_V6ONLY,
							(void *)&on, sizeof(on)) < 0)
		{
			DBG1(DBG_CFG, "unable to set IPV6_V6ONLY on socket: %s",
						   strerror(errno));
			close(skt);
			return 0;
		}
	}

	/* bind the socket */
	if (bind(skt, (struct sockaddr *)&addr, addrlen) < 0)
	{
		DBG1(DBG_CFG, "unable to bind TCP socket: %s", strerror(errno));
		close(skt);
		return 0;
	}

	/* start listening on socket */
	if (listen(skt, 5) == -1)
	{
		DBG1(DBG_TNC, "listen on TCP socket failed: %s", strerror(errno));
		close(skt);
		return 0;
	}

	return skt;
}

static bool parse_http_header(chunk_t *in,  u_int *content_len)
{
	chunk_t line, method, path, parameter;
	u_int len;

	/*initialize output parameters */
	*content_len = 0;

	/* Process HTTP protocol version and HTTP status code */
	if (!fetchline(in, &line) ||
		!extract_token(&method, ' ', &line) || !match("POST", &method) ||
		!extract_token(&path, ' ', &line) ||
		!(match("HTTP/1.1", &line) || match("HTTP/1.0", &line)))
	{
		DBG1(DBG_APP, "malformed http response header");
		return FALSE;
	}

	/* Process HTTP header line by line until the HTTP body is reached */
	while (fetchline(in, &line))
	{
		if (line.len == 0)
		{
			break;
		}
		if (extract_token(&parameter, ':', &line) && eat_whitespace(&line))
		{
			if (matchcase("Content-Length", &parameter))
			{
				if (sscanf(line.ptr, "%u", &len) == 1)
				{
					*content_len = len;
				}
			}
			else if (matchcase("Content-Type", &parameter))
			{
				if (!matchcase("application/ocsp-request", &line))
				{
					DBG1(DBG_APP, "wrong Content-Type '%.*s", line.len, line.ptr);
					return FALSE;
				}
			}
		}
	}
	return TRUE;
}

/**
 * Accept TCP connection received on the PT-TLS listening socket
 */
static bool ocsp_receive(void *this, int fd, watcher_event_t event)
{
	int ocsp_fd, flags = 0;
	chunk_t request;
	u_int len;
	ssize_t in;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	char buf[4096];
	host_t *client;

	ocsp_fd = accept(fd, (sockaddr_t*)&addr, &addrlen);
	if (ocsp_fd == -1)
	{
		DBG1(DBG_APP, "accepting OCSP stream failed: %s", strerror(errno));
		return FALSE;
	}
	client = host_create_from_sockaddr((sockaddr_t*)&addr);
	DBG1(DBG_APP, "accepting OCSP stream %d from %H", ocsp_fd, client);
	client->destroy(client);

	in = recv(ocsp_fd, buf, sizeof(buf), flags);

	if (in < 0)
	{
		DBG1(DBG_APP, "recv error");
	}
	else
	{
		chunk_t signature = chunk_empty;
		chunk_t data = chunk_from_chars(
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
		);

		request = chunk_create(buf, in);
		if (parse_http_header(&request, &len))
		{
			DBG1(DBG_APP, "Content-Length: %u bytes, remaining %d bytes", len,
				 request.len);

			if (!key->sign(key, SIGN_RSA_EMSA_PKCS1_SHA2_384, NULL,
					   data, &signature))
			{
				DBG1(DBG_APP, "creating OCSP response signature failed");
			}
			else
			{
				DBG1(DBG_APP, "creating OCSP response signature successful");
			}
			chunk_free(&signature);
		}
	}
	close(ocsp_fd);

	/*
	pt_tls = pt_tls_server_create(this->server, pt_tls_fd, auth, tnccs);
	if (!pt_tls)
	{
		DBG1(DBG_TNC, "could not create PT-TLS connection instance");
		close(pt_tls_fd);
		return FALSE;
	}
	lib->watcher->add(lib->watcher, ocsp_fd, WATCHER_READ,
							 (watcher_cb_t)ocsp_receive_more, NULL);
	*/
	return TRUE;
}

/**
 * Run the daemon and handle unix signals
 */
static void run()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);

	while (TRUE)
	{
		int sig;

		/* wait for signal */
		sig = sigwaitinfo(&set, NULL);
		if (sig == -1)
		{
			if (errno == EINTR)
			{	/* ignore signals we didn't wait for */
				continue;
			}
			DBG1(DBG_DMN, "waiting for signal failed: %s", strerror(errno));
			return;
		}

		switch (sig)
		{
			case SIGHUP:
				DBG1(DBG_APP, "received SIGHUP, updating configuration");
				continue;
			case SIGINT:
			case SIGTERM:
				DBG1(DBG_APP, "received %s, shutting down",
					(sig == SIGINT) ? "SIGINT" : "SIGTERM");
			return;
		}
	}
}


int main(int argc, char *argv[])
{
	mem_cred_t *creds;
	chunk_t handle = chunk_empty;
	shared_key_t *shared = NULL;
	identification_t *owner;
	char keyid[] = "10", pin[] = "272841";
	struct sigaction action;
	bool has_ipv4 = FALSE, has_ipv6 = FALSE;
	int port = 80, threads = 4, res = 1;

	init();

	while (TRUE)
	{
		struct option long_opts[] = {
			{"help",    no_argument,       NULL, 'h' },
			{"port",    required_argument, NULL, 'p' },
			{"ipv4",    no_argument,       NULL, '4' },
			{"ipv6",    no_argument,       NULL, '6' },
			{"threads", required_argument, NULL, 't' },
			{"debug",   required_argument, NULL, 'd' },
			{0,0,0,0 }
		};

		switch (getopt_long(argc, argv, "hp;46t:d:", long_opts, NULL))
		{
			case EOF:
				break;
			case 'h':
				usage(stdout, argv[0]);
				return 0;
			case 'p':
				port = atoi(optarg);
				continue;
			case 'd':
				debug_level = atoi(optarg);
				continue;
			case '4':
				has_ipv4 = TRUE;
				continue;
			case '6':
				has_ipv6 = TRUE;
				continue;
			case 't':
				threads = atoi(optarg);
				continue;
			default:
				usage(stderr, argv[0]);
				return 1;
		}
		break;
	}

	creds = mem_cred_create();
	lib->credmgr->add_local_set(lib->credmgr, &creds->set, FALSE);

	handle = chunk_from_hex(chunk_from_str(keyid), NULL);
	shared = shared_key_create(SHARED_PIN, chunk_clone(chunk_from_str(pin)));
	owner = identification_create_from_encoding(ID_KEY_ID, handle);
	creds->add_shared(creds, shared->get_ref(shared), owner, NULL);

	key = lib->creds->create(lib->creds,
							CRED_PRIVATE_KEY, KEY_ANY,
							BUILD_PKCS11_KEYID, handle, BUILD_END);
	chunk_free(&handle);
	if (!key)
	{
		DBG1(DBG_APP, "attaching to private key handle %s failed", keyid);
		goto end;
	}
	creds->add_key(creds, key);

	if (has_ipv4)
	{
		ipv4_socket = open_tcp_socket(AF_INET, port);
		if (ipv4_socket)
		{
			lib->watcher->add(lib->watcher, ipv4_socket, WATCHER_READ,
							 (watcher_cb_t)ocsp_receive, NULL);
		}
		else
		{
			DBG1(DBG_APP, "could not open IPv4 TCP socket, IPv4 disabled");
		}
	}
	if (has_ipv6)
	{
		ipv6_socket = open_tcp_socket(AF_INET6, port);
		if (ipv6_socket)
		{
			lib->watcher->add(lib->watcher, ipv6_socket, WATCHER_READ,
							 (watcher_cb_t)ocsp_receive, NULL);
		}
		else
		{
			DBG1(DBG_APP, "could not open IPv6 TCP socket, IPv6 disabled");
		}
	}
	if (!ipv4_socket && !ipv6_socket)
	{
		DBG1(DBG_APP, "could not create any listening sockets, exiting");
		goto end;
	}

	/* add handler for fatal signals,
	 * INT, TERM and HUP are handled by sigwaitinfo() in run()
	 */
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGINT);
	sigaddset(&action.sa_mask, SIGTERM);
	sigaddset(&action.sa_mask, SIGHUP);

	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);

	pthread_sigmask(SIG_SETMASK, &action.sa_mask, NULL);

	lib->processor->set_threads(lib->processor, threads);
	res = 0;

	/* main thread goes to run loop */
	run();

end:
	if (ipv4_socket)
	{
		lib->watcher->remove(lib->watcher, ipv4_socket);
		close(ipv4_socket);
	}
	if (ipv6_socket)
	{
		lib->watcher->remove(lib->watcher, ipv6_socket);
		close(ipv6_socket);
	}

	lib->credmgr->remove_local_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	exit(res);
}
