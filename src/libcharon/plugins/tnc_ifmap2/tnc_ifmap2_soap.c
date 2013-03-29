/*
 * Copyright (C) 2011-2013 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_ifmap2_soap.h"

#include <utils/debug.h>
#include <credentials/sets/mem_cred.h>
#include <daemon.h>

#include <tls_socket.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define IFMAP_NO_FD		-1
#define IFMAP_SERVER_ID	"C=DE, ST=Niedersachsen, L=Hannover, O=Hochschule Hannover, OU=Trust@FHH, CN=irond.trust.inform.fh-hannover.de"		
#define IFMAP_NS		"http://www.trustedcomputinggroup.org/2010/IFMAP/2"
#define IFMAP_META_NS	"http://www.trustedcomputinggroup.org/2010/IFMAP-METADATA/2"
#define IFMAP_LOGFILE	"strongswan_ifmap.log"
#define IFMAP_SERVER	"https://localhost:8443/"

typedef struct private_tnc_ifmap2_soap_t private_tnc_ifmap2_soap_t;

/**
 * Private data of an tnc_ifmap2_soap_t object.
 */
struct private_tnc_ifmap2_soap_t {

	/**
	 * Public tnc_ifmap2_soap_t interface.
	 */
	tnc_ifmap2_soap_t public;

	/**
	 * SOAP Session ID
	 */
	char *session_id;

	/**
	 * IF-MAP Publisher ID
	 */
	char *ifmap_publisher_id;

	/**
	 * PEP and PDP device name
	 */
	char *device_name;

	/**
	 * IF-MAP Server host
	 */
	host_t *host;

	/**
	 * TLS socket
	 */
	tls_socket_t *tls;

	/**
	 * File descriptor for secure TCP socket
	 */
	int fd;

	/**
	 * In memory credential set
	 */
	mem_cred_t *creds;

};

/**
 * Send request and receive result via SOAP
 */
static bool send_receive(private_tnc_ifmap2_soap_t *this,
									 char *request_qname, chunk_t request,
									 char *receipt_qname, chunk_t *result)

{
	int written, len;
	char *pos;

	char soap[] =
		"<?xml version=\"1.0\"?>"
		"<env:Envelope xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\">"
		"  <env:Body>"
		"    <ifmap:newSession xmlns:ifmap=\"http://www.trustedcomputinggroup.org/2010/IFMAP/2\"></ifmap:newSession>"
		"  </env:Body>"
		"</env:Envelope>";

	char http_header[] =
		 "POST /ifmap HTTP/1.1\r\n"
		 "Content-Type: application/soap+xml; charset=utf-8\r\n"
		 "Content-Length: ";

	char buf[2048];

	pos = buf;
	len = sizeof(buf);
	written = snprintf(pos, len, "%s", http_header);
	pos += written;
	len -= written;
	written = snprintf(pos, len, "%d\r\n\r\n%s", strlen(soap), soap);
 
	this->tls->write(this->tls, buf, strlen(buf));
	len = this->tls->read(this->tls, buf, sizeof(buf), TRUE);
	*result = chunk_create(buf, len);
	DBG2(DBG_TNC, "%B", result);
 
	return TRUE;
}

METHOD(tnc_ifmap2_soap_t, newSession, bool,
	private_tnc_ifmap2_soap_t *this)
{
	chunk_t request, result;

	send_receive(this, "newSession", request, "newSessionResult", &result);

    return this->session_id && this->ifmap_publisher_id;
}

METHOD(tnc_ifmap2_soap_t, purgePublisher, bool,
	private_tnc_ifmap2_soap_t *this)
{
	/* send purgePublisher request and receive purgePublisherReceived */
	/* return send_receive(this, "purgePublisher", request,
							  "purgePublisherReceived", NULL); */
	return FALSE;
}

METHOD(tnc_ifmap2_soap_t, publish_ike_sa, bool,
	private_tnc_ifmap2_soap_t *this, ike_sa_t *ike_sa, bool up)
{
	/* send publish request and receive publishReceived */
	/* return send_receive(this, "publish", request, "publishReceived", NULL); */
	return FALSE;
}

METHOD(tnc_ifmap2_soap_t, publish_device_ip, bool,
	private_tnc_ifmap2_soap_t *this, host_t *host)
{
	/* send publish request and receive publishReceived */
	/* return send_receive(this, "publish", request, "publishReceived", NULL); */
	return FALSE;
}

METHOD(tnc_ifmap2_soap_t, publish_enforcement_report, bool,
	private_tnc_ifmap2_soap_t *this, host_t *host, char *action, char *reason)
{
	/* send publish request and receive publishReceived */
	/* return send_receive(this, "publish", request, "publishReceived", NULL); */
	return FALSE;
}

METHOD(tnc_ifmap2_soap_t, endSession, bool,
	private_tnc_ifmap2_soap_t *this)
{
	/* send endSession request and receive end SessionResult */
	/* return send_receive(this, "endSession", request, "endSessionResult", NULL); */
	return FALSE;
}

METHOD(tnc_ifmap2_soap_t, destroy, void,
	private_tnc_ifmap2_soap_t *this)
{
	if (this->session_id)
	{
		endSession(this);
		free(this->session_id);
		free(this->ifmap_publisher_id);
		free(this->device_name);
	}
	DESTROY_IF(this->tls);
	DESTROY_IF(this->host);

	if (this->fd != IFMAP_NO_FD)
	{
		close(this->fd);
	}
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	this->creds->destroy(this->creds);
	free(this);
}

static bool soap_init(private_tnc_ifmap2_soap_t *this)
{
	char *server, *server_cert, *client_cert, *client_key;
	certificate_t *cert;
	private_key_t *key;
	identification_t *server_id, *client_id;

	/** Load [self-signed] MAP server certificate */
	server_cert = lib->settings->get_str(lib->settings,
					"%s.plugins.tnc-ifmap2.server_cert", NULL, charon->name);
	if (!server_cert)
	{
		DBG1(DBG_TNC, "MAP server certificate not defined");
		return FALSE;
	}
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, server_cert, BUILD_END);
	if (!cert)
	{
		DBG1(DBG_TNC, "loading MAP server certificate from '%s' failed",
					   server_cert);
		return FALSE;
	}
	DBG1(DBG_TNC, "loaded MAP server certificate from '%s'", server_cert);
	server_id = cert->get_subject(cert);
	this->creds->add_cert(this->creds, TRUE, cert);

	/* Load MAP client certificate */
	client_cert = lib->settings->get_str(lib->settings,
					"%s.plugins.tnc-ifmap2.client_cert", NULL, charon->name);
	if (!client_cert)
	{
		DBG1(DBG_TNC, "MAP client certificate not defined");
		return FALSE;
	}
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, client_cert, BUILD_END);
	if (!cert)
	{
		DBG1(DBG_TNC, "loading MAP client certificate from '%s' failed",
					   client_cert);
		return FALSE;
	}
	DBG1(DBG_TNC, "loaded MAP client certificate from '%s'", client_cert);
	client_id = cert->get_subject(cert);
	this->creds->add_cert(this->creds, TRUE, cert);

	/* Load MAP client private key */
	client_key = lib->settings->get_str(lib->settings,
					"%s.plugins.tnc-ifmap2.client_key", NULL, charon->name);
	if (!client_key)
	{
		DBG1(DBG_TNC, "MAP client private key not defined");
		return FALSE;
	}
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
							  BUILD_FROM_FILE, client_key, BUILD_END);
	if (!key)
	{
		DBG1(DBG_TNC, "loading MAP client private key from '%s' failed",
					   client_key);
		return FALSE;
	}
	DBG1(DBG_TNC, "loaded MAP client RSA private key from '%s'", client_key);
	this->creds->add_key(this->creds, key);

	/* Open TCP socket and connect to MAP server */
	server = "127.0.0.1";
	this->host = host_create_from_dns(server, 0, 8444);
	if (!this->host)
	{
		DBG1(DBG_TNC, "resolving hostname %s failed", server);
		return FALSE;
	}

	this->fd = socket(this->host->get_family(this->host), SOCK_STREAM, 0);
	if (this->fd == IFMAP_NO_FD)
	{
		DBG1(DBG_TNC, "opening socket failed: %s", strerror(errno));
		return FALSE;
	}

	if (connect(this->fd, this->host->get_sockaddr(this->host),
						 *this->host->get_sockaddr_len(this->host)) == -1)
	{
		DBG1(DBG_TNC, "connecting to %#H failed: %s",
					   this->host, strerror(errno));
		return FALSE;
	}

	/* Open TLS socket */
	this->tls = tls_socket_create(FALSE, server_id, client_id, this->fd, NULL);
	if (!this->tls)
	{
		DBG1(DBG_TNC, "creating TLS socket failed");
		return FALSE;
	}

	return TRUE;
}

/**
 * See header
 */
tnc_ifmap2_soap_t *tnc_ifmap2_soap_create()
{
	private_tnc_ifmap2_soap_t *this;

	INIT(this,
		.public = {
			.newSession = _newSession,
			.purgePublisher = _purgePublisher,
			.publish_ike_sa = _publish_ike_sa,
			.publish_device_ip = _publish_device_ip,
			.publish_enforcement_report = _publish_enforcement_report,
			.endSession = _endSession,
			.destroy = _destroy,
		},
		.fd = IFMAP_NO_FD,
		.creds = mem_cred_create(),
	);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);

	if (!soap_init(this))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

