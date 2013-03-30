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
#include "tnc_ifmap2_soap_msg.h"

#include <utils/debug.h>
#include <credentials/sets/mem_cred.h>
#include <daemon.h>

#include <tls_socket.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define IFMAP_NS		"http://www.trustedcomputinggroup.org/2010/IFMAP/2"
#define IFMAP_META_NS	"http://www.trustedcomputinggroup.org/2010/IFMAP-METADATA/2"
#define IFMAP_LOGFILE	"strongswan_ifmap.log"
#define IFMAP_SERVER	"https://localhost:8443/"
#define IFMAP_NO_FD		-1

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
	xmlChar *session_id;

	/**
	 * IF-MAP Publisher ID
	 */
	xmlChar *ifmap_publisher_id;

	/**
	 * IF-MAP namespace
	 */
	xmlNsPtr ns;

	/**
	 * IF-MAP metadata namespace
	 */
	xmlNsPtr ns_meta;

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

METHOD(tnc_ifmap2_soap_t, newSession, bool,
	private_tnc_ifmap2_soap_t *this)
{
	tnc_ifmap2_soap_msg_t *soap_msg;
	xmlNodePtr request, result;

	/*build newSession request */
	request = xmlNewNode(NULL, "newSession");
	this->ns = xmlNewNs(request, IFMAP_NS, "ifmap");
	xmlSetNs(request, this->ns);

	soap_msg = tnc_ifmap2_soap_msg_create(this->tls);
	if (!soap_msg->post(soap_msg, "newSession", request,
								  "newSessionResult", &result))
	{
		soap_msg->destroy(soap_msg);
		return FALSE;
	}

	/* get session-id and ifmap-publisher-id properties */
	this->session_id = xmlGetProp(result, "session-id");
	this->ifmap_publisher_id = xmlGetProp(result, "ifmap-publisher-id");
	soap_msg->destroy(soap_msg);

	DBG1(DBG_TNC, "session-id: %s, ifmap-publisher-id: %s",
				   this->session_id, this->ifmap_publisher_id);

	/* set PEP and PDP device name (defaults to IF-MAP Publisher ID) */
	this->device_name = lib->settings->get_str(lib->settings,
									"%s.plugins.tnc-ifmap2.device_name",
									 this->ifmap_publisher_id, charon->name);
	this->device_name = strdup(this->device_name);

    return this->session_id && this->ifmap_publisher_id;
}

METHOD(tnc_ifmap2_soap_t, purgePublisher, bool,
	private_tnc_ifmap2_soap_t *this)
{
	tnc_ifmap2_soap_msg_t *soap_msg;
	xmlNodePtr request;
	bool success;

	/* build purgePublisher request */
	request = xmlNewNode(NULL, "purgePublisher");
	this->ns = xmlNewNs(request, IFMAP_NS, "ifmap");
	xmlSetNs(request, this->ns);
	xmlNewProp(request, "session-id", this->session_id);
	xmlNewProp(request, "ifmap-publisher-id", this->ifmap_publisher_id);

	soap_msg = tnc_ifmap2_soap_msg_create(this->tls);
	success = soap_msg->post(soap_msg, "purgePublisher", request,
									   "purgePublisherReceived", NULL);
	soap_msg->destroy(soap_msg);

	return success;
}

/**
 * Create a publish request
 */
static xmlNodePtr create_publish_request(private_tnc_ifmap2_soap_t *this)
{
	xmlNodePtr request;

	request = xmlNewNode(NULL, "publish");
	this->ns = xmlNewNs(request, IFMAP_NS, "ifmap");
	xmlSetNs(request, this->ns);
	this->ns_meta = xmlNewNs(request, IFMAP_META_NS, "meta");
	xmlNewProp(request, "session-id", this->session_id);

	return request;
}

/**
 * Create a device
 */
static xmlNodePtr create_device(private_tnc_ifmap2_soap_t *this)
{
	xmlNodePtr node, node2;

	node = xmlNewNode(NULL, "device");
	node2 = xmlNewNode(NULL, "name");
	xmlAddChild(node, node2);
	xmlNodeAddContent(node2, this->device_name);

	return node;
}

/**
 * Create an ip-address
 */
static xmlNodePtr create_ip_address(private_tnc_ifmap2_soap_t *this,
									host_t *host)
{
	xmlNodePtr node;
	char buf[BUF_LEN];

	node = xmlNewNode(NULL, "ip-address");

	if (host->get_family(host) == AF_INET6)
	{
		chunk_t address;
		int len, written, i;
		char *pos;
		bool first = TRUE;

		/* output IPv6 address in canonical IF-MAP 2.0 format */
		address = host->get_address(host);
		pos = buf;
		len = sizeof(buf);

		for (i = 0; i < address.len; i = i + 2)
		{
			written = snprintf(pos, len, "%s%x", first ? "" : ":",
							   256*address.ptr[i] +  address.ptr[i+1]);
			if (written < 0 || written >= len)
			{
				break;
			}
			pos += written;
			len -= written;
			first = FALSE;
		}
	}
	else
	{
		snprintf(buf, BUF_LEN, "%H", host);
	}

	xmlSetProp(node, "value", buf);
	xmlSetProp(node, "type", host->get_family(host) == AF_INET ? "IPv4" : "IPv6");

	return node;
}

/**
 * Create metadata
 */
static xmlNodePtr create_metadata(private_tnc_ifmap2_soap_t *this,
								  xmlChar *metadata)
{
	xmlNodePtr node, node2;

	node = xmlNewNode(NULL, "metadata");
	node2 = xmlNewNode(this->ns_meta, metadata);
	xmlAddChild(node, node2);
	xmlSetProp(node2, "ifmap-cardinality", "singleValue");

	return node;
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
	tnc_ifmap2_soap_msg_t *soap_msg;
	xmlNodePtr request, update;
	bool success;

	/* build publish update request */
	request = create_publish_request(this);
	update = xmlNewNode(NULL, "update");
	xmlAddChild(request, update);

	/* add device, ip-address and metadata */
	xmlAddChild(update, create_device(this));
	xmlAddChild(update, create_ip_address(this, host));
	xmlAddChild(update, create_metadata(this, "device-ip"));

	soap_msg = tnc_ifmap2_soap_msg_create(this->tls);
	success = soap_msg->post(soap_msg, "publish", request,
									   "publishReceived", NULL);
	soap_msg->destroy(soap_msg);

	return success;
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
		xmlFree(this->session_id);
		xmlFree(this->ifmap_publisher_id);
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

	/**
	 * Load [self-signed] MAP server certificate
	 */
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

	/**
	 * Load MAP client certificate
	 */
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

	/**
	 * Load MAP client private key
	 */
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

	/**
	 * Open TCP socket and connect to MAP server
	 */
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

	/**
	 * Open TLS socket
	 */
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

