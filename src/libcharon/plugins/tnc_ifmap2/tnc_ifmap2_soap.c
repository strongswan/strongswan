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

#define _GNU_SOURCE /* for asprintf() */

#include "tnc_ifmap2_soap.h"

#include <utils/debug.h>
#include <utils/lexparser.h>
#include <credentials/sets/mem_cred.h>
#include <daemon.h>

#include <tls_socket.h>

#include <libxml/parser.h>

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SOAP_NS			"http://www.w3.org/2003/05/soap-envelope"
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
 * Send HTTP POST request and receive HTTP response
 */
static bool http_send_receive(private_tnc_ifmap2_soap_t *this, chunk_t out,
															   chunk_t *in)
{
	char header[] =
		 "POST /ifmap HTTP/1.1\r\n"
		 "Content-Type: application/soap+xml;charset=utf-8\r\n"
		 "Content-Length: ";
	char *request, response[2048];
	chunk_t line, http, parameter;
	int len, code, content_len = 0;

	/* Write HTTP POST request */
	len = asprintf(&request, "%s%d\r\n\r\n%.*s", header, out.len,
				   out.len, out.ptr);
	if (len == -1)
	{
		return FALSE;
	}
	this->tls->write(this->tls, request, len);
	free(request);

	/* Read HTTP response */
	len = this->tls->read(this->tls, response, sizeof(response), TRUE);
	if (len == -1)
	{
		return FALSE;
	}
	*in = chunk_create(response, len);

	/* Process HTTP protocol version */
	if (!fetchline(in, &line) || !extract_token(&http, ' ', &line) ||
		!match("HTTP/1.1", &http) || sscanf(line.ptr, "%d", &code) != 1)
	{
		DBG1(DBG_TNC, "malformed http response header");
		return FALSE;
	}
	if (code != 200)
	{
		DBG1(DBG_TNC, "http response returns error code %d", code);
		return FALSE;
	}	

	/* Process HTTP header line by line until the HTTP body is reached */
	while (fetchline(in, &line))
	{
		if (line.len == 0)
		{
			break;
		}

		if (extract_token(&parameter, ':', &line) &&
			match("Content-Length", &parameter) &&
			sscanf(line.ptr, "%d", &len) == 1)
	 	{
			content_len = len;
		}
	}

	/* Found Content-Length parameter and check size of HTTP body */
	if (content_len)
	{
		if (content_len > in->len)
		{
			DBG1(DBG_TNC, "http body is smaller than content length");
			return FALSE;
		}
		in->len = content_len;
	}
	*in = chunk_clone(*in);

	return TRUE;
}

/**
 * Find a child node with a given name
 */
static xmlNodePtr find_child(xmlNodePtr parent, const xmlChar* name)
{
	xmlNodePtr child;
	
	child = parent->xmlChildrenNode;
	while (child)
	{
		if (xmlStrcmp(child->name, name) == 0)
		{
			return child;
		}
		child = child->next;
	}

	DBG1(DBG_TNC, "child node \"%s\" not found", name);
	return NULL;
}

/**
 * Send request and receive result via SOAP
 */
static bool soap_send_receive(private_tnc_ifmap2_soap_t *this,
							  char *request_name, xmlNodePtr request,
							  char *result_name, xmlNodePtr *result,
							  xmlDocPtr *result_doc)
{
	xmlDocPtr doc;
	xmlNodePtr env, body, cur;
	xmlNsPtr ns;
	xmlChar *xml;
	int len;
	chunk_t in, out;

	*result_doc = NULL;
	DBG2(DBG_TNC, "sending ifmap %s", request_name);

	/* Generate XML Document containing SOAP Envelope */
	doc = xmlNewDoc("1.0");
	env =xmlNewNode(NULL, "Envelope");
	ns = xmlNewNs(env, SOAP_NS, "env");
	xmlSetNs(env, ns);
	xmlDocSetRootElement(doc, env);

	/* Add SOAP Body containing IF-MAP request */
	body = xmlNewNode(ns, "Body");
	xmlAddChild(body, request);
	xmlAddChild(env, body);

	/* Convert XML Document into a character string */
	xmlDocDumpFormatMemory(doc, &xml, &len, 1);
	xmlFreeDoc(doc);
	DBG3(DBG_TNC, "%.*s", len, xml);
	out = chunk_create(xml, len);

	/* Send SOAP-XML request via HTTP */
	if (!http_send_receive(this, out, &in))
	{
		xmlFree(xml);
		return FALSE;
	}
	xmlFree(xml);

	DBG3(DBG_TNC, "%B", &in);
	doc = xmlParseMemory(in.ptr, in.len);
	free(in.ptr);
	
	if (!doc)
	{
		DBG1(DBG_TNC, "failed to parse XML message");
		return FALSE;
	}
	*result_doc = doc;

	/* check out XML document */
	cur = xmlDocGetRootElement(doc);
	if (!cur)
	{
		DBG1(DBG_TNC, "empty XML message");
		return FALSE;
	}

	/* get XML Document type is a SOAP Envelope */
	if (xmlStrcmp(cur->name, "Envelope"))
	{
		DBG1(DBG_TNC, "XML message does not contain a SOAP Envelope");
		return FALSE;
	}

	/* get SOAP Body */
	cur = find_child(cur, "Body");
	if (!cur)
	{
		return FALSE;
	}

	/* get IF-MAP response */
	cur = find_child(cur, "response");
	if (!cur)
	{
		return FALSE;
	}

	/* get IF-MAP result */
	cur = find_child(cur, result_name);
	if (!cur)
	{
		return FALSE;
	}

	if (result)
	{
		*result = cur;
	}
	return TRUE;
}

METHOD(tnc_ifmap2_soap_t, newSession, bool,
	private_tnc_ifmap2_soap_t *this)
{
	xmlNodePtr request, result;
	xmlDocPtr result_doc;
	xmlNsPtr ns;

	/*build newSession request */
	request = xmlNewNode(NULL, "newSession");
	ns = xmlNewNs(request, IFMAP_NS, "ifmap");
	xmlSetNs(request, ns);

	if (!soap_send_receive(this, "newSession", request, "newSessionResult",
						   &result, &result_doc))
	{
		if (result_doc)
		{
			xmlFreeDoc(result_doc);
		}
		return FALSE;
	}

	/* get session-id and ifmap-publisher-id properties */
	this->session_id = xmlGetProp(result, "session-id");
	this->ifmap_publisher_id = xmlGetProp(result, "ifmap-publisher-id");
	xmlFreeDoc(result_doc);

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
	xmlNodePtr request;
	xmlDocPtr result_doc;
	xmlNsPtr ns;
	bool success;

	/* build purgePublisher request */
	request = xmlNewNode(NULL, "purgePublisher");
	ns = xmlNewNs(request, IFMAP_NS, "ifmap");
	xmlSetNs(request, ns);
	xmlNewProp(request, "session-id", this->session_id);
	xmlNewProp(request, "ifmap-publisher-id", this->ifmap_publisher_id);

	success = soap_send_receive(this, "purgePublisher", request,
								"purgePublisherReceived", NULL, &result_doc);
	if (result_doc)
	{
		xmlFreeDoc(result_doc);
	}
	return success;
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

