/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "tnc_ifmap2_soap_msg.h"

#include <utils/debug.h>
#include <utils/lexparser.h>

#include <stdio.h>

#define SOAP_NS		"http://www.w3.org/2003/05/soap-envelope"

typedef struct private_tnc_ifmap2_soap_msg_t private_tnc_ifmap2_soap_msg_t;

/**
 * Private data of an tnc_ifmap2_soap_msg_t object.
 */
struct private_tnc_ifmap2_soap_msg_t {

	/**
	 * Public tnc_ifmap2_soap_msg_t interface.
	 */
	tnc_ifmap2_soap_msg_t public;

	/**
	 * TLS Socket
	 */
	tls_socket_t *tls;

	/**
	 * XML Document
	 */
	xmlDocPtr doc;

};

/**
 * Send HTTP POST request and receive HTTP response
 */
static bool http_post(private_tnc_ifmap2_soap_msg_t *this, chunk_t out,
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

METHOD(tnc_ifmap2_soap_msg_t, post, bool,
	private_tnc_ifmap2_soap_msg_t *this, char *request_name, xmlNodePtr request,
	char *result_name, xmlNodePtr *result)
{
	xmlDocPtr doc;
	xmlNodePtr env, body, cur, response;
	xmlNsPtr ns;
	xmlChar *xml, *errorCode, *errorString;
	int len;
	chunk_t in, out;

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

	/* Send SOAP-XML request via HTTP POST */
	if (!http_post(this, out, &in))
	{
		xmlFree(xml);
		return FALSE;
	}
	xmlFree(xml);

	DBG3(DBG_TNC, "%B", &in);
	this->doc = xmlParseMemory(in.ptr, in.len);
	free(in.ptr);
	
	if (!this->doc)
	{
		DBG1(DBG_TNC, "failed to parse XML message");
		return FALSE;
	}

	/* check out XML document */
	cur = xmlDocGetRootElement(this->doc);
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
	response = find_child(cur, "response");
	if (!response)
	{
		return FALSE;
	}

	/* get IF-MAP result */
	cur = find_child(response, result_name);
	if (!cur)
	{
		cur = find_child(response, "errorResult");
		if (cur)
		{
			DBG1(DBG_TNC, "received errorResult");

			errorCode = xmlGetProp(cur, "errorCode");
			if (errorCode)
			{
				DBG1(DBG_TNC, "  %s", errorCode);
				xmlFree(errorCode);
			}

			cur = find_child(cur, "errorString");
			if (cur)
			{
				errorString = xmlNodeGetContent(cur);
				if (errorString)
				{
					DBG1(DBG_TNC, "  %s", errorString);
					xmlFree(errorString);
				}
			}
		}
		return FALSE;
	}

	if (result)
	{
		*result = cur;
	}
	return TRUE;
}

METHOD(tnc_ifmap2_soap_msg_t, destroy, void,
	private_tnc_ifmap2_soap_msg_t *this)
{
	if (this->doc)
	{
		xmlFreeDoc(this->doc);
	}
	free(this);
}

/**
 * See header
 */
tnc_ifmap2_soap_msg_t *tnc_ifmap2_soap_msg_create(tls_socket_t *tls)
{
	private_tnc_ifmap2_soap_msg_t *this;

	INIT(this,
		.public = {
			.post = _post,
			.destroy = _destroy,
		},
		.tls = tls,
	);

	return &this->public;
}

