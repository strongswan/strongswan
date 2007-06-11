/**
 * @file xml_interface.c
 * 
 * @brief Implementation of xml_interface_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include <stdlib.h>

#include "xml_interface.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>

#include <library.h>
#include <daemon.h>
#include <processing/jobs/callback_job.h>

static struct sockaddr_un socket_addr = { AF_UNIX, "/var/run/charon.xml"};


typedef struct private_xml_interface_t private_xml_interface_t;

/**
 * Private data of an xml_interface_t object.
 */
struct private_xml_interface_t {

	/**
	 * Public part of xml_t object.
	 */
	xml_interface_t public;
	
	/**
	 * XML unix socket fd
	 */
	int socket;
	
	/**
	 * job accepting stroke messages
	 */
	callback_job_t *job;
};

/**
 * process a getRequest message
 */
static void process_get(xmlTextReaderPtr reader, xmlTextWriterPtr writer)
{
	if (/* <GetResponse> */
		xmlTextWriterStartElement(writer, "GetResponse") < 0 ||
		/*   <Status Code="200"><Message/></Status> */
		xmlTextWriterStartElement(writer, "Status") < 0 ||
		xmlTextWriterWriteAttribute(writer, "Code", "200") < 0  ||
		xmlTextWriterStartElement(writer, "Message") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		/*   <ConnectionList/> */
		xmlTextWriterStartElement(writer, "ConnectionList") < 0 ||
		xmlTextWriterEndElement(writer) < 0 ||
		/* </GetResponse> */
		xmlTextWriterEndElement(writer) < 0)
	{
		DBG1(DBG_CFG, "error writing XML document (GetResponse)");
	}
}

/**
 * read from a opened connection and process it
 */
static job_requeue_t process(int *fdp)
{
	int oldstate, fd = *fdp;
	char buffer[4096];
	size_t len;
	xmlTextReaderPtr reader;
	xmlTextWriterPtr writer;
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	len = read(fd, buffer, sizeof(buffer));
	pthread_setcancelstate(oldstate, NULL);
	if (len <= 0)
	{
		close(fd);
		DBG2(DBG_CFG, "SMP XML connection closed");
		return JOB_REQUEUE_NONE;
	}
	
	reader = xmlReaderForMemory(buffer, len, NULL, NULL, 0);
	if (reader == NULL)
	{
		DBG1(DBG_CFG, "opening SMP XML reader failed");
		return JOB_REQUEUE_FAIR;;
	}
	
	writer = xmlNewTextWriter(xmlOutputBufferCreateFd(fd, NULL));
	if (writer == NULL)
	{
		xmlFreeTextReader(reader);
		DBG1(DBG_CFG, "opening SMP XML writer failed");
		return JOB_REQUEUE_FAIR;;
	}
	
	/* create the standard message parts */
	if (xmlTextWriterStartDocument(writer, NULL, NULL, NULL) < 0 ||
		/* <SMPMessage xmlns="http://www.strongswan.org/smp/1.0"> */
		xmlTextWriterStartElement(writer, "SMPMessage") < 0 ||
		xmlTextWriterWriteAttribute(writer, "xmlns",
						"http://www.strongswan.org/smp/1.0") < 0 ||
		/* <Body> */
		xmlTextWriterStartElement(writer, "Body") < 0)
	{
		xmlFreeTextReader(reader);
		xmlFreeTextWriter(writer);
		DBG1(DBG_CFG, "creating SMP XML message failed");
		return JOB_REQUEUE_FAIR;;
	}
	
    while (TRUE)
    {
    	switch (xmlTextReaderRead(reader))
    	{
    		case 1:
    		{
				if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
				{
					if (streq(xmlTextReaderConstName(reader), "GetRequest"))
					{
						process_get(reader, writer);
						break;
					}
				}
				continue;
			}
			case 0:
			    /* end of XML */
			    break;
			default:
			    DBG1(DBG_CFG, "parsing SMP XML message failed");
			    break;
		}
        xmlFreeTextReader(reader);
        break;
    }
    /* write </Body></SMPMessage> and close document */
    if (xmlTextWriterEndDocument(writer) < 0)
    {
		DBG1(DBG_CFG, "completing SMP XML message failed");
    }
    xmlFreeTextWriter(writer);
    
    /* write a newline to indicate end of xml */
    write(fd, "\n", 1);
    return JOB_REQUEUE_FAIR;;
}

/**
 * accept from XML socket and create jobs to process connections
 */
static job_requeue_t dispatch(private_xml_interface_t *this)
{
	struct sockaddr_un strokeaddr;
	int oldstate, fd, *fdp, strokeaddrlen = sizeof(strokeaddr);
	callback_job_t *job;
	
	/* wait for connections, but allow thread to terminate */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	fd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	pthread_setcancelstate(oldstate, NULL);
	
	if (fd < 0)
	{
		DBG1(DBG_CFG, "accepting SMP XML socket failed: %s", strerror(errno));
		sleep(1);
		return JOB_REQUEUE_FAIR;;
	}
	
	fdp = malloc_thing(int);
	*fdp = fd;
	job = callback_job_create((callback_job_cb_t)process, fdp, free, this->job);
	charon->processor->queue_job(charon->processor, (job_t*)job);
	
	return JOB_REQUEUE_DIRECT;
}

/**
 * Implementation of itnerface_t.destroy.
 */
static void destroy(private_xml_interface_t *this)
{
	this->job->cancel(this->job);
	unlink(socket_addr.sun_path);
	free(this);
}

/*
 * Described in header file
 */
interface_t *interface_create()
{
	private_xml_interface_t *this = malloc_thing(private_xml_interface_t);
	mode_t old;

	this->public.interface.destroy = (void (*)(interface_t*))destroy;
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "could not create XML socket");
		free(this);
		return NULL;
	}
	
	old = umask(~S_IRWXU);
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		DBG1(DBG_CFG, "could not bind XML socket: %s", strerror(errno));
		close(this->socket);
		free(this);
		return NULL;
	}
	umask(old);
	
	if (listen(this->socket, 0) < 0)
	{
		DBG1(DBG_CFG, "could not listen on XML socket: %s", strerror(errno));
		close(this->socket);
		free(this);
		return NULL;
	}

	this->job = callback_job_create((callback_job_cb_t)dispatch, this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public.interface;
}

