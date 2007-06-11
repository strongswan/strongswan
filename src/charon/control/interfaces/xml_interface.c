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
	 * thread receiving messages
	 */
	pthread_t thread;
};

static void get(private_xml_interface_t *this, 
				xmlTextReaderPtr reader, xmlTextWriterPtr writer)
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
		

/*
					   DBG1(DBG_CFG, "%d %d %s %d %d %s", 
						    xmlTextReaderDepth(reader),
						    ,
						    xmlTextReaderConstName(reader),
						    xmlTextReaderIsEmptyElement(reader),
						    xmlTextReaderHasValue(reader),
						    xmlTextReaderConstValue(reader));
		*/
}

static void receive(private_xml_interface_t *this)
{
	charon->drop_capabilities(charon, TRUE);
	
	/* disable cancellation by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	while (TRUE)
	{
		struct sockaddr_un strokeaddr;
		int strokeaddrlen = sizeof(strokeaddr);
		int oldstate;
		int fd;
		char buffer[4096];
		size_t len;
		
		/* wait for connections, but allow thread to terminate */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		fd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
		pthread_setcancelstate(oldstate, NULL);
		
		if (fd < 0)
		{
			DBG1(DBG_CFG, "accepting SMP XML socket failed: %s", strerror(errno));
			continue;
		}
		DBG2(DBG_CFG, "SMP XML connection opened");
		while (TRUE)
		{
			xmlTextReaderPtr reader;
			xmlTextWriterPtr writer;
			
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
			len = read(fd, buffer, sizeof(buffer));
			pthread_setcancelstate(oldstate, NULL);
			if (len <= 0)
			{
				close(fd);
				DBG2(DBG_CFG, "SMP XML connection closed");
				break;
			}
			
			reader = xmlReaderForMemory(buffer, len, NULL, NULL, 0);
			if (reader == NULL)
			{
				DBG1(DBG_CFG, "opening SMP XML reader failed");
				continue;
			}
			
			writer = xmlNewTextWriter(xmlOutputBufferCreateFd(fd, NULL));
			if (writer == NULL)
			{
				xmlFreeTextReader(reader);
				DBG1(DBG_CFG, "opening SMP XML writer failed");
				continue;
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
				continue;
			}
			
	        while (TRUE)
	        {
	        	switch (xmlTextReaderRead(reader))
	        	{
	        		case 1:
	        		{
						if (xmlTextReaderNodeType(reader) ==
							XML_READER_TYPE_ELEMENT)
						{
							if (streq(xmlTextReaderConstName(reader), "GetRequest"))
							{
								get(this, reader, writer);
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
		}
	}
}

/**
 * Implementation of itnerface_t.destroy.
 */
static void destroy(private_xml_interface_t *this)
{
	pthread_cancel(this->thread);
	pthread_join(this->thread, NULL);
	close(this->socket);
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
	
	if (pthread_create(&this->thread, NULL, (void*(*)(void*))receive, this) != 0)
	{
		DBG1(DBG_CFG, "could not create XML socket thread: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		free(this);
		return NULL;
	}
	
	return &this->public.interface;
}

