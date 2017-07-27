/* vim: set ts=4 sw=4 noexpandtab: */
/*
 * Copyright (C) 2015 Pavel Balaev.
 * Copyright (C) 2015 InfoTeCS JSC.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <curl/curl.h>

#include <daemon.h>
#include "dead_peer_notify_mail.h"

#define CONNECT_TIMEOUT 10

typedef struct private_dead_peer_notify_mail_t private_dead_peer_notify_mail_t;

/**
 * Private data of an dead_peer_notify_mail_t object.
 */
struct private_dead_peer_notify_mail_t {

	/**
	 * Public dead_peer_notify_mail_t interface.
	 */
	dead_peer_notify_mail_t public;

	/**
	 * CURL handle
	 */
	CURL* curl;

	/**
	 * Enable/disable email reports flag
	 */
	bool email_enabled;

	/**
	 * Sender email address
	 */
	char *mail_from;

	/**
	 * Recipient email address
	 */
	char *mail_to;

	/**
	 * MTA url
	 */
	char *smtp_url;

	/**
	 * MTA CA certificate path
	 */
	char *cacert_path;

	/**
	 * Sender email user name
	 */
	char *mail_user;

	/**
	 * Sender email user password
	 */
	char *mail_passwd;
};

/**
 * Data to pass to curl callback
 */
typedef struct {
	char *payload;
	int len;
	bool done;
} cb_data_t;

/**
 * Curl callback function
 */
static size_t curl_cb(void *ptr, size_t size, size_t nmemb, cb_data_t *data)
{
	cb_data_t *mail = (cb_data_t *) data;

	if (mail->len > size * nmemb || mail->len == 0)
	{
		return 0;
	}

	if (!mail->done)
	{
		memcpy(ptr, mail->payload, mail->len);
		mail->done = true;
		return mail->len;
	}

	return 0;
}

METHOD(dead_peer_notify_mail_t, send_mail, void,
	private_dead_peer_notify_mail_t *this, const char *peer, const char *host)
{
	CURLcode res = CURLE_OK;
	char error[CURL_ERROR_SIZE];
	struct curl_slist *recipients = NULL;
	char mail_payload[BUFSIZ];
	cb_data_t data;
	time_t time_raw;

	if (!this->email_enabled)
	{
		return;
	}

	if (this->curl)
	{
		time(&time_raw);
		memset(mail_payload, 0, sizeof(mail_payload));
		data.len = snprintf(mail_payload, sizeof(mail_payload),
				 "%s<%s>\r\n%s<%s>\r\n%s\r\n\r\n%s (%s)%s%s\r\n\r\n%s\r\n",
				 "To: ", this->mail_to, "From: ", this->mail_from,
				 MAIL_SUBJ, peer, host, MAIL_BODY, ctime(&time_raw), MAIL_SIGN);

		if (data.len < 0)
		{
			data.len = 0;
			data.payload = 0;
		}
		else
		{
			data.payload = mail_payload;
		}
		data.done = false;

		curl_easy_setopt(this->curl, CURLOPT_ERRORBUFFER, error);
		curl_easy_setopt(this->curl, CURLOPT_FAILONERROR, FALSE);
		curl_easy_setopt(this->curl, CURLOPT_USERNAME, this->mail_user);
		curl_easy_setopt(this->curl, CURLOPT_PASSWORD, this->mail_passwd);
		curl_easy_setopt(this->curl, CURLOPT_URL, this->smtp_url);
		curl_easy_setopt(this->curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
		curl_easy_setopt(this->curl, CURLOPT_CAINFO, this->cacert_path);
		curl_easy_setopt(this->curl, CURLOPT_MAIL_FROM, this->mail_from);
		recipients = curl_slist_append(recipients, this->mail_to);
		curl_easy_setopt(this->curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(this->curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
		curl_easy_setopt(this->curl, CURLOPT_READFUNCTION, (void *) curl_cb);
		curl_easy_setopt(this->curl, CURLOPT_READDATA, &data);
		curl_easy_setopt(this->curl, CURLOPT_UPLOAD, 1L);

		DBG2(DBG_LIB, "trying to send email via '%s'...", this->smtp_url);
		res = curl_easy_perform(this->curl);

		if (res != CURLE_OK)
		{
			DBG1(DBG_LIB, "libcurl email send failed [%d]: %s", res, error);
		}

		curl_slist_free_all(recipients);
	}
}

METHOD(dead_peer_notify_mail_t, destroy, void,
	private_dead_peer_notify_mail_t *this)
{
	curl_easy_cleanup(this->curl);
	free(this);
}

/**
 * See header
 */
dead_peer_notify_mail_t *dead_peer_notify_mail_create()
{
	private_dead_peer_notify_mail_t *this;
	bool email_ok = true;
	struct stat cert_info;

	INIT(this,
		.public = {
			.send_mail = _send_mail,
			.destroy = _destroy,
		},
		.curl = curl_easy_init(),
	);

	this->email_enabled = lib->settings->get_bool(lib->settings,
								"%s.plugins.dead-peer-notify.send_email", FALSE,
								lib->ns);
	if (this->email_enabled)
	{
		this->mail_from = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.mail_from", NULL,
								lib->ns);
		this->mail_to = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.mail_to", NULL,
								lib->ns);
		this->smtp_url = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.smtp_url", NULL,
								lib->ns);
		this->cacert_path = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.smtp_cacert", NULL,
								lib->ns);
		this->mail_user = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.mail_username", NULL,
								lib->ns);
		this->mail_passwd = lib->settings->get_str(lib->settings,
								"%s.plugins.dead-peer-notify.mail_password", NULL,
								lib->ns);
		if (!this->mail_from)
		{
			DBG1(DBG_CFG, "no sender email address set");
			email_ok = false;
		}
		if (!this->mail_to)
		{
			DBG1(DBG_CFG, "no recipient email address set");
			email_ok = false;
		}
		if (!this->smtp_url)
		{
			DBG1(DBG_CFG, "no MTA url address set");
			email_ok = false;
		}
		else
		{
			if (!strstr(this->smtp_url, "smtp://"))
			{
				DBG1(DBG_CFG, "invalid MTA url address format");
				email_ok = false;
			}
		}
		if (!this->cacert_path)
		{
			DBG1(DBG_CFG, "no MTA CA certificate path set");
			email_ok = false;
		}
		else
		{
			if (stat(this->cacert_path, &cert_info) == -1)
			{
				DBG1(DBG_CFG, "error read MTA CA certificate: %s", strerror(errno));
				email_ok = false;
			}
		}
		if (!this->mail_user)
		{
			DBG1(DBG_CFG, "no sender email username set");
			email_ok = false;
		}
		if (!this->mail_passwd)
		{
			DBG1(DBG_CFG, "no sender email password set");
			email_ok = false;
		}

		if (!email_ok)
		{
			this->email_enabled = false;
			DBG1(DBG_CFG, "email reports disabled");
		}
	}

	return &this->public;
}
