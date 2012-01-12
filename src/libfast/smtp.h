/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

/**
 * @defgroup smtp smtp
 * @{ @ingroup libfast
 */

#ifndef SMTP_H_
#define SMTP_H_

typedef struct smtp_t smtp_t;

#include <library.h>

/**
 * Ultra-minimalistic SMTP client. Works at most with Exim on localhost.
 */
struct smtp_t {

	/**
	 * Send an e-mail message.
	 *
	 * @param from		sender address
	 * @param to		recipient address
	 * @param subject	mail subject
	 * @param fmt		mail body format string
	 * @param ...		arguments for body format string
	 */
	bool (*send_mail)(smtp_t *this, char *from, char *to,
					  char *subject, char *fmt, ...);

	/**
	 * Destroy a smtp_t.
	 */
	void (*destroy)(smtp_t *this);
};

/**
 * Create a smtp instance.
 */
smtp_t *smtp_create();

#endif /** SMTP_H_ @}*/
