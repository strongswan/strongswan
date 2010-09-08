/*
 * Copyright (C) 2010 Andreas Steffen
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

/**
 * @defgroup tnc_if_tnccs tnc_if_tnccs
 * @{ @ingroup tnc_if_tnccs
 */

#ifndef TNC_IF_TNCCS_H_
#define TNC_IF_TNCCS_H_

#include <library.h>

#include <tls.h>

/**
 * Create an instance of the TNC IF-TNCCS 1.1 protocol handler.
 *
 * @param is_server			TRUE to act as server, FALSE for client
 * @param purpose			purpose this TLS stack instance is used for
 * @return					TNC_IF_TNCCS stack
 */
tls_t *tnc_if_tnccs_create(bool is_server, tls_purpose_t purpose);

#endif /** TNC_IF_TNCCS_H_ @}*/
