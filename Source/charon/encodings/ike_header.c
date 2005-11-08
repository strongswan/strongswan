/**
 * @file ike_header.c
 * 
 * @brief Definition of the encoding rules used when parsing or generating
 * an IKEv2-Header
 *  
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

/* offsetof macro */
#include <stddef.h>

 #include "../encodings.h"
 #include "ike_header.h"

/**
 * Encoding rules to parse or generate a IKEv2-Header
 * 
 * The defined offsets are the positions in a struct of type 
 * ike_header_t.
 * 
 */
encoding_rule_t ike_header_encodings[] = {
 	/* 8 Byte SPI, stored in the field initiator_spi */
	{ U_INT_64,		offsetof(ike_header_t, initiator_spi)	},
 	/* 8 Byte SPI, stored in the field responder_spi */
	{ U_INT_64,		offsetof(ike_header_t, responder_spi) 	},
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,		offsetof(ike_header_t, next_payload) 	},
 	/* 4 Bit major version, stored in the field maj_version */
	{ U_INT_4,		offsetof(ike_header_t, maj_version) 		},
 	/* 4 Bit minor version, stored in the field min_version */
	{ U_INT_4,		offsetof(ike_header_t, min_version) 		},
 	/* 2 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 										}, 
	{ RESERVED_BIT,	0 										}, 
 	/* 3 Bit flags, stored in the fields response, version and initiator */
	{ FLAG,			offsetof(ike_header_t, flags.response) 	},	
	{ FLAG,			offsetof(ike_header_t, flags.version) 	},
	{ FLAG,			offsetof(ike_header_t, flags.initiator) 	},
 	/* 3 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 										},
	{ RESERVED_BIT,	0 										},
	{ RESERVED_BIT,	0 										},
 	/* 4 Byte message id, stored in the field message_id */
	{ U_INT_32,		offsetof(ike_header_t, message_id) 		},
 	/* 4 Byte length fied, stored in the field length */
	{ LENGTH,		offsetof(ike_header_t, length) 			}
};
