/**
 * @file identification_test.c
 * 
 * @brief Tests for the identification_t class.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include <string.h>

#include "identification_test.h"

#include <utils/identification.h>
#include <utils/logger.h>

/*
 * described in Header-File
 */
void test_identification(protected_tester_t *tester)
{
	identification_t *a, *b, *c, *d;
	bool result;
	
	{ /* test RFC822_ADDR */
		char *bob_string = "bob@wonderland.net";
		chunk_t bob_chunk = {bob_string, strlen(bob_string)};
		
		a = identification_create_from_string("alice@wonderland.net");
		b = identification_create_from_encoding(ID_RFC822_ADDR, bob_chunk);
		c = identification_create_from_string("*@wonderland.net");
		d = identification_create_from_string("*@badlands.com");
		
		result = a->belongs_to(a, c);
		tester->assert_true(tester, result, "alice belongs to wonderland");
		result = b->belongs_to(b, c);
		tester->assert_true(tester, result, "bob belongs to wonderland");
		result = a->belongs_to(a, d);
		tester->assert_false(tester, result, "alice does not belong to badlands");
		result = b->belongs_to(b, d);
		tester->assert_false(tester, result, "bob does not belong to badlands");
		result = c->belongs_to(c, d);
		tester->assert_false(tester, result, "wonderland is not in badlands");
		result = a->belongs_to(a, a);
		tester->assert_true(tester, result, "alice belongs to alice alice");
		result = a->equals(a, a);
		tester->assert_true(tester, result, "alice is alice");
		result = a->equals(a, b);
		tester->assert_false(tester, result, "alice is not bob");
		
		a->destroy(a);
		b->destroy(b);
		c->destroy(c);
		d->destroy(d);
	}
	
	{ /* test FQDN */
		char *bob_string = "@dave.nirvana.org";
		chunk_t bob_chunk = {bob_string, strlen(bob_string)};
		
		a = identification_create_from_string("@carol.nirvana.org");
		b = identification_create_from_encoding(ID_FQDN, bob_chunk);
		c = identification_create_from_string("@*.nirvana.org");
		d = identification_create_from_string("@*.samsara.com");
		
		result = a->belongs_to(a, c);
		tester->assert_true(tester, result, "carol belongs to nirvana");
		result = b->belongs_to(b, c);
		tester->assert_true(tester, result, "dave belongs to nirvana");
		result = a->belongs_to(a, d);
		tester->assert_false(tester, result, "carol does not belong to samsara");
		result = b->belongs_to(b, d);
		tester->assert_false(tester, result, "dave does not belong to samsara");
		result = c->belongs_to(c, d);
		tester->assert_false(tester, result, "nirvana is not in samsara");
		result = a->belongs_to(a, a);
		tester->assert_true(tester, result, "carol belongs to carol carol");
		result = a->equals(a, a);
		tester->assert_true(tester, result, "carol is carol");
		result = a->equals(a, b);
		tester->assert_false(tester, result, "carol is not dave");
		
		a->destroy(a);
		b->destroy(b);
		c->destroy(c);
		d->destroy(d);
	}
	
	
	{ /* test ID IPV4 ADDR, no wildcards yet */
		char bob_addr[] = {192,168,0,2};
		chunk_t bob_chunk = chunk_from_buf(bob_addr);
		
		a = identification_create_from_string("192.168.0.1");
		b = identification_create_from_encoding(ID_IPV4_ADDR, bob_chunk);
		c = identification_create_from_string("192.168.0.2"); /* as bob */
		
		result = a->equals(a, a);
		tester->assert_true(tester, result, "IPV4_ADDR of alice equals IPV4_ADDR of alice");
		result = b->equals(b, c);
		tester->assert_true(tester, result, "IPV4_ADDR of bob equals IPV4_ADDR of carol");
		result = a->equals(a, b);
		tester->assert_false(tester, result, "IPV4_ADDR of alice doesn't equal IPV4_ADDR of bob");
		
		a->destroy(a);
		b->destroy(b);
		c->destroy(c);
	}
	
	{ /* test ID IPV6 ADDR, no wildcards yet */
		char bob_addr[] = {0x20,0x01,0x0d,0xb8,0x85,0xa3,0x08,0xd3,0x13,0x19,0x8a,0x2e,0x03,0x70,0x73,0x44};
		chunk_t bob_chunk = chunk_from_buf(bob_addr);
		
		a = identification_create_from_string("2001:0db8:85a3:08d3:1319:8a2e:0370:7345");
		b = identification_create_from_encoding(ID_IPV6_ADDR, bob_chunk);
		c = identification_create_from_string("2001:0db8:85a3:08d3:1319:8a2e:0370:7344"); /* as bob */
		
		result = a->equals(a, a);
		tester->assert_true(tester, result, "IPV6_ADDR of alice equals IPV6_ADDR of alice");
		result = b->equals(b, c);
		tester->assert_true(tester, result, "IPV6_ADDR of bob equals IPV6_ADDR of carol");
		result = a->equals(a, b);
		tester->assert_false(tester, result, "IPV6_ADDR of alice doesn't equal IPV6_ADDR of bob");
		
		a->destroy(a);
		b->destroy(b);
		c->destroy(c);
	}
	
	{ /* test ID DER_ASN1_DN */
		a = identification_create_from_string("C=CH, O=Linux strongSwan, CN=alice");
		b = identification_create_from_string("O=Linux strongSwan, C=CH, CN=bob");
		c = identification_create_from_string("C=CH, O=Linux strongSwan, CN=*");
		d = identification_create_from_string("C=CH, O=Linux openswan, CN=*");
		
		result = a->equals(a, a);
		tester->assert_true(tester, result, "DN of alice equals DN of alice");
		result = a->equals(a, b);
		tester->assert_false(tester, result, "DN of alice doesn't equal DN of bob");
		result = a->belongs_to(a, c);
		tester->assert_true(tester, result, "DN of alice belongs to DN of carol");
		/* TODO: This does NOT work, wildcard check should work with unordered RDNs */
		result = b->belongs_to(b, c);
		tester->assert_true(tester, result, "DN of bob belongs to DN of carol");
		result = b->belongs_to(b, d);
		tester->assert_false(tester, result, "DN of bob doesn't belong to DN of dave");
		
		a->destroy(a);
		b->destroy(b);
		c->destroy(c);
		d->destroy(d);
	}
}
