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

/**
 * @defgroup tests tests
 * @{ @ingroup unit_tester
 */

DEFINE_TEST("linked_list_t->remove()", test_list_remove, FALSE)
DEFINE_TEST("hashtable_t->remove_at()", test_hashtable_remove_at, FALSE)
DEFINE_TEST("simple enumerator", test_enumerate, FALSE)
DEFINE_TEST("nested enumerator", test_enumerate_nested, FALSE)
DEFINE_TEST("filtered enumerator", test_enumerate_filtered, FALSE)
DEFINE_TEST("token enumerator", test_enumerate_token, FALSE)
DEFINE_TEST("auth cfg", test_auth_cfg, FALSE)
DEFINE_TEST("CURL get", test_curl_get, FALSE)
DEFINE_TEST("MySQL operations", test_mysql, FALSE)
DEFINE_TEST("SQLite operations", test_sqlite, FALSE)
DEFINE_TEST("mutex primitive", test_mutex, FALSE)
DEFINE_TEST("RSA key generation", test_rsa_gen, FALSE)
DEFINE_TEST("RSA subjectPublicKeyInfo loading", test_rsa_load_any, FALSE)
DEFINE_TEST("X509 certificate", test_cert_x509, FALSE)
DEFINE_TEST("Mediation database key fetch", test_med_db, FALSE)
DEFINE_TEST("Base64 converter", test_chunk_base64, FALSE)
DEFINE_TEST("IP pool", test_pool, FALSE)
DEFINE_TEST("SSH agent", test_agent, FALSE)
DEFINE_TEST("ID parts", test_id_parts, FALSE)
DEFINE_TEST("ID wildcards", test_id_wildcards, FALSE)
DEFINE_TEST("ID equals", test_id_equals, FALSE)
DEFINE_TEST("ID matches", test_id_matches, FALSE)

/** @}*/
