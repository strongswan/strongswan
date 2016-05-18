/*
 * Copyright (C) 2016 Tobias Brunner
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

/**
 * Special assertions against IKE_SAs and CHILD_SAs (e.g. regarding their
 * state).
 *
 * @defgroup sa_asserts sa_asserts
 * @{ @ingroup test_utils_c
 */

#ifndef SA_ASSERTS_H_
#define SA_ASSERTS_H_

/**
 * Check that there exists a specific number of CHILD_SAs.
 */
#define assert_child_sa_count(ike_sa, count) \
({ \
	typeof(ike_sa) _sa = ike_sa; \
	typeof(count) _count = count; \
	test_assert_msg(_count == _sa->get_child_count(_sa), "unexpected number " \
					"of CHILD_SAs in IKE_SA %s (%d != %d)", #ike_sa, _count, \
					_sa->get_child_count(_sa)); \
})

/**
 * Check if the CHILD_SA with the given SPI is in the expected state.
 */
#define assert_child_sa_state(ike_sa, spi, state) \
({ \
	typeof(ike_sa) _sa = ike_sa; \
	typeof(spi) _spi = spi; \
	typeof(state) _state = state; \
	child_sa_t *_child = _sa->get_child_sa(_sa, PROTO_ESP, _spi, TRUE) ?: \
						 _sa->get_child_sa(_sa, PROTO_ESP, _spi, FALSE); \
	test_assert_msg(_child, "CHILD_SA with SPI %.8x does not exist", \
					ntohl(_spi)); \
	test_assert_msg(_state == _child->get_state(_child), "%N != %N", \
					child_sa_state_names, _state, \
					child_sa_state_names, _child->get_state(_child)); \
})

/**
 * Assert that the CHILD_SA with the given inbound SPI does not exist.
 */
#define assert_child_sa_not_exists(ike_sa, spi) \
({ \
	typeof(ike_sa) _sa = ike_sa; \
	typeof(spi) _spi = spi; \
	child_sa_t *_child = _sa->get_child_sa(_sa, PROTO_ESP, _spi, TRUE) ?: \
						 _sa->get_child_sa(_sa, PROTO_ESP, _spi, FALSE); \
	test_assert_msg(!_child, "CHILD_SA with SPI %.8x exists", ntohl(_spi)); \
})

#endif /** SA_ASSERTS_H_ @}*/
