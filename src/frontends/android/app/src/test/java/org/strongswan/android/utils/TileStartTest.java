/*
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

package org.strongswan.android.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class TileStartTest
{
	@Test
	public void testDirectOnlyWithoutPrompts()
	{
		assertThat(TileStart.direct(true, false, false, false, false)).isTrue();
	}

	@Test
	public void testEachPromptNeedsTheActivity()
	{
		assertThat(TileStart.direct(false, false, false, false, false)).as("VPN permission").isFalse();
		assertThat(TileStart.direct(true, true, false, false, false)).as("certificate").isFalse();
		assertThat(TileStart.direct(true, false, true, false, false)).as("password").isFalse();
		assertThat(TileStart.direct(true, false, false, true, false)).as("battery optimization").isFalse();
		assertThat(TileStart.direct(true, false, false, false, true)).as("notification permission").isFalse();
	}
}
