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

/**
 * Whether the quick settings tile may connect by itself, without starting
 * VpnProfileControlActivity (which, on Android 14+, can only be started with
 * startActivityAndCollapse() and so closes the drawer).  Only if none of the
 * activity's prompts would be shown.
 */
public final class TileStart
{
	/** how long to wait for the connection to start before falling back to the activity */
	public static final long FALLBACK_MS = 3000;

	private TileStart()
	{
	}

	/**
	 * @param vpnPrepared        VpnService.prepare() returned null (permission granted)
	 * @param certificateMissing the profile needs a user certificate that isn't selected
	 * @param passwordMissing    the profile needs a password that isn't stored
	 * @param powerPrompt        the battery optimization dialog would be shown
	 * @param notificationPrompt the notification permission would be requested
	 * @return true if the tile may connect without the activity
	 */
	public static boolean direct(boolean vpnPrepared, boolean certificateMissing, boolean passwordMissing,
								 boolean powerPrompt, boolean notificationPrompt)
	{
		return vpnPrepared && !certificateMissing && !passwordMissing && !powerPrompt && !notificationPrompt;
	}
}
