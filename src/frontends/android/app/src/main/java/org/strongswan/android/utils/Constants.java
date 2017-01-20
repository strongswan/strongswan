/*
 * Copyright (C) 2016 Tobias Brunner
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

package org.strongswan.android.utils;

public final class Constants
{
	/**
	 * Intent action used to notify about changes to the VPN profiles
	 */
	public static final String VPN_PROFILES_CHANGED = "org.strongswan.android.VPN_PROFILES_CHANGED";

	/**
	 * Used in the intent above to notify about edits or inserts of a VPN profile (long)
	 */
	public static final String VPN_PROFILES_SINGLE = "org.strongswan.android.VPN_PROFILES_SINGLE";

	/**
	 * Used in the intent above to notify about the deletion of multiple VPN profiles (array of longs)
	 */
	public static final String VPN_PROFILES_MULTIPLE = "org.strongswan.android.VPN_PROFILES_MULTIPLE";

	/**
	 * Limits for MTU
	 */
	public static final int MTU_MAX = 1500;
	public static final int MTU_MIN = 1280;
}
