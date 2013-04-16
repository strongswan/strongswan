/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

package org.strongswan.android.logic;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

public class NetworkManager extends BroadcastReceiver
{
	private final Context mContext;
	private boolean mRegistered;

	public NetworkManager(Context context)
	{
		mContext = context;
	}

	public void Register()
	{
		mContext.registerReceiver(this, new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION));
	}

	public void Unregister()
	{
		mContext.unregisterReceiver(this);
	}

	@Override
	public void onReceive(Context context, Intent intent)
	{
		ConnectivityManager cm = (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
		NetworkInfo info = cm.getActiveNetworkInfo();
		networkChanged(info == null || !info.isConnected());
	}

	/**
	 * Notify the native parts about a network change
	 *
	 * @param disconnected true if no connection is available at the moment
	 */
	public native void networkChanged(boolean disconnected);
}
