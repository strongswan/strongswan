/*
 * Copyright (C) 2012-2015 Tobias Brunner
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

import android.annotation.TargetApi;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Build;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class NetworkManager extends BroadcastReceiver
{
	private final Context mContext;
	private boolean mRegistered;
	private NetworkCallback mCallback;

	public NetworkManager(Context context)
	{
		mContext = context;
	}

	public void Register()
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
		{
			this.mCallback = new ConnectivityManager.NetworkCallback() {
				@Override
				public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties)
				{
					/* triggering the networkChanged callback again is needed
					 * in some scenarios where the broadcast comes before IPv4
					 * connectivity is fully established.  disadvantage is that
					 * it might be triggered a bit often and even when not
					 * required */
					/* this seems only to get triggered when connected */
					networkChanged(false);
				}
			};
			ConnectivityManager cm = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
			cm.registerNetworkCallback(new NetworkRequest.Builder().build(), this.mCallback);
		}
		mContext.registerReceiver(this, new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION));
	}

	public void Unregister()
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
		{
			ConnectivityManager cm = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
			cm.unregisterNetworkCallback(this.mCallback);
		}
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
