/*
 * Copyright (C) 2012-2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
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
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

import androidx.annotation.NonNull;

public class NetworkManager extends BroadcastReceiver implements Runnable
{
	private final Context mContext;
	private volatile boolean mRegistered;
	private ConnectivityManager.NetworkCallback mCallback;
	private Thread mEventNotifier;
	private LinkedList<Boolean> mEvents = new LinkedList<>();
	private HashMap<Network, NetworkState> mNetworks = new HashMap<>();

	public NetworkManager(Context context)
	{
		mContext = context;

		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
		{
			mCallback = new ConnectivityManager.NetworkCallback()
			{
				@Override
				public void onAvailable(Network network)
				{
					synchronized (NetworkManager.this)
					{
						/* we expect this to be called if connected to at least one network during
						 * callback registration */
						mNetworks.put(network, new NetworkState());
						notifyNetworkChanged();
					}
				}

				@Override
				public void onLost(Network network)
				{
					synchronized (NetworkManager.this)
					{
						/* in particular mobile connections are disconnected overlapping with WiFi */
						mNetworks.remove(network);
						notifyNetworkChanged();
					}
				}

				@Override
				public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities networkCapabilities)
				{
					synchronized (NetworkManager.this)
					{
						NetworkState state = mNetworks.get(network);
						if (state != null)
						{
							int capabilities = 0;
							/* only look at the capabilities relevant for us */
							if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
							{
								capabilities |= (1 << 1);
							}
							if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
								networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED))
							{
								capabilities |= (1 << 2);
							}
							if (state.capabilities != capabilities)
							{
								state.capabilities = capabilities;
								notifyNetworkChanged();
							}
						}
					}
				}

				@Override
				public void onLinkPropertiesChanged(@NonNull Network network, @NonNull LinkProperties linkProperties)
				{
					synchronized (NetworkManager.this)
					{
						NetworkState state = mNetworks.get(network);
						if (state != null)
						{
							/* check addresses in case e.g. a new DHCP lease is assigned or
							 * IPv4 arrives after IPv6 */
							HashSet<InetAddress> addresses = new HashSet<>();
							for (LinkAddress address : linkProperties.getLinkAddresses())
							{
								addresses.add(address.getAddress());
							}
							if (!state.addresses.equals(addresses))
							{
								state.addresses = addresses;
								notifyNetworkChanged();
							}
						}
					}
				}

				@Override
				public void onBlockedStatusChanged(@NonNull Network network, boolean blocked)
				{
					synchronized (NetworkManager.this)
					{
						NetworkState state = mNetworks.get(network);
						if (state != null && state.blocked != blocked)
						{
							state.blocked = blocked;
							notifyNetworkChanged();
						}
					}
				}
			};
		}
	}

	public void Register()
	{
		mEvents.clear();
		mNetworks.clear();
		mRegistered = true;
		mEventNotifier = new Thread(this);
		mEventNotifier.start();
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
		{
			ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
			/* while we only get events for the VPN network via registerDefaultNetworkCallback,
			 * the default capabilities in the builder include NetworkCapabilities.NET_CAPABILITY_NOT_VPN */
			NetworkRequest.Builder builder = new NetworkRequest.Builder();
			cm.registerNetworkCallback(builder.build(), mCallback);
		}
		else
		{
			registerLegacyReceiver();
		}
	}

	@SuppressWarnings("deprecation")
	private void registerLegacyReceiver()
	{
		/* deprecated since API level 28 */
		mContext.registerReceiver(this, new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION));
	}

	public void Unregister()
	{
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
		{
			ConnectivityManager cm = mContext.getSystemService(ConnectivityManager.class);
			cm.unregisterNetworkCallback(mCallback);
		}
		else
		{
			mContext.unregisterReceiver(this);
		}
		mRegistered = false;
		synchronized (this)
		{
			notifyAll();
		}
		try
		{
			mEventNotifier.join();
			mEventNotifier = null;
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
	}

	@SuppressWarnings("deprecation")
	public boolean isConnected()
	{
		/* deprecated since API level 29 */
		ConnectivityManager cm = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
		android.net.NetworkInfo info = null;
		if (cm != null)
		{
			info = cm.getActiveNetworkInfo();
		}
		return info != null && info.isConnected();
	}

	@Override
	public void onReceive(Context context, Intent intent)
	{
		synchronized (this)
		{
			mEvents.addLast(isConnected());
			notifyAll();
		}
	}

	/**
	 * Queue a connectivity change event for the notifier thread.  Has to be
	 * called from a synchronized() section.
	 */
	private void notifyNetworkChanged()
	{
		mEvents.addLast(!mNetworks.isEmpty());
		NetworkManager.this.notifyAll();
	}

	@Override
	public void run()
	{
		while (mRegistered)
		{
			boolean connected;

			synchronized (this)
			{
				try
				{
					while (mRegistered && mEvents.isEmpty())
					{
						wait();
					}
				}
				catch (InterruptedException ex)
				{
					break;
				}
				if (!mRegistered)
				{
					break;
				}
				connected = mEvents.removeFirst();
			}
			/* call the native parts without holding the lock */
			networkChanged(!connected);
		}
	}

	/**
	 * Notify the native parts about a network change
	 *
	 * @param disconnected true if no connection is available at the moment
	 */
	public native void networkChanged(boolean disconnected);

	/**
	 * Simplified network state we track to see if anything changed
	 */
	private static class NetworkState
	{
		boolean blocked;
		int capabilities;
		HashSet<InetAddress> addresses = new HashSet<>();
	}
}
