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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;

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

	/**
	 * Function that retrieves a local address of the given family.
	 *
	 * @param ipv4 true to return an IPv4 address, false for IPv6
	 * @return string representation of an IPv4 address, or null if none found
	 */
	public String getLocalAddress(boolean ipv4)
	{
		try
		{
			Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
			if (en == null)
			{	/* no interfaces at all */
				return null;
			}
			while (en.hasMoreElements())
			{
				NetworkInterface intf = en.nextElement();
				if (intf.isLoopback() || !intf.isUp() ||
					intf.getName().startsWith("tun"))
				{
					continue;
				}
				Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses();
				while (enumIpAddr.hasMoreElements())
				{
					InetAddress inetAddress = enumIpAddr.nextElement();
					if (inetAddress.isLoopbackAddress())
					{
						continue;
					}
					if ((ipv4 && inetAddress instanceof Inet4Address) ||
						(!ipv4 && inetAddress instanceof Inet6Address))
					{
						return inetAddress.getHostAddress();
					}
				}
			}
		}
		catch (SocketException ex)
		{
			ex.printStackTrace();
			return null;
		}
		return null;
	}

	/**
	 * Search for an interface that has the given address installed.
	 *
	 * @param addr network-order byte encoding of the address to look for
	 * @return name of the interface, or null if not found
	 */
	public String getInterface(byte[] addr)
	{
		try
		{
			InetAddress inetAddress = InetAddress.getByAddress(addr);
			NetworkInterface intf = NetworkInterface.getByInetAddress(inetAddress);
			if (intf != null)
			{
				return intf.getName();
			}
		}
		catch (UnknownHostException e)
		{
			e.printStackTrace();
		}
		catch (SocketException e)
		{
			e.printStackTrace();
		}
		return null;
	}
}
