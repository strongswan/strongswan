package org.strongswan.android;

import android.content.Intent;
import android.net.VpnService;

public class CharonVpnService extends VpnService
{

	@Override
	public int onStartCommand(Intent intent, int flags, int startId)
	{
		// called whenever the service is started with startService
		// create our own thread because we are running in the calling processes
		// main thread
		return super.onStartCommand(intent, flags, startId);
	}

	@Override
	public void onCreate()
	{
		// onCreate is only called once
		initializeCharon();
		super.onCreate();
	}

	@Override
	public void onDestroy()
	{
		// called once the service is to be destroyed
		deinitializeCharon();
		super.onDestroy();
	}

	/**
	 * Initialization of charon, provided by libandroidbridge.so
	 */
	public native void initializeCharon();

	/**
	 * Deinitialize charon, provided by libandroidbridge.so
	 */
	public native void deinitializeCharon();

	/*
	 * The libraries are extracted to /data/data/org.strongswan.android/...
	 * during installation.
	 */
	static
	{
		System.loadLibrary("crypto");
		System.loadLibrary("strongswan");
		System.loadLibrary("hydra");
		System.loadLibrary("charon");
		System.loadLibrary("ipsec");
		System.loadLibrary("androidbridge");
	}
}
