/*
 * Copyright (C) 2014 Tobias Brunner
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

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.Looper;

import org.strongswan.android.data.DatabaseHelper;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.data.ManagedVpnProfile;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.security.LocalCertificateKeyStoreProvider;
import org.strongswan.android.utils.Constants;

import java.security.Security;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import androidx.core.os.HandlerCompat;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.ProcessLifecycleOwner;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class StrongSwanApplication extends Application implements LifecycleEventObserver
{
	private static Context mContext;

	private final ExecutorService mExecutorService = Executors.newFixedThreadPool(4);
	private final Handler mMainHandler = HandlerCompat.createAsync(Looper.getMainLooper());

	private ManagedConfigurationService mManagedConfigurationService;

	private DatabaseHelper mDatabaseHelper;

	private final BroadcastReceiver mRestrictionsReceiver = new BroadcastReceiver()
	{
		@Override
		public void onReceive(Context context, Intent intent)
		{
			final List<ManagedVpnProfile> oldProfiles = mManagedConfigurationService.getManagedProfiles();
			Set<String> uuids = new HashSet<>(oldProfiles.size());
			for (final VpnProfile profile : oldProfiles)
			{
				uuids.add(profile.getUUID().toString());
			}

			mManagedConfigurationService.loadConfiguration();
			mManagedConfigurationService.updateSettings();

			final List<ManagedVpnProfile> newProfiles = mManagedConfigurationService.getManagedProfiles();
			for (final VpnProfile profile : newProfiles)
			{
				uuids.add(profile.getUUID().toString());
			}

			Intent profilesChanged = new Intent(Constants.VPN_PROFILES_CHANGED);
			profilesChanged.putExtra(Constants.VPN_PROFILES_MULTIPLE, uuids.toArray(new String[0]));
			LocalBroadcastManager.getInstance(context).sendBroadcast(profilesChanged);
		}
	};

	static
	{
		Security.addProvider(new LocalCertificateKeyStoreProvider());
	}

	@Override
	public void onCreate()
	{
		super.onCreate();
		StrongSwanApplication.mContext = getApplicationContext();

		mManagedConfigurationService = new ManagedConfigurationService(mContext);
		ProcessLifecycleOwner.get().getLifecycle().addObserver(this);

		mDatabaseHelper = new DatabaseHelper(mContext);
	}

	/**
	 * Returns the current application context
	 *
	 * @return context
	 */
	public static Context getContext()
	{
		return StrongSwanApplication.mContext;
	}

	/**
	 * Returns a thread pool to run tasks in separate threads
	 *
	 * @return thread pool
	 */
	public Executor getExecutor()
	{
		return mExecutorService;
	}

	/**
	 * Returns a handler to execute stuff by the main thread.
	 *
	 * @return handler
	 */
	public Handler getHandler()
	{
		return mMainHandler;
	}

	/**
	 * @return the application's database helper used to access its SQLite database
	 */
	public DatabaseHelper getDatabaseHelper()
	{
		return mDatabaseHelper;
	}

	/*
	 * The libraries are extracted to /data/data/org.strongswan.android/...
	 * during installation.  On newer releases most are loaded in JNI_OnLoad.
	 */
	static
	{
		System.loadLibrary("androidbridge");
	}

	@Override
	public void onStateChanged(final LifecycleOwner source, final Lifecycle.Event event)
	{
		if (event == Lifecycle.Event.ON_START)
		{
			registerManagedConfigurationReceiver();
		}
		else if (event == Lifecycle.Event.ON_STOP)
		{
			unregisterManagedConfigurationReceiver();
		}
	}

	private void registerManagedConfigurationReceiver()
	{
		final IntentFilter restrictionsFilter = new IntentFilter(Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED);
		registerReceiver(mRestrictionsReceiver, restrictionsFilter);
	}

	private void unregisterManagedConfigurationReceiver()
	{
		unregisterReceiver(mRestrictionsReceiver);
	}
}
