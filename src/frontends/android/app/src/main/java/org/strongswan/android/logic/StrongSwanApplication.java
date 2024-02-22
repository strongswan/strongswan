/*
 * Copyright (C) 2023 Relution GmbH
 * Copyright (C) 2014-2024 Tobias Brunner
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
import android.util.Log;

import org.strongswan.android.data.DatabaseHelper;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.security.LocalCertificateKeyStoreProvider;
import org.strongswan.android.utils.Constants;

import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import androidx.annotation.NonNull;
import androidx.core.os.HandlerCompat;
import androidx.lifecycle.DefaultLifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.ProcessLifecycleOwner;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class StrongSwanApplication extends Application implements DefaultLifecycleObserver
{
	private static final String TAG = StrongSwanApplication.class.getSimpleName();

	private static Context mContext;
	private static StrongSwanApplication mInstance;

	private final ExecutorService mExecutorService = Executors.newFixedThreadPool(4);
	private final Handler mMainHandler = HandlerCompat.createAsync(Looper.getMainLooper());

	private ManagedConfigurationService mManagedConfigurationService;
	private ManagedTrustedCertificateManager mTrustedCertificateManager;
	private ManagedUserCertificateManager mUserCertificateManager;

	private DatabaseHelper mDatabaseHelper;

	private final BroadcastReceiver mRestrictionsReceiver = new BroadcastReceiver()
	{
		@Override
		public void onReceive(Context context, Intent intent)
		{
			Log.d(TAG, "Managed configuration changed");
			reloadManagedConfigurationAndNotifyListeners();
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
		StrongSwanApplication.mInstance = this;

		mDatabaseHelper = new DatabaseHelper(mContext);

		mManagedConfigurationService = new ManagedConfigurationService(mContext);

		mTrustedCertificateManager = new ManagedTrustedCertificateManager(mContext, mExecutorService, mMainHandler,
																		  mManagedConfigurationService, mDatabaseHelper);

		mUserCertificateManager = new ManagedUserCertificateManager(mContext, mManagedConfigurationService, mDatabaseHelper);

		ProcessLifecycleOwner.get().getLifecycle().addObserver(this);
	}

	@Override
	public void onResume(@NonNull LifecycleOwner owner)
	{
		reloadManagedConfigurationAndNotifyListeners();

		final IntentFilter restrictionsFilter = new IntentFilter(Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED);
		registerReceiver(mRestrictionsReceiver, restrictionsFilter);
	}

	@Override
	public void onPause(@NonNull LifecycleOwner owner)
	{
		unregisterReceiver(mRestrictionsReceiver);
	}

	private void reloadManagedConfigurationAndNotifyListeners()
	{
		final Set<String> uuids = new HashSet<>(mManagedConfigurationService.getManagedProfiles().keySet());

		mManagedConfigurationService.loadConfiguration();
		mManagedConfigurationService.updateSettings();

		mUserCertificateManager.update();
		mTrustedCertificateManager.update(() -> {
			uuids.addAll(mManagedConfigurationService.getManagedProfiles().keySet());

			Log.d(TAG, "Send profiles changed broadcast");
			Intent profilesChanged = new Intent(Constants.VPN_PROFILES_CHANGED);
			profilesChanged.putExtra(Constants.VPN_PROFILES_MULTIPLE, uuids.toArray(new String[0]));
			LocalBroadcastManager.getInstance(mContext).sendBroadcast(profilesChanged);
		});
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
	 * Returns the current application object
	 *
	 * @return application
	 */
	public static StrongSwanApplication getInstance()
	{
		return StrongSwanApplication.mInstance;
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
	 * Returns a service providing access to the app's managed configuration.
	 *
	 * @return managed configuration
	 */
	public ManagedConfigurationService getManagedConfigurationService()
	{
		return mManagedConfigurationService;
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
}
