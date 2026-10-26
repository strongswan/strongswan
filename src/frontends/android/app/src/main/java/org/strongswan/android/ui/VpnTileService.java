/*
 * Copyright (C) 2018-2019 Tobias Brunner
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

package org.strongswan.android.ui;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.graphics.drawable.Icon;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.data.VpnProfileSource;
import org.strongswan.android.data.VpnType;
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.utils.Constants;
import org.strongswan.android.utils.TileStart;

import androidx.preference.PreferenceManager;

@TargetApi(Build.VERSION_CODES.N)
public class VpnTileService extends TileService implements VpnStateService.VpnStateListener
{
	private boolean mListening;
	private final Handler mHandler = new Handler(Looper.getMainLooper());
	/* a click that arrived before VpnStateService was bound (the tile service may
	 * be created right on the click, e.g. on ColorOS that kills it aggressively) */
	private boolean mPendingClick;
	private VpnProfileDataSource mDataSource;
	private VpnStateService mService;
	private final ServiceConnection mServiceConnection = new ServiceConnection()
	{
		@Override
		public void onServiceDisconnected(ComponentName name)
		{
			mService = null;
		}

		@Override
		public void onServiceConnected(ComponentName name, IBinder service)
		{
			mService = ((VpnStateService.LocalBinder)service).getService();
			if (mListening && mDataSource != null)
			{
				mService.registerListener(VpnTileService.this);
				updateTile();
			}
			if (mPendingClick)
			{
				mPendingClick = false;
				onClick();
			}
		}
	};

	@Override
	public void onCreate()
	{
		super.onCreate();

		Context context = getApplicationContext();
		context.bindService(new Intent(context, VpnStateService.class),
							mServiceConnection, Service.BIND_AUTO_CREATE);

		mDataSource = new VpnProfileSource(this);
		mDataSource.open();
	}

	@Override
	public void onDestroy()
	{
		super.onDestroy();
		mHandler.removeCallbacksAndMessages(null);

		if (mService != null)
		{
			getApplicationContext().unbindService(mServiceConnection);
		}
		mDataSource.close();
		mDataSource = null;
	}

	@Override
	public void onStartListening()
	{
		super.onStartListening();
		mListening = true;

		if (mService != null)
		{
			mService.registerListener(this);
			updateTile();
		}
	}

	@Override
	public void onStopListening()
	{
		super.onStopListening();
		mListening = false;

		if (mService != null)
		{
			mService.unregisterListener(this);
		}
	}

	private VpnProfile getProfile()
	{
		SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(this);
		String uuid = pref.getString(Constants.PREF_DEFAULT_VPN_PROFILE, null);
		if (uuid == null || uuid.equals(Constants.PREF_DEFAULT_VPN_PROFILE_MRU))
		{
			uuid = pref.getString(Constants.PREF_MRU_VPN_PROFILE, null);
		}
		return mDataSource != null ? mDataSource.getVpnProfile(uuid) : null;
	}

	@Override
	public void onClick()
	{
		if (mService == null && mDataSource != null)
		{	/* not bound yet, handle the click once we are */
			mPendingClick = true;
			return;
		}
		if (mService != null)
		{
			/* we operate on the current/most recently used profile, but fall back to configuration */
			VpnProfile profile = mService.getProfile();
			if (profile == null)
			{
				profile = getProfile();
			}
			else if (mDataSource != null)
			{   /* always get the plain profile without cached password */
				profile = mDataSource.getVpnProfile(profile.getUUID());
			}
			/* reconnect the profile in case of an error */
			if (mService.getErrorState() == VpnStateService.ErrorState.NO_ERROR)
			{
				switch (mService.getState())
				{
					case CONNECTING:
					case CONNECTED:
						Runnable disconnect = new Runnable()
						{
							@Override
							public void run()
							{
								mService.disconnect();
							}
						};
						if (isLocked())
						{
							unlockAndRun(disconnect);
						}
						else
						{
							disconnect.run();
						}
						return;
				}
			}
			if (profile != null && VpnProfileControlActivity.canConnectWithoutPrompt(this, profile))
			{	/* nothing to ask, connect from here so the drawer stays open and shows the state */
				final VpnProfile direct = profile;
				Runnable connect = new Runnable()
				{
					@Override
					public void run()
					{
						connectDirectly(direct);
					}
				};
				if (isLocked())
				{
					unlockAndRun(connect);
				}
				else
				{
					connect.run();
				}
				return;
			}
			if (profile != null)
			{
				startControlActivity(profile);
				return;
			}
		}
		Intent intent = new Intent(this, MainActivity.class);
		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
		{
			startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent,
								PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
		}
		else
		{
			startActivityAndCollapseCompat(intent);
		}
	}

	/**
	 * Connect without the activity. If the system refuses to start the service
	 * from here (background start restrictions, vendor limits), or the connection
	 * doesn't start within TileStart.FALLBACK_MS, fall back to the activity.
	 */
	private void connectDirectly(final VpnProfile profile)
	{
		try
		{
			mService.connect(VpnProfileControlActivity.profileInfo(profile), true);
		}
		catch (IllegalStateException | SecurityException e)
		{
			startControlActivity(profile);
			return;
		}
		mHandler.postDelayed(new Runnable()
		{
			@Override
			public void run()
			{
				if (mService != null && mService.getState() == VpnStateService.State.DISABLED &&
					mService.getErrorState() == VpnStateService.ErrorState.NO_ERROR)
				{
					try
					{
						startControlActivity(profile);
					}
					catch (RuntimeException e)
					{	/* not allowed outside of a click on some versions, the tile shows "disconnected" */
					}
				}
			}
		}, TileStart.FALLBACK_MS);
	}

	private void startControlActivity(VpnProfile profile)
	{
		Intent intent = new Intent(this, VpnProfileControlActivity.class);
		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		intent.setAction(VpnProfileControlActivity.START_PROFILE);
		intent.putExtra(VpnProfileControlActivity.EXTRA_VPN_PROFILE_UUID, profile.getUUID().toString());
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
		{	/* starting an activity from a tile is only reliably allowed via
			 * startActivityAndCollapse() on Android 14+, a plain startActivity()
			 * (even with the overlay permission) is silently blocked by some
			 * vendors, e.g. ColorOS 15 */
			startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent,
								PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
		}
		else if (profile.getVpnType().has(VpnType.VpnTypeFeature.USER_PASS) &&
				 profile.getPassword() == null)
		{	/* the user will have to enter the password, so collapse the drawer */
			startActivityAndCollapseCompat(intent);
		}
		else
		{
			startActivity(intent);
		}
	}

	@SuppressWarnings("deprecation")
	@SuppressLint("StartActivityAndCollapseDeprecated")
	private void startActivityAndCollapseCompat(Intent intent)
	{
		startActivityAndCollapse(intent);
	}

	@Override
	public void stateChanged()
	{
		updateTile();
	}

	private void updateTile()
	{
		VpnProfile profile = mService.getProfile();
		VpnStateService.State state = mService.getState();
		VpnStateService.ErrorState error = mService.getErrorState();

		/* same as above, only use the configured profile if we have no active profile */
		if (profile == null)
		{
			profile = getProfile();
		}

		Tile tile = getQsTile();
		if (tile == null)
		{
			return;
		}

		if (error != VpnStateService.ErrorState.NO_ERROR)
		{
			tile.setState(Tile.STATE_INACTIVE);
			tile.setIcon(Icon.createWithResource(this, R.drawable.ic_notification_warning));
			tile.setLabel(getString(R.string.tile_connect));
		}
		else
		{
			switch (state)
			{
				case DISCONNECTING:
				case DISABLED:
					tile.setState(Tile.STATE_INACTIVE);
					tile.setIcon(Icon.createWithResource(this, R.drawable.ic_notification_disconnected));
					tile.setLabel(getString(R.string.tile_connect));
					break;
				case CONNECTING:
					tile.setState(Tile.STATE_ACTIVE);
					tile.setIcon(Icon.createWithResource(this, R.drawable.ic_notification_connecting));
					tile.setLabel(getString(R.string.tile_disconnect));
					break;
				case CONNECTED:
					tile.setState(Tile.STATE_ACTIVE);
					tile.setIcon(Icon.createWithResource(this, R.drawable.ic_notification));
					tile.setLabel(getString(R.string.tile_disconnect));
					break;
			}
		}
		if (profile != null && !isSecure())
		{
			tile.setLabel(profile.getName());
		}
		tile.updateTile();
	}
}
