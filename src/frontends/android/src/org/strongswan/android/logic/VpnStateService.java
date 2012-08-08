/*
 * Copyright (C) 2012 Tobias Brunner
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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import org.strongswan.android.data.VpnProfile;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;

public class VpnStateService extends Service
{
	private final List<VpnStateListener> mListeners = new ArrayList<VpnStateListener>();
	private final IBinder mBinder = new LocalBinder();
	private Handler mHandler;
	private VpnProfile mProfile;
	private State mState = State.DISABLED;
	private ErrorState mError = ErrorState.NO_ERROR;

	public enum State
	{
		DISABLED,
		CONNECTING,
		CONNECTED,
		DISCONNECTING,
	}

	public enum ErrorState
	{
		NO_ERROR,
		AUTH_FAILED,
		PEER_AUTH_FAILED,
		LOOKUP_FAILED,
		UNREACHABLE,
		GENERIC_ERROR,
	}

	/**
	 * Listener interface for bound clients that are interested in changes to
	 * this Service.
	 */
	public interface VpnStateListener
	{
		public void stateChanged();
	}

	/**
	 * Simple Binder that allows to directly access this Service class itself
	 * after binding to it.
	 */
	public class LocalBinder extends Binder
	{
		public VpnStateService getService()
		{
			return VpnStateService.this;
		}
	}

	@Override
	public void onCreate()
	{
		/* this handler allows us to notify listeners from the UI thread and
		 * not from the threads that actually report any state changes */
		mHandler = new Handler();
	}

	@Override
	public IBinder onBind(Intent intent)
	{
		return mBinder;
	}

	@Override
	public void onDestroy()
	{
	}

	/**
	 * Register a listener with this Service. We assume this is called from
	 * the main thread so no synchronization is happening.
	 *
	 * @param listener listener to register
	 */
	public void registerListener(VpnStateListener listener)
	{
		mListeners.add(listener);
	}

	/**
	 * Unregister a listener from this Service.
	 *
	 * @param listener listener to unregister
	 */
	public void unregisterListener(VpnStateListener listener)
	{
		mListeners.remove(listener);
	}

	/**
	 * Get the current VPN profile.
	 *
	 * @return profile
	 */
	public VpnProfile getProfile()
	{	/* only updated from the main thread so no synchronization needed */
		return mProfile;
	}

	/**
	 * Get the current state.
	 *
	 * @return state
	 */
	public State getState()
	{	/* only updated from the main thread so no synchronization needed */
		return mState;
	}

	/**
	 * Get the current error, if any.
	 *
	 * @return error
	 */
	public ErrorState getErrorState()
	{	/* only updated from the main thread so no synchronization needed */
		return mError;
	}

	/**
	 * Update state and notify all listeners about the change. By using a Handler
	 * this is done from the main UI thread and not the initial reporter thread.
	 * Also, in doing the actual state change from the main thread, listeners
	 * see all changes and none are skipped.
	 *
	 * @param change the state update to perform before notifying listeners, returns true if state changed
	 */
	private void notifyListeners(final Callable<Boolean> change)
	{
		mHandler.post(new Runnable() {
			@Override
			public void run()
			{
				try
				{
					if (change.call())
					{	/* otherwise there is no need to notify the listeners */
						for (VpnStateListener listener : mListeners)
						{
							listener.stateChanged();
						}
					}
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Set the VPN profile currently active. Listeners are not notified.
	 *
	 * May be called from threads other than the main thread.
	 *
	 * @param profile current profile
	 */
	public void setProfile(final VpnProfile profile)
	{
		/* even though we don't notify the listeners the update is done from the
		 * same handler so updates are predictable for listeners */
		mHandler.post(new Runnable() {
			@Override
			public void run()
			{
				VpnStateService.this.mProfile = profile;
			}
		});
	}

	/**
	 * Update the state and notify all listeners, if changed.
	 *
	 * May be called from threads other than the main thread.
	 *
	 * @param state new state
	 */
	public void setState(final State state)
	{
		notifyListeners(new Callable<Boolean>() {
			@Override
			public Boolean call() throws Exception
			{
				if (VpnStateService.this.mState != state)
				{
					VpnStateService.this.mState = state;
					return true;
				}
				return false;
			}
		});
	}

	/**
	 * Set the current error state and notify all listeners, if changed.
	 *
	 * May be called from threads other than the main thread.
	 *
	 * @param error error state
	 */
	public void setError(final ErrorState error)
	{
		notifyListeners(new Callable<Boolean>() {
			@Override
			public Boolean call() throws Exception
			{
				if (VpnStateService.this.mError != error)
				{
					VpnStateService.this.mError = error;
					return true;
				}
				return false;
			}
		});
	}
}
