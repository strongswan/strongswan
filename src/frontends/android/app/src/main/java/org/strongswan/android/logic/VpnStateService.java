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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;

import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.logic.imc.ImcState;
import org.strongswan.android.logic.imc.RemediationInstruction;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;

public class VpnStateService extends Service
{
	private final List<VpnStateListener> mListeners = new ArrayList<VpnStateListener>();
	private final IBinder mBinder = new LocalBinder();
	private long mConnectionID = 0;
	private Handler mHandler;
	private VpnProfile mProfile;
	private State mState = State.DISABLED;
	private ErrorState mError = ErrorState.NO_ERROR;
	private ImcState mImcState = ImcState.UNKNOWN;
	private final LinkedList<RemediationInstruction> mRemediationInstructions = new LinkedList<RemediationInstruction>();

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
	 * Get the current connection ID.  May be used to track which state
	 * changes have already been handled.
	 *
	 * Is increased when startConnection() is called.
	 *
	 * @return connection ID
	 */
	public long getConnectionID()
	{	/* only updated from the main thread so no synchronization needed */
		return mConnectionID;
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
	 * Get the current IMC state, if any.
	 *
	 * @return imc state
	 */
	public ImcState getImcState()
	{	/* only updated from the main thread so no synchronization needed */
		return mImcState;
	}

	/**
	 * Get the remediation instructions, if any.
	 *
	 * @return read-only list of instructions
	 */
	public List<RemediationInstruction> getRemediationInstructions()
	{	/* only updated from the main thread so no synchronization needed */
		return Collections.unmodifiableList(mRemediationInstructions);
	}

	/**
	 * Disconnect any existing connection and shutdown the daemon, the
	 * VpnService is not stopped but it is reset so new connections can be
	 * started.
	 */
	public void disconnect()
	{
		/* as soon as the TUN device is created by calling establish() on the
		 * VpnService.Builder object the system binds to the service and keeps
		 * bound until the file descriptor of the TUN device is closed.  thus
		 * calling stopService() here would not stop (destroy) the service yet,
		 * instead we call startService() with an empty Intent which shuts down
		 * the daemon (and closes the TUN device, if any) */
		Context context = getApplicationContext();
		Intent intent = new Intent(context, CharonVpnService.class);
		context.startService(intent);
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
	 * Called when a connection is started.  Sets the currently active VPN
	 * profile, resets IMC and Error state variables, sets the State to
	 * CONNECTING, increases the connection ID, and notifies all listeners.
	 *
	 * May be called from threads other than the main thread.
	 *
	 * @param profile current profile
	 */
	public void startConnection(final VpnProfile profile)
	{
		notifyListeners(new Callable<Boolean>() {
			@Override
			public Boolean call() throws Exception
			{
				VpnStateService.this.mConnectionID++;
				VpnStateService.this.mProfile = profile;
				VpnStateService.this.mState = State.CONNECTING;
				VpnStateService.this.mError = ErrorState.NO_ERROR;
				VpnStateService.this.mImcState = ImcState.UNKNOWN;
				VpnStateService.this.mRemediationInstructions.clear();
				return true;
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

	/**
	 * Set the current IMC state and notify all listeners, if changed.
	 *
	 * Setting the state to UNKNOWN clears all remediation instructions.
	 *
	 * May be called from threads other than the main thread.
	 *
	 * @param state IMC state
	 */
	public void setImcState(final ImcState state)
	{
		notifyListeners(new Callable<Boolean>() {
			@Override
			public Boolean call() throws Exception
			{
				if (state == ImcState.UNKNOWN)
				{
					VpnStateService.this.mRemediationInstructions.clear();
				}
				if (VpnStateService.this.mImcState != state)
				{
					VpnStateService.this.mImcState = state;
					return true;
				}
				return false;
			}
		});
	}

	/**
	 * Add the given remediation instruction to the internal list.  Listeners
	 * are not notified.
	 *
	 * Instructions are cleared if the IMC state is set to UNKNOWN.
	 *
	 * May be called from threads other than the main thread.
	 *
	 * @param instruction remediation instruction
	 */
	public void addRemediationInstruction(final RemediationInstruction instruction)
	{
		mHandler.post(new Runnable() {
			@Override
			public void run()
			{
				VpnStateService.this.mRemediationInstructions.add(instruction);
			}
		});
	}
}
