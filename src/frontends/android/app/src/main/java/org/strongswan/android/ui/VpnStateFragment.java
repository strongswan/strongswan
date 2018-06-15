/*
 * Copyright (C) 2012-2018 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * HSR Hochschule fuer Technik Rapperswil
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

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.support.v4.app.Fragment;
import android.support.v4.content.ContextCompat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.logic.VpnStateService.ErrorState;
import org.strongswan.android.logic.VpnStateService.State;
import org.strongswan.android.logic.VpnStateService.VpnStateListener;
import org.strongswan.android.logic.imc.ImcState;
import org.strongswan.android.logic.imc.RemediationInstruction;

import java.util.ArrayList;
import java.util.List;

public class VpnStateFragment extends Fragment implements VpnStateListener
{
	private static final String KEY_ERROR_CONNECTION_ID = "error_connection_id";

	private TextView mProfileNameView;
	private TextView mProfileView;
	private TextView mStateView;
	private int mColorStateBase;
	private int mColorStateError;
	private int mColorStateSuccess;
	private Button mActionButton;
	private ProgressBar mProgress;
	private LinearLayout mErrorView;
	private TextView mErrorText;
	private Button mErrorRetry;
	private Button mDismissError;
	private long mErrorConnectionID;
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
			mService.registerListener(VpnStateFragment.this);
			updateView();
		}
	};
	private OnClickListener mDisconnectListener = new OnClickListener()
	{
		@Override
		public void onClick(View v)
		{
			if (mService != null)
			{
				mService.disconnect();
			}
		}
	};

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		mColorStateError = ContextCompat.getColor(getActivity(), R.color.error_text);
		mColorStateSuccess = ContextCompat.getColor(getActivity(), R.color.success_text);

		/* bind to the service only seems to work from the ApplicationContext */
		Context context = getActivity().getApplicationContext();
		context.bindService(new Intent(context, VpnStateService.class),
							mServiceConnection, Service.BIND_AUTO_CREATE);

		mErrorConnectionID = 0;
		if (savedInstanceState != null && savedInstanceState.containsKey(KEY_ERROR_CONNECTION_ID))
		{
			mErrorConnectionID = (Long)savedInstanceState.getSerializable(KEY_ERROR_CONNECTION_ID);
		}
	}

	@Override
	public void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);

		outState.putSerializable(KEY_ERROR_CONNECTION_ID, mErrorConnectionID);
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
							 Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.vpn_state_fragment, null);

		mActionButton = (Button)view.findViewById(R.id.action);
		enableActionButton(null);

		mErrorView = view.findViewById(R.id.vpn_error);
		mErrorText = view.findViewById(R.id.vpn_error_text);
		mErrorRetry = view.findViewById(R.id.retry);
		mDismissError = view.findViewById(R.id.dismiss_error);
		mProgress = (ProgressBar)view.findViewById(R.id.progress);
		mStateView = (TextView)view.findViewById(R.id.vpn_state);
		mColorStateBase = mStateView.getCurrentTextColor();
		mProfileView = (TextView)view.findViewById(R.id.vpn_profile_label);
		mProfileNameView = (TextView)view.findViewById(R.id.vpn_profile_name);

		mErrorRetry.setOnClickListener(v -> {
			if (mService != null)
			{
				mService.reconnect();
			}
		});
		mDismissError.setOnClickListener(v -> clearError());

		return view;
	}

	@Override
	public void onStart()
	{
		super.onStart();
		if (mService != null)
		{
			mService.registerListener(this);
			updateView();
		}
	}

	@Override
	public void onStop()
	{
		super.onStop();
		if (mService != null)
		{
			mService.unregisterListener(this);
		}
	}

	@Override
	public void onDestroy()
	{
		super.onDestroy();
		if (mService != null)
		{
			getActivity().getApplicationContext().unbindService(mServiceConnection);
		}
	}

	@Override
	public void stateChanged()
	{
		updateView();
	}

	public void updateView()
	{
		long connectionID = mService.getConnectionID();
		VpnProfile profile = mService.getProfile();
		State state = mService.getState();
		ErrorState error = mService.getErrorState();
		ImcState imcState = mService.getImcState();
		String name = "";

		if (getActivity() == null)
		{
			return;
		}

		if (profile != null)
		{
			name = profile.getName();
		}

		if (reportError(connectionID, name, error, imcState))
		{
			return;
		}

		mProfileNameView.setText(name);

		switch (state)
		{
			case DISABLED:
				showProfile(false);
				mProgress.setVisibility(View.GONE);
				enableActionButton(null);
				mStateView.setText(R.string.state_disabled);
				mStateView.setTextColor(mColorStateBase);
				break;
			case CONNECTING:
				showProfile(true);
				mProgress.setVisibility(View.VISIBLE);
				enableActionButton(getString(android.R.string.cancel));
				mStateView.setText(R.string.state_connecting);
				mStateView.setTextColor(mColorStateBase);
				break;
			case CONNECTED:
				showProfile(true);
				mProgress.setVisibility(View.GONE);
				enableActionButton(getString(R.string.disconnect));
				mStateView.setText(R.string.state_connected);
				mStateView.setTextColor(mColorStateSuccess);
				break;
			case DISCONNECTING:
				showProfile(true);
				mProgress.setVisibility(View.VISIBLE);
				enableActionButton(null);
				mStateView.setText(R.string.state_disconnecting);
				mStateView.setTextColor(mColorStateBase);
				break;
		}
	}

	private boolean reportError(long connectionID, String name, ErrorState error, ImcState imcState)
	{
		if (error == ErrorState.NO_ERROR)
		{
			mErrorView.setVisibility(View.GONE);
			return false;
		}
		mErrorConnectionID = connectionID;
		mProfileNameView.setText(name);
		showProfile(true);
		mProgress.setVisibility(View.GONE);
		mStateView.setText(R.string.state_error);
		mStateView.setTextColor(mColorStateError);
		enableActionButton(getString(R.string.show_log));
		mActionButton.setOnClickListener(v -> {
			Intent intent = new Intent(getActivity(), LogActivity.class);
			startActivity(intent);
		});
		mErrorText.setText(getString(R.string.error_format, getString(mService.getErrorText())));
		mErrorView.setVisibility(View.VISIBLE);
		return true;
	}

	private void showProfile(boolean show)
	{
		mProfileView.setVisibility(show ? View.VISIBLE : View.GONE);
		mProfileNameView.setVisibility(show ? View.VISIBLE : View.GONE);
	}

	private void enableActionButton(String text)
	{
		mActionButton.setText(text);
		mActionButton.setEnabled(text != null);
		mActionButton.setVisibility(text != null ? View.VISIBLE : View.GONE);
		mActionButton.setOnClickListener(mDisconnectListener);
	}

	private void clearError()
	{
		if (mService != null)
		{
			if (mService.getConnectionID() == mErrorConnectionID)
			{
				mService.disconnect();
				mService.setError(ErrorState.NO_ERROR);
			}
		}
		updateView();
	}
}
