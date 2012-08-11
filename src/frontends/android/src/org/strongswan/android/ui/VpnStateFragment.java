/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

package org.strongswan.android.ui;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.logic.VpnStateService.ErrorState;
import org.strongswan.android.logic.VpnStateService.State;
import org.strongswan.android.logic.VpnStateService.VpnStateListener;

import android.app.AlertDialog;
import android.app.Fragment;
import android.app.ProgressDialog;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

public class VpnStateFragment extends Fragment implements VpnStateListener
{
	private static final String KEY_ERROR = "error";
	private static final String KEY_NAME = "name";

	private TextView mProfileNameView;
	private TextView mProfileView;
	private TextView mStateView;
	private int stateBaseColor;
	private Button mActionButton;
	private ProgressDialog mProgressDialog;
	private State mState;
	private AlertDialog mErrorDialog;
	private ErrorState mError;
	private String mErrorProfileName;
	private VpnStateService mService;
	private final ServiceConnection mServiceConnection = new ServiceConnection() {
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

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		/* bind to the service only seems to work from the ApplicationContext */
		Context context = getActivity().getApplicationContext();
		context.bindService(new Intent(context, VpnStateService.class),
							mServiceConnection, Service.BIND_AUTO_CREATE);

		mError = ErrorState.NO_ERROR;
		if (savedInstanceState != null && savedInstanceState.containsKey(KEY_ERROR))
		{
			mError = (ErrorState)savedInstanceState.getSerializable(KEY_ERROR);
			mErrorProfileName = savedInstanceState.getString(KEY_NAME);
		}
	}

	@Override
	public void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);

		outState.putSerializable(KEY_ERROR, mError);
		outState.putString(KEY_NAME, mErrorProfileName);
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
							 Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.vpn_state_fragment, null);

		mActionButton = (Button)view.findViewById(R.id.action);
		mActionButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v)
			{
				if (mService != null)
				{
					mService.disconnect();
				}
			}
		});
		enableActionButton(false);

		mStateView = (TextView)view.findViewById(R.id.vpn_state);
		stateBaseColor = mStateView.getCurrentTextColor();
		mProfileView = (TextView)view.findViewById(R.id.vpn_profile_label);
		mProfileNameView = (TextView)view.findViewById(R.id.vpn_profile_name);

		return view;
	}

	@Override
	public void onStart()
	{
		super.onStart();
		if (mService != null)
		{
			updateView();
		}
	}

	@Override
	public void onStop()
	{
		super.onStop();
		hideErrorDialog();
		hideProgressDialog();
	}

	@Override
	public void onDestroy()
	{
		super.onDestroy();
		if (mService != null)
		{
			mService.unregisterListener(this);
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
		State state = mService.getState();
		ErrorState error = ErrorState.NO_ERROR;
		String name = "", gateway = "";

		if (state != State.DISABLED)
		{
			VpnProfile profile = mService.getProfile();
			if (profile != null)
			{
				name = profile.getName();
				gateway = profile.getGateway();
			}
			error = mService.getErrorState();
		}

		if (reportError(name, state, error))
		{
			return;
		}

		if (state == mState)
		{	/* avoid unnecessary updates */
			return;
		}

		hideProgressDialog();
		enableActionButton(false);
		mProfileNameView.setText(name);
		mState = state;

		switch (state)
		{
			case DISABLED:
				showProfile(false);
				mStateView.setText(R.string.state_disabled);
				mStateView.setTextColor(stateBaseColor);
				break;
			case CONNECTING:
				showProfile(true);
				showConnectDialog(name, gateway);
				mStateView.setText(R.string.state_connecting);
				mStateView.setTextColor(stateBaseColor);
				break;
			case CONNECTED:
				showProfile(true);
				enableActionButton(true);
				mStateView.setText(R.string.state_connected);
				mStateView.setTextColor(getResources().getColor(R.color.success_text));
				break;
			case DISCONNECTING:
				showProfile(true);
				showDisconnectDialog(name);
				mStateView.setText(R.string.state_disconnecting);
				mStateView.setTextColor(stateBaseColor);
				break;
		}
	}

	private boolean reportError(String name, State state, ErrorState error)
	{
		if (mError != ErrorState.NO_ERROR)
		{	/* we are currently reporting an error which was not yet dismissed */
			error = mError;
			name = mErrorProfileName;
		}
		else if (error != ErrorState.NO_ERROR && (state == State.CONNECTING || state == State.CONNECTED))
		{	/* while initiating we report errors */
			mError = error;
			mErrorProfileName = name;
		}
		else
		{	/* ignore all other errors */
			error = ErrorState.NO_ERROR;
		}
		if (error == ErrorState.NO_ERROR)
		{
			hideErrorDialog();
			return false;
		}
		else if (mErrorDialog != null)
		{	/* we already show the dialog */
			return true;
		}
		hideProgressDialog();
		mProfileNameView.setText(name);
		showProfile(true);
		enableActionButton(false);
		mStateView.setText(R.string.state_error);
		mStateView.setTextColor(getResources().getColor(R.color.error_text));
		switch (error)
		{
			case AUTH_FAILED:
				showErrorDialog(R.string.error_auth_failed);
				break;
			case PEER_AUTH_FAILED:
				showErrorDialog(R.string.error_peer_auth_failed);
				break;
			case LOOKUP_FAILED:
				showErrorDialog(R.string.error_lookup_failed);
				break;
			case UNREACHABLE:
				showErrorDialog(R.string.error_unreachable);
				break;
			default:
				showErrorDialog(R.string.error_generic);
				break;
		}
		return true;
	}

	private void showProfile(boolean show)
	{
		mProfileView.setVisibility(show ? View.VISIBLE : View.GONE);
		mProfileNameView.setVisibility(show ? View.VISIBLE : View.GONE);
	}

	private void enableActionButton(boolean enable)
	{
		mActionButton.setEnabled(enable);
		mActionButton.setVisibility(enable ? View.VISIBLE : View.GONE);
	}

	private void hideProgressDialog()
	{
		if (mProgressDialog != null)
		{
			mProgressDialog.dismiss();
			mProgressDialog = null;
		}
	}

	private void hideErrorDialog()
	{
		if (mErrorDialog != null)
		{
			mErrorDialog.dismiss();
			mErrorDialog = null;
		}
	}

	private void showConnectDialog(String profile, String gateway)
	{
		mProgressDialog = new ProgressDialog(getActivity());
		mProgressDialog.setTitle(String.format(getString(R.string.connecting_title), profile));
		mProgressDialog.setMessage(String.format(getString(R.string.connecting_message), gateway));
		mProgressDialog.setIndeterminate(true);
		mProgressDialog.setCancelable(false);
		mProgressDialog.setButton(getString(android.R.string.cancel),
								  new DialogInterface.OnClickListener()
								  {
									  @Override
									  public void onClick(DialogInterface dialog, int which)
									  {
										  if (mService != null)
										  {
											  mService.disconnect();
										  }
									  }
								  });
		mProgressDialog.show();
	}

	private void showDisconnectDialog(String profile)
	{
		mProgressDialog = new ProgressDialog(getActivity());
		mProgressDialog.setMessage(getString(R.string.state_disconnecting));
		mProgressDialog.setIndeterminate(true);
		mProgressDialog.setCancelable(false);
		mProgressDialog.show();
	}

	private void showErrorDialog(int textid)
	{
		mErrorDialog = new AlertDialog.Builder(getActivity())
			.setMessage(getString(R.string.error_introduction) + " " + getString(textid))
			.setCancelable(false)
			.setNeutralButton(R.string.show_log, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int which)
				{
					dialog.dismiss();
					Intent logIntent = new Intent(getActivity(), LogActivity.class);
					startActivity(logIntent);
				}
			})
			.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int id)
				{
					dialog.dismiss();
				}
			}).create();
		mErrorDialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
			@Override
			public void onDismiss(DialogInterface dialog)
			{	/* clear the error */
				mError = ErrorState.NO_ERROR;
				mErrorDialog = null;
				updateView();
			}
		});
		mErrorDialog.show();
	}
}
