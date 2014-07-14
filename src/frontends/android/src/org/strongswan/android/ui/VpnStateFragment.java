/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

import java.util.ArrayList;
import java.util.List;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.logic.VpnStateService.ErrorState;
import org.strongswan.android.logic.VpnStateService.State;
import org.strongswan.android.logic.VpnStateService.VpnStateListener;
import org.strongswan.android.logic.imc.ImcState;
import org.strongswan.android.logic.imc.RemediationInstruction;

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
	private static final String KEY_ERROR_CONNECTION_ID = "error_connection_id";
	private static final String KEY_DISMISSED_CONNECTION_ID = "dismissed_connection_id";

	private TextView mProfileNameView;
	private TextView mProfileView;
	private TextView mStateView;
	private int stateBaseColor;
	private Button mActionButton;
	private ProgressDialog mConnectDialog;
	private ProgressDialog mDisconnectDialog;
	private ProgressDialog mProgressDialog;
	private AlertDialog mErrorDialog;
	private long mErrorConnectionID;
	private long mDismissedConnectionID;
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

		mErrorConnectionID = 0;
		mDismissedConnectionID = 0;
		if (savedInstanceState != null && savedInstanceState.containsKey(KEY_ERROR_CONNECTION_ID))
		{
			mErrorConnectionID = (Long)savedInstanceState.getSerializable(KEY_ERROR_CONNECTION_ID);
			mDismissedConnectionID = (Long)savedInstanceState.getSerializable(KEY_DISMISSED_CONNECTION_ID);
		}
	}

	@Override
	public void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);

		outState.putSerializable(KEY_ERROR_CONNECTION_ID, mErrorConnectionID);
		outState.putSerializable(KEY_DISMISSED_CONNECTION_ID, mDismissedConnectionID);
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
		hideErrorDialog();
		hideProgressDialog();
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
		String name = "", gateway = "";

		if (profile != null)
		{
			name = profile.getName();
			gateway = profile.getGateway();
		}

		if (reportError(connectionID, name, error, imcState))
		{
			return;
		}

		enableActionButton(false);
		mProfileNameView.setText(name);

		switch (state)
		{
			case DISABLED:
				showProfile(false);
				hideProgressDialog();
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
				hideProgressDialog();
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

	private boolean reportError(long connectionID, String name, ErrorState error, ImcState imcState)
	{
		if (connectionID > mDismissedConnectionID)
		{	/* report error if it hasn't been dismissed yet */
			mErrorConnectionID = connectionID;
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
				if (imcState == ImcState.BLOCK)
				{
					showErrorDialog(R.string.error_assessment_failed);
				}
				else
				{
					showErrorDialog(R.string.error_auth_failed);
				}
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
			mDisconnectDialog = mConnectDialog = null;
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

	private void clearError()
	{
		if (mService != null)
		{
			mService.disconnect();
		}
		mDismissedConnectionID = mErrorConnectionID;
		updateView();
	}

	private void showConnectDialog(String profile, String gateway)
	{
		if (mConnectDialog != null)
		{	/* already showing the dialog */
			return;
		}
		hideProgressDialog();
		mConnectDialog = new ProgressDialog(getActivity());
		mConnectDialog.setTitle(String.format(getString(R.string.connecting_title), profile));
		mConnectDialog.setMessage(String.format(getString(R.string.connecting_message), gateway));
		mConnectDialog.setIndeterminate(true);
		mConnectDialog.setCancelable(false);
		mConnectDialog.setButton(DialogInterface.BUTTON_NEGATIVE,
			  getString(android.R.string.cancel),
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
		mConnectDialog.show();
		mProgressDialog = mConnectDialog;
	}

	private void showDisconnectDialog(String profile)
	{
		if (mDisconnectDialog != null)
		{	/* already showing the dialog */
			return;
		}
		hideProgressDialog();
		mDisconnectDialog = new ProgressDialog(getActivity());
		mDisconnectDialog.setMessage(getString(R.string.state_disconnecting));
		mDisconnectDialog.setIndeterminate(true);
		mDisconnectDialog.setCancelable(false);
		mDisconnectDialog.show();
		mProgressDialog = mDisconnectDialog;
	}

	private void showErrorDialog(int textid)
	{
		final List<RemediationInstruction> instructions = mService.getRemediationInstructions();
		final boolean show_instructions = mService.getImcState() == ImcState.BLOCK && !instructions.isEmpty();
		int text = show_instructions ? R.string.show_remediation_instructions : R.string.show_log;

		mErrorDialog = new AlertDialog.Builder(getActivity())
			.setMessage(getString(R.string.error_introduction) + " " + getString(textid))
			.setCancelable(false)
			.setNeutralButton(text, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int which)
				{
					clearError();
					dialog.dismiss();
					Intent intent;
					if (show_instructions)
					{
						intent = new Intent(getActivity(), RemediationInstructionsActivity.class);
						intent.putParcelableArrayListExtra(RemediationInstructionsFragment.EXTRA_REMEDIATION_INSTRUCTIONS,
														   new ArrayList<RemediationInstruction>(instructions));
					}
					else
					{
						intent = new Intent(getActivity(), LogActivity.class);
					}
					startActivity(intent);
				}
			})
			.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int id)
				{
					clearError();
					dialog.dismiss();
				}
			}).create();
		mErrorDialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
			@Override
			public void onDismiss(DialogInterface dialog)
			{
				mErrorDialog = null;
			}
		});
		mErrorDialog.show();
	}
}
