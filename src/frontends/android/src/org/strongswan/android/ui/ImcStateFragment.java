/*
 * Copyright (C) 2013 Tobias Brunner
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
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.logic.VpnStateService.VpnStateListener;

import android.app.Fragment;
import android.app.FragmentTransaction;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

public class ImcStateFragment extends Fragment implements VpnStateListener
{
	private TextView mStateView;
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
			mService.registerListener(ImcStateFragment.this);
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
		/* hide it initially */
		getFragmentManager().beginTransaction().hide(this).commit();
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
							 Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.imc_state_fragment, null);

		mStateView = (TextView)view.findViewById(R.id.imc_state);

		return view;
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
		FragmentTransaction ft = getFragmentManager().beginTransaction();

		switch (mService.getImcState())
		{
			case UNKNOWN:
			case ALLOW:
				ft.hide(this);
				break;
			case ISOLATE:
				mStateView.setText(R.string.imc_state_isolate);
				mStateView.setTextColor(getResources().getColor(R.color.warning_text));
				ft.show(this);
				break;
			case BLOCK:
				mStateView.setText(R.string.imc_state_block);
				mStateView.setTextColor(getResources().getColor(R.color.error_text));
				ft.show(this);
				break;
		}
		ft.commit();
	}
}
