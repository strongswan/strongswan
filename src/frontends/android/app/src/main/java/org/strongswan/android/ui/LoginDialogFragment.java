/*
 * Copyright (C) 2020 Tobias Brunner
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

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfileDataSource;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatDialogFragment;

/**
 * Class that displays a login dialog and triggers a callback.
 */
public class LoginDialogFragment extends AppCompatDialogFragment
{
	public static final String REQUEST_PIN = "REQUEST_PIN";

	private OnLoginDialogFragmentListener mListener;

	/**
	 * The activity containing this fragment should implement this interface to receive
	 * a password or NULL if canceled.
	 */
	public interface OnLoginDialogFragmentListener {
		void onLoginDialogDismissed(String password);
	}

	public static LoginDialogFragment newInstance(Bundle profileInfo, OnLoginDialogFragmentListener listener)
	{
		final LoginDialogFragment instance = new LoginDialogFragment();
		instance.setArguments(profileInfo);
		instance.mListener = listener;
		return instance;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState)
	{
		final Bundle profileInfo = getArguments();
		final boolean pin = profileInfo.getBoolean(REQUEST_PIN);
		LayoutInflater inflater = getActivity().getLayoutInflater();
		View view = inflater.inflate(pin ? R.layout.login_dialog_pin : R.layout.login_dialog, null);
		final EditText password = view.findViewById(R.id.password);
		if (!pin)
		{
			EditText username = view.findViewById(R.id.username);
			username.setText(profileInfo.getString(VpnProfileDataSource.KEY_USERNAME));
		}

		AlertDialog.Builder adb = new AlertDialog.Builder(getActivity());
		adb.setView(view);
		adb.setTitle(getString(pin ? R.string.login_title_pin : R.string.login_title));
		adb.setPositiveButton(R.string.login_confirm, (dialog, which) ->
			mListener.onLoginDialogDismissed(password.getText().toString().trim()));
		adb.setNegativeButton(android.R.string.cancel, (dialog, which) ->
			mListener.onLoginDialogDismissed(null));
		return adb.create();
	}

	@Override
	public void onCancel(DialogInterface dialog)
	{
		mListener.onLoginDialogDismissed(null);
	}
}
