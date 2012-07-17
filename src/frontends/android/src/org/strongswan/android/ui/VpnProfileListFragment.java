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

import java.util.List;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.ui.adapter.VpnProfileAdapter;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListView;

public class VpnProfileListFragment extends Fragment
{
	private static final int ADD_REQUEST = 1;

	private List<VpnProfile> mVpnProfiles;
	private VpnProfileDataSource mDataSource;
	private VpnProfileAdapter mListAdapter;
	private ListView mListView;

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
							 Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.profile_list_fragment, null);

		mListView = (ListView)view.findViewById(R.id.profile_list);
		mListView.setEmptyView(view.findViewById(R.id.profile_list_empty));
		mListView.setAdapter(mListAdapter);

		return view;
	}

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setHasOptionsMenu(true);

		Context context = getActivity().getApplicationContext();

		mDataSource = new VpnProfileDataSource(this.getActivity());
		mDataSource.open();

		/* cached list of profiles used as backend for the ListView */
		mVpnProfiles = mDataSource.getAllVpnProfiles();

		mListAdapter = new VpnProfileAdapter(context, R.layout.profile_list_item, mVpnProfiles);
	}

	@Override
	public void onDestroy()
	{
		super.onDestroy();
		mDataSource.close();
	}

	@Override
	public void onCreateOptionsMenu(Menu menu, MenuInflater inflater)
	{
		inflater.inflate(R.menu.profile_list, menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case R.id.add_profile:
				Intent connectionIntent = new Intent(getActivity(),
													 VpnProfileDetailActivity.class);
				startActivityForResult(connectionIntent, ADD_REQUEST);
				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}

	@Override
	public void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case ADD_REQUEST:
				if (resultCode != Activity.RESULT_OK)
				{
					return;
				}
				long id = data.getLongExtra(VpnProfileDataSource.KEY_ID, 0);
				VpnProfile profile = mDataSource.getVpnProfile(id);
				if (profile != null)
				{
					mVpnProfiles.add(profile);
					mListAdapter.notifyDataSetChanged();
				}
				return;
		}
		super.onActivityResult(requestCode, resultCode, data);
	}
}
