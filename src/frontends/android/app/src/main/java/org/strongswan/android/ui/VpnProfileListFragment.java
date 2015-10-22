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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.ui.adapter.VpnProfileAdapter;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.Intent;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView.MultiChoiceModeListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;
import android.widget.Toast;

public class VpnProfileListFragment extends Fragment
{
	private static final int ADD_REQUEST = 1;
	private static final int EDIT_REQUEST = 2;

	private List<VpnProfile> mVpnProfiles;
	private VpnProfileDataSource mDataSource;
	private VpnProfileAdapter mListAdapter;
	private ListView mListView;
	private OnVpnProfileSelectedListener mListener;
	private boolean mReadOnly;

	/**
	 * The activity containing this fragment should implement this interface
	 */
	public interface OnVpnProfileSelectedListener {
		public void onVpnProfileSelected(VpnProfile profile);
	}

	@Override
	public void onInflate(Activity activity, AttributeSet attrs, Bundle savedInstanceState)
	{
		super.onInflate(activity, attrs, savedInstanceState);
		TypedArray a = activity.obtainStyledAttributes(attrs, R.styleable.Fragment);
		mReadOnly = a.getBoolean(R.styleable.Fragment_read_only, false);
		a.recycle();
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
							 Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.profile_list_fragment, null);

		mListView = (ListView)view.findViewById(R.id.profile_list);
		mListView.setAdapter(mListAdapter);
		mListView.setEmptyView(view.findViewById(R.id.profile_list_empty));
		mListView.setOnItemClickListener(mVpnProfileClicked);

		if (!mReadOnly)
		{
			mListView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE_MODAL);
			mListView.setMultiChoiceModeListener(mVpnProfileSelected);
		}
		return view;
	}

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		Bundle args = getArguments();
		if (args != null)
		{
			mReadOnly = args.getBoolean("read_only", mReadOnly);
		}

		if (!mReadOnly)
		{
			setHasOptionsMenu(true);
		}

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
	public void onAttach(Activity activity)
	{
		super.onAttach(activity);

		if (activity instanceof OnVpnProfileSelectedListener)
		{
			mListener = (OnVpnProfileSelectedListener)activity;
		}
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
			case EDIT_REQUEST:
				if (resultCode != Activity.RESULT_OK)
				{
					return;
				}
				long id = data.getLongExtra(VpnProfileDataSource.KEY_ID, 0);
				VpnProfile profile = mDataSource.getVpnProfile(id);
				if (profile != null)
				{	/* in case this was an edit, we remove it first */
					mVpnProfiles.remove(profile);
					mVpnProfiles.add(profile);
					mListAdapter.notifyDataSetChanged();
				}
				return;
		}
		super.onActivityResult(requestCode, resultCode, data);
	}

	private final OnItemClickListener mVpnProfileClicked = new OnItemClickListener() {
		@Override
		public void onItemClick(AdapterView<?> a, View v, int position, long id)
		{
			if (mListener != null)
			{
				mListener.onVpnProfileSelected((VpnProfile)a.getItemAtPosition(position));
			}
		}
	};

	private final MultiChoiceModeListener mVpnProfileSelected = new MultiChoiceModeListener() {
		private HashSet<Integer> mSelected;
		private MenuItem mEditProfile;

		@Override
		public boolean onPrepareActionMode(ActionMode mode, Menu menu)
		{
			return false;
		}

		@Override
		public void onDestroyActionMode(ActionMode mode)
		{
		}

		@Override
		public boolean onCreateActionMode(ActionMode mode, Menu menu)
		{
			MenuInflater inflater = mode.getMenuInflater();
			inflater.inflate(R.menu.profile_list_context, menu);
			mEditProfile = menu.findItem(R.id.edit_profile);
			mSelected = new HashSet<Integer>();
			mode.setTitle(R.string.select_profiles);
			return true;
		}

		@Override
		public boolean onActionItemClicked(ActionMode mode, MenuItem item)
		{
			switch (item.getItemId())
			{
				case R.id.edit_profile:
				{
					int position = mSelected.iterator().next();
					VpnProfile profile = (VpnProfile)mListView.getItemAtPosition(position);
					Intent connectionIntent = new Intent(getActivity(), VpnProfileDetailActivity.class);
					connectionIntent.putExtra(VpnProfileDataSource.KEY_ID, profile.getId());
					startActivityForResult(connectionIntent, EDIT_REQUEST);
					break;
				}
				case R.id.delete_profile:
				{
					ArrayList<VpnProfile> profiles = new ArrayList<VpnProfile>();
					for (int position : mSelected)
					{
						profiles.add((VpnProfile)mListView.getItemAtPosition(position));
					}
					for (VpnProfile profile : profiles)
					{
						mDataSource.deleteVpnProfile(profile);
						mVpnProfiles.remove(profile);
					}
					mListAdapter.notifyDataSetChanged();
					Toast.makeText(VpnProfileListFragment.this.getActivity(),
								   R.string.profiles_deleted, Toast.LENGTH_SHORT).show();
					break;
				}
				default:
					return false;
			}
			mode.finish();
			return true;
		}

		@Override
		public void onItemCheckedStateChanged(ActionMode mode, int position,
											  long id, boolean checked)
		{
			if (checked)
			{
				mSelected.add(position);
			}
			else
			{
				mSelected.remove(position);
			}
			final int checkedCount = mSelected.size();
			mEditProfile.setEnabled(checkedCount == 1);
			switch (checkedCount)
			{
				case 0:
					mode.setSubtitle(R.string.no_profile_selected);
					break;
				case 1:
					mode.setSubtitle(R.string.one_profile_selected);
					break;
				default:
					mode.setSubtitle(String.format(getString(R.string.x_profiles_selected), checkedCount));
					break;
			}
		}
	};
}
