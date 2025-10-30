/*
 * Copyright (C) 2018 Tobias Brunner
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

import android.os.Bundle;
import android.view.MenuItem;

import org.strongswan.android.R;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.WindowCompat;

public class SettingsActivity extends AppCompatActivity
{

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.settings_activity);
		WindowCompat.enableEdgeToEdge(getWindow());

		getSupportActionBar().setDisplayHomeAsUpEnabled(true);

		if (savedInstanceState == null)
		{
			getSupportFragmentManager().beginTransaction()
				.setReorderingAllowed(true)
				.add(R.id.fragment_container, SettingsFragment.class, null)
				.commit();
		}
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case android.R.id.home:
				finish();
				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}
}
