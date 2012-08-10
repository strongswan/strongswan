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

package org.strongswan.android.ui;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.StringReader;

import org.strongswan.android.R;
import org.strongswan.android.logic.CharonVpnService;

import android.app.Fragment;
import android.os.Bundle;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

public class LogFragment extends Fragment implements Runnable
{
	private String mLogFilePath;
	private Handler mLogHandler;
	private TextView mLogView;
	private LogScrollView mScrollView;
	private BufferedReader mReader;
	private Thread mThread;
	private volatile boolean mRunning;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		mLogFilePath = getActivity().getFilesDir() + File.separator + CharonVpnService.LOG_FILE;
		/* use a handler to update the log view */
		mLogHandler = new Handler();
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.log_fragment, null);
		mLogView = (TextView)view.findViewById(R.id.log_view);
		mScrollView = (LogScrollView)view.findViewById(R.id.scroll_view);
		return view;
	}

	@Override
	public void onStart()
	{
		super.onStart();
		mLogView.setText("");
		try
		{
			mReader = new BufferedReader(new FileReader(mLogFilePath));
		}
		catch (FileNotFoundException e)
		{
			mReader = new BufferedReader(new StringReader(""));
		}
		mRunning = true;
		mThread = new Thread(this);
		mThread.start();
	}

	@Override
	public void onStop()
	{
		super.onStop();
		try
		{
			mRunning = false;
			mThread.interrupt();
			mThread.join();
		}
		catch (InterruptedException e)
		{
		}
	}

	/**
	 * Write the given log line to the TextView. We strip the prefix off to save
	 * some space (it is not that helpful for regular users anyway).
	 * @param line log line to log
	 */
	public void logLine(final String line)
	{
		mLogHandler.post(new Runnable() {
			@Override
			public void run()
			{
				/* strip off prefix (month=3, day=2, time=8, thread=2, spaces=3) */
				mLogView.append((line.length() > 18 ? line.substring(18) : line) + '\n');
				/* calling autoScroll() directly does not work, probably because content
				 * is not yet updated, so we post this to be done later */
				mScrollView.post(new Runnable() {
					@Override
					public void run()
					{
						mScrollView.autoScroll();
					}
				});
			}
		});
	}

	@Override
	public void run()
	{
		while (mRunning)
		{
			try
			{
				String line = mReader.readLine();
				if (line == null)
				{	/* wait until there is more to log */
					Thread.sleep(1000);
				}
				else
				{
					logLine(line);
				}
			}
			catch (Exception e)
			{
				break;
			}
		}
	}
}
