package org.strongswan.android;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;

public class strongSwanActivity extends Activity
{
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		startVpnService();
	}

	private void startVpnService()
	{
		Intent intent = VpnService.prepare(this);
		if (intent != null)
		{
			startActivityForResult(intent, 0);
		}
		else
		{
			onActivityResult(0, RESULT_OK, null);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		if (resultCode == RESULT_OK)
		{
			Intent intent = new Intent(this, CharonVpnService.class);
			startService(intent);
		}
	}
}
