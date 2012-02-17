package org.strongswan.android;

import android.app.Activity;
import android.os.Bundle;

public class strongSwanActivity extends Activity {
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
    }
}