/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 * 
 */
package org.strongswan.android.ipc;

import android.app.Service;
import android.content.Intent;
import android.os.*;
import android.util.Log;
import org.strongswan.android.api.R;

import java.util.List;

/**
 * @author Piotr Soróbka <piotr.sorobka@fancyfon.com>
 */
public class VpnProfileCrudMessengerService extends Service {

    private static final String TAG = "VpnProfileService";
    private VpnProfileCrud vpnProfileCrud;

    Messenger messenger = new Messenger(new Handler() {

        @Override
        public void handleMessage(Message msg) {
            if (msg.what == getInteger(R.integer.vpn_profile_create_message)) {
                create(msg);
            } else if (msg.what == getInteger(R.integer.vpn_profile_read_message)) {
                read(msg);
            } else if (msg.what == getInteger(R.integer.vpn_profile_read_all_message)) {
                readAll(msg);
            } else if (msg.what == getInteger(R.integer.vpn_profile_update_message)) {
                update(msg);
            } else if (msg.what == getInteger(R.integer.vpn_profile_delete_message)) {
                delete(msg);
            } else if (msg.what == getInteger(R.integer.vpn_profile_delete_all_message)) {
                deleteAll(msg);
            } else {
                Log.w(TAG, "Unknown message: " + msg);
                super.handleMessage(msg);
            }
        }

        private void deleteAll(Message msg) {
            boolean result = vpnProfileCrud.deleteVpnProfiles();
            reply(msg, result);
        }

        private void readAll(Message msg) {
            List<Bundle> profiles = vpnProfileCrud.readVpnProfiles();
            long[] ids = new long[profiles.size()];
            int i = 0;
            Bundle result = new Bundle();
            for (Bundle bundle : profiles) {
                long id = bundle.getLong(getString(R.string.vpn_profile_bundle_id_key));
                ids[i++] = id;
                result.putBundle(getString(R.string.vpn_profile_bundle_id_params_key, id + ""), bundle);
            }
            result.putLongArray(getString(R.string.vpn_profile_bundle_ids_key), ids);
            reply(msg, result);
        }


        private void delete(Message msg) {
            long id = msg.getData().getLong(getString(R.string.vpn_profile_bundle_id_key));
            boolean result = vpnProfileCrud.deleteVpnProfile(id);
            reply(msg, result);
        }

        private void update(Message msg) {
            boolean result = vpnProfileCrud.updateVpnProfile(msg.getData());
            reply(msg, result);
        }

        private void read(Message msg) {
            long id = msg.getData().getLong(getString(R.string.vpn_profile_bundle_id_key));
            Bundle result = vpnProfileCrud.readVpnProfile(id);
            reply(msg, result);
        }

        private void create(Message msg) {
            boolean result = vpnProfileCrud.createVpnProfile(msg.getData());
            reply(msg, result);
        }

        private void reply(Message msg, boolean result) {
            Message returnMsg = getReturnMessage(msg, result);
            sendReturnMessage(returnMsg, msg.replyTo);
        }


        private void reply(Message msg, Bundle result) {
            if (result == null) {
                reply(msg, false);
                return;
            }
            Message returnMsg = getReturnMessage(msg, true);
            returnMsg.setData(result);
            sendReturnMessage(returnMsg, msg.replyTo);
        }

        private Message getReturnMessage(Message msg, boolean result) {
            return Message.obtain(null, msg.what, msg.arg1, result ? 0 : 1);
        }

        private void sendReturnMessage(Message returnMsg, Messenger replyTo) {
            try {
                replyTo.send(returnMsg);
            } catch (RemoteException e) {
                Log.e(TAG, "failed to send return message", e);
            }
        }

    });

    @Override
    public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        vpnProfileCrud = new VpnProfileCrud(this);
    }

    @Override
    public void onDestroy() {
        vpnProfileCrud.close();
        super.onDestroy();
    }

    private int getInteger(int id) {
        return getResources().getInteger(id);
    }


}
