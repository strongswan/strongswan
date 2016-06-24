/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 *
 */
package org.strongswan.android.ipc.verification;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;
import com.fancyfon.mobile.android.verification.CallerVerificator;


import org.strongswan.android.R;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


/**
 * @author: Lena Jurkiewicz <lena.jurkiewicz@fancyfon.com>
 */
public class StrongswanCallerVerificator implements CallerVerificator {

    private static final String TAG = "StrongswanCallerVerificator";
    static final String SHA_1 = "SHA-1";
    Context context;
    String[] trustedFingerprints;
    String[] trustedPackageNames;


    public StrongswanCallerVerificator(Context context) {
        this.context = context;
        trustedFingerprints = context.getResources().getStringArray(R.array.trusted_fingerprints);
        trustedPackageNames = context.getResources().getStringArray(R.array.trusted_packages);
    }


    public boolean isCallerPermitted(int callingUid) {
        String callingPackageName = context.getPackageManager().getNameForUid(callingUid);
        String callerFingerprint = getCallerFingerprint(callingPackageName);
        for (String trustedFingerprint : trustedFingerprints) {
            if (trustedFingerprint.equalsIgnoreCase(callerFingerprint)) {
                return verifyPackages(callingPackageName);
            }
        }
        return false;
    }

    private boolean verifyPackages(String callingPackageName) {
        return Arrays.asList(trustedPackageNames).contains(callingPackageName);
    }

    private String getCallerFingerprint(String callingPackageName) {
        String fingerprint = "";
        try {
            Signature[] signatures = context.getPackageManager().getPackageInfo(callingPackageName,
                    PackageManager.GET_SIGNATURES).signatures;
            for (Signature signature : signatures) {
                fingerprint = getFingerprint(signature);
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.w(TAG, "Exception while determining caller signatures: " + e);
        } catch (NoSuchAlgorithmException e) {
            Log.w(TAG, "Error while calculating SHA1 from caller signature: " + e);
        }
        return fingerprint;
    }

    private String getFingerprint(Signature signature) throws NoSuchAlgorithmException {
        String fingerprintSHA1;
        byte[] hexBytes = signature.toByteArray();
        MessageDigest digest = MessageDigest.getInstance(SHA_1);
        byte[] sha1digest = digest.digest(hexBytes);
        StringBuilder sb = new StringBuilder();
        for (byte aSha1digest : sha1digest) {
            sb.append((Integer.toHexString((aSha1digest & 0xFF) | 0x100)).substring(1, 3));
        }
        fingerprintSHA1 = sb.toString();
        return fingerprintSHA1;
    }


}
