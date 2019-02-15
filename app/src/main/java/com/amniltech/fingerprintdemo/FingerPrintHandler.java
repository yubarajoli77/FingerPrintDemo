package com.amniltech.fingerprintdemo;

import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;

@TargetApi(Build.VERSION_CODES.M)
public class FingerPrintHandler extends FingerprintManager.AuthenticationCallback {
    private Context mContext;
    private LoginActivity loginActivity;

    FingerPrintHandler(Context mContext, LoginActivity loginActivity){
        this.mContext = mContext;
        this.loginActivity = loginActivity;
    }

    public void authInit(FingerprintManager fingerprintManager, FingerprintManager.CryptoObject cryptoObject){
        CancellationSignal cancellationSignal = new CancellationSignal();

        fingerprintManager.authenticate(cryptoObject,cancellationSignal,0,this,null);
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        loginActivity.setFingerPrintSensorMsg("Error: "+errString,true);
    }

    @Override
    public void onAuthenticationFailed() {
        loginActivity.setFingerPrintSensorMsg("Failed to Authenticate",true);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        loginActivity.setFingerPrintSensorMsg("Error: "+helpString,true);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        loginActivity.setFingerPrintSensorMsg("Successfully authenticated",false);
        loginActivity.showProgress(true);
        loginActivity.fingerPrintLogin();
    }
}
