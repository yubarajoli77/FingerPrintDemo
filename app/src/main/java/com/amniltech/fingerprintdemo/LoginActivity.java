package com.amniltech.fingerprintdemo;

import android.Manifest;
import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.support.design.widget.Snackbar;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.app.LoaderManager.LoaderCallbacks;

import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;

import android.os.Build;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.EditorInfo;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Permission;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static android.Manifest.permission.READ_CONTACTS;

/**
 * A login screen that offers login via email/password.
 */
public class LoginActivity extends AppCompatActivity {

    // UI references.
    private EditText mEmailView;
    private EditText mPasswordView;
    private View mProgressView;
    private View mLoginFormView;
    private TextView tvFingerPrintMsg;
    private ImageView ivFingerPrintIcon;
    private final String EMAIL = "uv@gmail.com";
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;
    private LinearLayout llfingerPrintViewHolder;
    private KeyStore keyStore;
    private Cipher cipher;
    private String KEY_NAME = "AndroidKey";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        // Set up the login form.
        mEmailView = findViewById(R.id.email);

        mPasswordView = findViewById(R.id.password);
        mPasswordView.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView textView, int id, KeyEvent keyEvent) {
                if (id == EditorInfo.IME_ACTION_DONE || id == EditorInfo.IME_NULL) {
                    attemptLogin();
                    return true;
                }
                return false;
            }
        });

        Button mEmailSignInButton = findViewById(R.id.email_sign_in_button);
        mEmailSignInButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                attemptLogin();
            }
        });

        mLoginFormView = findViewById(R.id.login_form);
        mProgressView = findViewById(R.id.login_progress);
        tvFingerPrintMsg = findViewById(R.id.tv_finger_print_msg);
        ivFingerPrintIcon = findViewById(R.id.iv_finger_print_holder);
        llfingerPrintViewHolder = findViewById(R.id.ll_fingerprint_view_holder);

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){
            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
            keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            hideShowFingerPrintViews(true);

            if(checkPreRequisites()){
                doFingerPrintAuthentication();
            }

        }else
            hideShowFingerPrintViews(false);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void doFingerPrintAuthentication() {
        generateKey();

        if(cipherInit()){
            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
            FingerPrintHandler fingerPrintHandler = new FingerPrintHandler(this,this);
            fingerPrintHandler.authInit(fingerprintManager,cryptoObject);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean checkPreRequisites() {
        if(!fingerprintManager.isHardwareDetected()){
            hideShowFingerPrintViews(false);
            return false;
        }else if(ContextCompat.checkSelfPermission(this,Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED){
            showFingerPrintMsg("No permission for fingerprint is granted",true);
            return false;
        }else if (!keyguardManager.isDeviceSecure()){
            showFingerPrintMsg("Please set lock screen for your phone",true);
            return false;
        }else if (!fingerprintManager.hasEnrolledFingerprints()){
            showFingerPrintMsg("Please add at least one finger print",true);
            return false;
        }else {
            showFingerPrintMsg("You can use your fingerprint to login",false);
            return true;
        }
    }

    private void showFingerPrintMsg(String msg, boolean errorMsg) {
        if(errorMsg){
            tvFingerPrintMsg.setText("Error: "+msg);
            tvFingerPrintMsg.setTextColor(ContextCompat.getColor(this,R.color.colorAccent));
        }else {
            tvFingerPrintMsg.setText(msg);
            tvFingerPrintMsg.setTextColor(ContextCompat.getColor(this,R.color.colorBlack));
        }

    }

    private void hideShowFingerPrintViews(boolean show) {
        llfingerPrintViewHolder.setVisibility(show? View.VISIBLE : View.GONE);
    }


    private void attemptLogin() {
        showProgress(true);
        // Store values at the time of the login attempt.
        String email = mEmailView.getText().toString();
        String password = mPasswordView.getText().toString();

        // Check for a valid password, if the user entered one.
        if(TextUtils.isEmpty(email)){
            mEmailView.setError(getString(R.string.error_field_required));
            mEmailView.requestFocus();
            showProgress(false);
        }else if(!TextUtils.isEmpty(email) && !isEmailValid(email)){
            mEmailView.setError(getString(R.string.error_invalid_email));
            mEmailView.requestFocus();
            showProgress(false);

        }else if(TextUtils.isEmpty(password)){
            mPasswordView.setError(getString(R.string.error_field_required));
            mPasswordView.requestFocus();
            showProgress(false);

        }else if (!TextUtils.isEmpty(password) && !isPasswordValid(password)) {
            mPasswordView.setError(getString(R.string.error_invalid_password));
            mPasswordView.requestFocus();
            showProgress(false);

        }else
            authenticateUser(email,password);

    }

    private void authenticateUser(String email, String password) {
        showProgress(false);
        if(email.equals(EMAIL) && password.equals(EMAIL)){
            startActivity(new Intent(LoginActivity.this,MainActivity.class));
            finish();
        }else {
            Snackbar.make(mEmailView,"Sorry, Email and Password mismatch",Snackbar.LENGTH_INDEFINITE).show();
        }
    }


    private boolean isEmailValid(String email) {
        return email.contains("@");
    }

    private boolean isPasswordValid(String password) {
        return password.length() > 4;
    }

    /**
     * Shows the progress UI and hides the login form.
     */
    @TargetApi(Build.VERSION_CODES.HONEYCOMB_MR2)
    public void showProgress(final boolean show) {
        // On Honeycomb MR2 we have the ViewPropertyAnimator APIs, which allow
        // for very easy animations. If available, use these APIs to fade-in
        // the progress spinner.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB_MR2) {
            int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

            mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
            mLoginFormView.animate().setDuration(shortAnimTime).alpha(
                    show ? 0 : 1).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
                }
            });

            mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            mProgressView.animate().setDuration(shortAnimTime).alpha(
                    show ? 1 : 0).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });
        } else {
            // The ViewPropertyAnimator APIs are not available, so simply show
            // and hide the relevant UI components.
            mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
        }
    }

    public void setFingerPrintSensorMsg(String msg, boolean error) {
        if(error){
            ivFingerPrintIcon.setImageResource(R.mipmap.ic_red_finger_print);
            tvFingerPrintMsg.setTextColor(ContextCompat.getColor(this,R.color.colorAccent));
            tvFingerPrintMsg.setText(msg);
        }else {
            ivFingerPrintIcon.setImageResource(R.mipmap.ic_verified);
            tvFingerPrintMsg.setTextColor(ContextCompat.getColor(this,R.color.colorBlack));
            tvFingerPrintMsg.setText(msg);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void generateKey(){
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyGenerator keyGenerator = KeyGenerator.getInstance( KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyStore.load(null);
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC) .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            e.printStackTrace();
        }


    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean cipherInit() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }


        try {

            keyStore.load(null);

            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);

            cipher.init(Cipher.ENCRYPT_MODE, key);

            return true;

        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }

    }

    public void fingerPrintLogin(){
        authenticateUser(EMAIL,EMAIL);
    }

}

