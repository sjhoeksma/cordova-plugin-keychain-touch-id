/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.widget.ImageView;
import android.widget.TextView;


/**
 * Small helper class to manage text/icon around fingerprint authentication UI.
 */
@TargetApi(23)
public class FingerprintUiHelper extends FingerprintManager.AuthenticationCallback {

    static final long ERROR_TIMEOUT_MILLIS = 1600;
    static final long SUCCESS_DELAY_MILLIS = 1300;

    private final Context mContext;
    private final FingerprintManager mFingerprintManager;
    private final ImageView mIcon;
    private final TextView mErrorTextView;
    private final Callback mCallback;
    private final Bundle mOptions;
    private CancellationSignal mCancellationSignal;

    boolean mSelfCancelled;

    /**
     * Builder class for {@link FingerprintUiHelper} in which injected fields from Dagger
     * holds its fields and takes other arguments in the {@link #build} method.
     */
    public static class FingerprintUiHelperBuilder {
        private final FingerprintManager mFingerPrintManager;
        private final Context mContext;
        private final Bundle mOptions;

        public FingerprintUiHelperBuilder(Context context, FingerprintManager fingerprintManager, Bundle options) {
            mFingerPrintManager = fingerprintManager;
            mContext = context;
            mOptions = options;
        }

        public FingerprintUiHelper build(ImageView icon, TextView errorTextView, Callback callback) {
            return new FingerprintUiHelper(mContext, mFingerPrintManager, mOptions, icon, errorTextView, callback);
        }
    }

    /**
     * Constructor for {@link FingerprintUiHelper}. This method is expected to be called from
     * only the {@link FingerprintUiHelperBuilder} class.
     */
    private FingerprintUiHelper(Context context, FingerprintManager fingerprintManager, Bundle options,
                                ImageView icon, TextView errorTextView, Callback callback) {
        mFingerprintManager = fingerprintManager;
        mOptions = options;
        mIcon = icon;
        mErrorTextView = errorTextView;
        mCallback = callback;
        mContext = context;
    }

    public boolean isFingerprintAuthAvailable() {
        return mFingerprintManager.isHardwareDetected()
                && mFingerprintManager.hasEnrolledFingerprints();
    }

    public void startListening(FingerprintManager.CryptoObject cryptoObject) {
        if (!isFingerprintAuthAvailable()) {
            return;
        }
        mCancellationSignal = new CancellationSignal();
        mSelfCancelled = false;
        mFingerprintManager
                .authenticate(cryptoObject, mCancellationSignal, 0 /* flags */, this, null);

        int ic_fp_40px_id = mContext.getResources()
                .getIdentifier("ic_fp_40px", "drawable", FingerprintAuth.packageName);
        mIcon.setImageResource(ic_fp_40px_id);
    }

    public void stopListening() {
        if (mCancellationSignal != null) {
            mSelfCancelled = true;
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        if (!mSelfCancelled) {
            showError(errString);
            mIcon.postDelayed(new Runnable() {
                @Override
                public void run() {
                    mCallback.onError();
                }
            }, ERROR_TIMEOUT_MILLIS);
        }
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        showError(helpString);
    }

    @Override
    public void onAuthenticationFailed() {
        String dialogStatusNotRecognized = mOptions.getString("dialogStatusNotRecognized");
        if (dialogStatusNotRecognized == null) {
            int fingerprint_not_recognized_id = mContext.getResources().getIdentifier("fingerprint_not_recognized", "string", FingerprintAuth.packageName);
            dialogStatusNotRecognized = mIcon.getResources().getString(fingerprint_not_recognized_id);
        }
        showError(dialogStatusNotRecognized);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        mErrorTextView.removeCallbacks(mResetErrorTextRunnable);
        int ic_fingerprint_success_id = mContext.getResources()
                .getIdentifier("ic_fingerprint_success", "drawable", FingerprintAuth.packageName);
        mIcon.setImageResource(ic_fingerprint_success_id);
        int success_color_id = mContext.getResources()
                .getIdentifier("kc_success_color", "color", FingerprintAuth.packageName);
        mErrorTextView.setTextColor(
                mErrorTextView.getResources().getColor(success_color_id, null));

        String dialogStatusSuccess = mOptions.getString("dialogStatusSuccess");
        if (dialogStatusSuccess == null) {
            int fingerprint_success_id = mContext.getResources().getIdentifier("fingerprint_success", "string", FingerprintAuth.packageName);
            dialogStatusSuccess = mErrorTextView.getResources().getString(fingerprint_success_id);
        }
        mErrorTextView.setText(dialogStatusSuccess);
        mIcon.postDelayed(new Runnable() {
            @Override
            public void run() {
                mCallback.onAuthenticated();
            }
        }, SUCCESS_DELAY_MILLIS);
    }

    private void showError(CharSequence error) {
        int ic_fingerprint_error_id = mContext.getResources()
                .getIdentifier("ic_fingerprint_error", "drawable", FingerprintAuth.packageName);
        mIcon.setImageResource(ic_fingerprint_error_id);
        mErrorTextView.setText(error);
        int warning_color_id = mContext.getResources()
                .getIdentifier("kc_warning_color", "color", FingerprintAuth.packageName);
        mErrorTextView.setTextColor(
                mErrorTextView.getResources().getColor(warning_color_id, null));
        mErrorTextView.removeCallbacks(mResetErrorTextRunnable);
        mErrorTextView.postDelayed(mResetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }

    Runnable mResetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            int hint_color_id = mContext.getResources().getIdentifier("kc_hint_color", "color", FingerprintAuth.packageName);
            mErrorTextView.setTextColor(mErrorTextView.getResources().getColor(hint_color_id, null));

            String dialogHint = mOptions.getString("dialogHint");
            if (dialogHint == null) {
                int fingerprint_hint_id = mContext.getResources().getIdentifier("fingerprint_hint", "string", FingerprintAuth.packageName);
                dialogHint = mErrorTextView.getResources().getString(fingerprint_hint_id);
            }
            mErrorTextView.setText(dialogHint);
            int ic_fp_40px_id = mContext.getResources().getIdentifier("ic_fp_40px", "drawable", FingerprintAuth.packageName);
            mIcon.setImageResource(ic_fp_40px_id);
        }
    };

    public interface Callback {

        void onAuthenticated();

        void onError();
    }
}
